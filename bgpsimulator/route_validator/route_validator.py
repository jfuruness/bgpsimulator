from functools import lru_cache

from bgpsimulator.shared import Prefix, ROARouted, ROAValidity

from .roa import ROA
from .roas_node import ROASNode


class RouteValidator:
    """Trie of ROAs"""

    def __init__(self) -> None:
        self.root: ROASNode = ROASNode()
        self.get_roa_outcome.cache_clear()
        self._roas: list[ROA] = list()

    @property
    def roas(self) -> tuple[ROA, ...]:
        """Returns all ROAs in the trie"""
        return tuple(self._roas)

    def clear(self) -> None:
        """Clears the trie"""
        self.__init__()  # type: ignore

    def add_roa(self, roa: ROA) -> None:
        """Inserts a prefix into the trie"""
        prefix = roa.prefix
        bits = self._get_binary_str_from_prefix(prefix)
        node = self.root
        for bit in bits[: prefix.prefixlen]:
            if bool(int(bit)):
                if node.right is None:
                    node.right = ROASNode()
                node = node.right
            else:
                if node.left is None:
                    node.left = ROASNode()
                node = node.left
        node.add_data(prefix, roa)
        self._roas.append(roa)

    def __contains__(self, prefix: Prefix) -> bool:
        """Checks if a prefix is contained within the Trie"""
        return bool(self.get_most_specific_trie_supernet(prefix))

    def get_most_specific_trie_supernet(self, prefix: Prefix) -> ROASNode | None:
        """Returns the most specific trie subnet"""
        bits = self._get_binary_str_from_prefix(prefix)
        node = self.root
        most_specific_node = None
        for bit in bits[: prefix.prefixlen]:
            next_node = node.right if bool(int(bit)) else node.left
            if next_node is None:
                return most_specific_node
            elif next_node.prefix is not None:
                most_specific_node = next_node
            node = next_node
        return most_specific_node

    def _get_binary_str_from_prefix(self, prefix: Prefix) -> str:
        """Returns a binary string from a prefix"""

        binary_str = ""
        for _byte in prefix.network_address.packed:
            binary_str += str(bin(_byte))[2:].zfill(8)
        return binary_str

    @lru_cache(maxsize=10_000)  # noqa: B019
    def get_roa_outcome(
        self, prefix: Prefix, origin: int
    ) -> tuple[ROAValidity, ROARouted]:
        """Gets the validity and roa routed vs non rotued of a prefix-origin pair

        This can get fairly complicated, since there can be multiple ROAs
        for the same announcement, and each ROA can have a different validity.
        Essentially, we need to calculate the best validity for a given announcement
        and then that's the validity that should be used. I.e. the "most valid" roa
        is the one that should be used
        """

        relevant_roas = self.get_relevant_roas(prefix)

        if relevant_roas:
            # Return the best ROAOutcome
            rv = sorted(
                [x.get_outcome(prefix, origin) for x in relevant_roas],
                key=lambda x: x[0],
            )[0]
            return rv
        else:
            return ROAValidity.UNKNOWN, ROARouted.UNKNOWN

    def get_relevant_roas(self, prefix: Prefix) -> set[ROA]:
        """Returns all relevant ROAs for a given prefix

        This is a bit non-intuitive, because you'd think that all ROAs relevant
        for a given prefix would be __at the prefix__. But this isn't the case.
        They could be higher up the trie, and simply have a __max length__ that
        is >= your prefix length. So you need to collect all ROAs all the way down,
        and for each ROA, determine if it's relevant, and then return them
        """

        bits = self._get_binary_str_from_prefix(prefix)
        node = self.root
        roas: list[ROA] = list()
        for bit in bits[: prefix.prefixlen]:
            next_node = node.right if bool(int(bit)) else node.left
            if next_node is None:
                return set(roas)
            elif next_node.prefix is not None:
                for roa in next_node.roas:
                    if roa.covers_prefix(prefix):
                        roas.append(roa)
            node = next_node
        return set(roas)

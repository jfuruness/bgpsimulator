from functools import cached_property
from typing import TYPE_CHECKING, Any, Optional
from weakref import CallableProxyType, proxy


class AS:
    """Autonomous System class. Contains attributes of an AS"""

    def __init__(
        self,
        *,
        asn: int,
        tier_1: bool = False,
        ixp: bool = False,
        peer_asns: set[int] = set(),
        provider_asns: set[int] = set(),
        customer_asns: set[int] = set(),
        peers: list["AS"] = list(),
        providers: list["AS"] = list(),
        customers: list["AS"] = list(),
        provider_cone_asns: set[int] = None,
        propagation_rank: int | None = None,
        as_graph: Optional["ASGraph"] = None,
    ) -> None:
        # Make sure you're not accidentally passing in a string here
        self.asn: int = int(asn)

        self.peer_asns: set[int] = peer_asns
        self.provider_asns: set[int] = provider_asns
        self.customer_asns: set[int] = customer_asns

        self.peers: list[AS] = peers
        self.providers: list[AS] = providers
        self.customers: list[AS] = customers

        # Read Caida's paper to understand these
        self.tier_1: bool = tier_1
        self.ixp: bool = ixp
        self.provider_cone_asns: set[int] | None = provider_cone_asns
        # Propagation rank. 0 is a leaf, highest is the input clique/t1 ASes
        self.propagation_rank: int | None = propagation_rank

        # Hash in advance and only once since this gets called a lot
        self.hashed_asn = hash(self.asn)

        self.routing_policy: RoutingPolicy = RoutingPolicy(proxy(self))

        # This is useful for some policies to have knowledge of the graph
        if as_graph is not None:
            self.as_graph: CallableProxyType[ASGraph] = proxy(as_graph)
        else:
            # Ignoring this because it gets set properly immediatly
            self.as_graph = None  # type: ignore

    def __lt__(self, as_obj: Any) -> bool:
        if isinstance(as_obj, AS):
            return self.asn < as_obj.asn
        else:
            return NotImplemented

    def __eq__(self, other: Any) -> bool:
        if isinstance(other, AS):
            return self.to_json() == other.to_json()
        else:
            return NotImplemented

    def __hash__(self) -> int:
        return self.hashed_asn

    @cached_property
    def stub(self) -> bool:
        """Returns True if AS is a stub by RFC1772"""

        return len(self.neighbors) == 1

    @cached_property
    def multihomed(self) -> bool:
        """Returns True if AS is multihomed by RFC1772"""

        return len(self.customers) == 0 and len(self.peers) + len(self.providers) > 1

    @cached_property
    def transit(self) -> bool:
        """Returns True if AS is a transit AS by RFC1772"""

        return (
            len(self.customers) > 0
            and len(self.customers) + len(self.peers) + len(self.providers) > 1
        )

    @cached_property
    def stubs(self) -> tuple["AS", ...]:
        """Returns a list of any stubs connected to that AS"""

        return tuple([x for x in self.customers if x.stub])

    @cached_property
    def neighbors(self) -> tuple["AS", ...]:
        """Returns customers + peers + providers"""

        return self.customers + self.peers + self.providers

    @cached_property
    def neighbor_asns(self) -> set[int]:
        """Returns neighboring ASNs (useful for ASRA)"""

        return set([x.asn for x in self.neighbors])

    ##############
    # Yaml funcs #
    ##############

    def to_json(self) -> dict[str, Any]:
        """This optional method is called when you call yaml.dump()"""

        return {
            "asn": self.asn,
            "customer_asns": [asn for x in self.customer_asns],
            "peer_asns": [asn for x in self.peer_asns],
            "provider_asns": [asn for x in self.provider_asns],
            "tier_1": self.tier_1,
            "ixp": self.ixp,
            "provider_cone_asns": self.provider_cone_asns,
            "propagation_rank": self.propagation_rank,
            "policy": self.policy.to_json() if self.policy else None,
        }

from functools import cached_property
from typing import TYPE_CHECKING, Any, Optional
from weakref import CallableProxyType, proxy

from frozendict import frozendict


class AS:
    """Autonomous System class. Contains attributes of an AS"""

    def __init__(
        self,
        *,
        asn: int,
        peer_asns: set[int] | None = None,
        provider_asns: set[int] | None = None,
        customer_asns: set[int] | None = None,
        provider_cone_asns: set[int] = None,
        propagation_rank: int | None = None,
        tier_1: bool = False,
        ixp: bool = False,
        base_routing_policy_settings: frozendict[str, Any] = frozendict(),
        overriden_routing_policy_settings: frozendict[str, Any] = frozendict(),
        as_graph: Optional["ASGraph"] = None,
    ) -> None:
        # Make sure you're not accidentally passing in a string here
        self.asn: int = int(asn)

        self.peer_asns: set[int] = peer_asns or set()
        self.provider_asns: set[int] = provider_asns or set()
        self.customer_asns: set[int] = customer_asns or set()

        self.peers: list[AS] = []
        self.providers: list[AS] = []
        self.customers: list[AS] = []

        # Read Caida's paper to understand these
        self.tier_1: bool = tier_1
        self.ixp: bool = ixp
        self.provider_cone_asns: set[int] | None = provider_cone_asns
        # Propagation rank. 0 is a leaf, highest is the input clique/t1 ASes
        self.propagation_rank: int | None = propagation_rank

        # Hash in advance and only once since this gets called a lot
        self.hashed_asn = hash(self.asn)

        self.routing_policy: RoutingPolicy = RoutingPolicy(proxy(self), base_routing_policy_settings, overriden_routing_policy_settings)

        # This is useful for some policies to have knowledge of the graph
        if as_graph is not None:
            self.as_graph: CallableProxyType[ASGraph] = proxy(as_graph)
        else:
            # Ignoring this because it gets set properly immediatly
            self.as_graph = None  # type: ignore

    def set_relations(self) -> None:
        """Sets the relations for the AS"""
        if not self.as_graph:
            raise ValueError("AS graph not set")

        self.peers = [self.as_graph[asn] for asn in self.peer_asns]
        self.providers = [self.as_graph[asn] for asn in self.provider_asns]
        self.customers = [self.as_graph[asn] for asn in self.customer_asns]

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
            "routing_policy": self.routing_policy.to_json(),
        }
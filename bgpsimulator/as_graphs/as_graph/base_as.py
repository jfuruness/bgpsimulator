from functools import cached_property
from typing import TYPE_CHECKING, Any, cast
from weakref import proxy

from bgpsimulator.shared import Relationships
from bgpsimulator.simulation_engine import Policy

if TYPE_CHECKING:
    from .as_graph import ASGraph


class AS:
    """Autonomous System class. Contains attributes of an AS"""

    def __init__(
        self,
        asn: int,
        peer_asns: set[int] | None = None,
        provider_asns: set[int] | None = None,
        customer_asns: set[int] | None = None,
        provider_cone_asns: set[int] | None = None,
        propagation_rank: int | None = None,
        tier_1: bool = False,
        ixp: bool = False,
        as_graph: "ASGraph | None" = None,
        policy_json: dict[str, Any] | None = None,
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
        self.provider_cone_asns: set[int] = provider_cone_asns or set()
        # Propagation rank. 0 is a leaf, highest is the input clique/t1 ASes
        self.propagation_rank: int | None = propagation_rank

        # Hash in advance and only once since this gets called a lot
        self.hashed_asn = hash(self.asn)

        self.policy: Policy = (
            Policy.from_json(policy_json, self) if policy_json else Policy(self)
        )

        # This is useful for some policies to have knowledge of the graph
        # Cast this here to avoid having to write the weakref everywhere
        if as_graph is not None:
            self.as_graph: ASGraph = cast("ASGraph", proxy(as_graph))
        else:
            # Ignoring this because it gets set properly immediatly
            self.as_graph = None  # type: ignore

    def set_relations(self) -> None:
        """Sets the relations for the AS"""
        if not self.as_graph:
            raise ValueError("AS graph not set")

        self.peers = [cast("AS", proxy(self.as_graph[asn])) for asn in self.peer_asns]
        self.providers = [
            cast("AS", proxy(self.as_graph[asn])) for asn in self.provider_asns
        ]
        self.customers = [
            cast("AS", proxy(self.as_graph[asn])) for asn in self.customer_asns
        ]

    def get_neighbor(self, rel: Relationships) -> list["AS"]:
        """Returns the neighbors of the AS based on the relationship enum"""

        if rel == Relationships.PEERS:
            return self.peers
        elif rel == Relationships.PROVIDERS:
            return self.providers
        elif rel == Relationships.CUSTOMERS:
            return self.customers
        else:
            raise ValueError(f"Invalid relationship: {rel}")

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
        """Returns True if AS is a stub by RFC1772

        Use neighbor_asns instead of neighbors so you can use this
        during graph construction
        """

        return len(self.neighbor_asns) == 1

    @cached_property
    def multihomed(self) -> bool:
        """Returns True if AS is multihomed by RFC1772

        Use customer_asns instead of customers so you can use this
        during graph construction
        """

        return (
            len(self.customer_asns) == 0
            and len(self.peer_asns) + len(self.provider_asns) > 1
        )

    @cached_property
    def transit(self) -> bool:
        """Returns True if AS is a transit AS by RFC1772

        Use customer_asns instead of customers so you can use this
        during graph construction
        """

        return (
            len(self.customer_asns) > 0
            and len(self.customer_asns) + len(self.peer_asns) + len(self.provider_asns)
            > 1
        )

    @cached_property
    def stubs(self) -> list["AS"]:
        """Returns a list of any stubs connected to that AS"""

        return [x for x in self.customers if x.stub]

    @cached_property
    def neighbors(self) -> list["AS"]:
        """Returns customers + peers + providers"""

        return self.customers + self.peers + self.providers

    @cached_property
    def neighbor_asns(self) -> set[int]:
        """Returns neighboring ASNs (useful for ASRA)"""

        return self.customer_asns | self.peer_asns | self.provider_asns

    ##############
    # JSON funcs #
    ##############

    def to_json(self) -> dict[str, Any]:
        """This optional method is called when you call yaml.dump()"""

        return {
            "asn": self.asn,
            "customer_asns": sorted(self.customer_asns),
            "peer_asns": sorted(self.peer_asns),
            "provider_asns": sorted(self.provider_asns),
            "tier_1": self.tier_1,
            "ixp": self.ixp,
            "provider_cone_asns": sorted(self.provider_cone_asns),
            "propagation_rank": self.propagation_rank,
            "policy": self.policy.to_json(),
        }

    @classmethod
    def from_json(
        cls, json_obj: dict[str, Any], as_graph: "ASGraph | None" = None
    ) -> "AS":
        """Converts the AS to a JSON object"""

        return cls(
            as_graph=as_graph,
            asn=int(json_obj["asn"]),
            customer_asns=set([int(x) for x in json_obj.get("customer_asns", [])]),
            peer_asns=set([int(x) for x in json_obj.get("peer_asns", [])]),
            provider_asns=set([int(x) for x in json_obj.get("provider_asns", [])]),
            tier_1=json_obj.get("tier_1", False),
            ixp=json_obj.get("ixp", False),
            provider_cone_asns=set(
                [int(x) for x in json_obj.get("provider_cone_asns", [])]
            ),
            propagation_rank=int(json_obj.get("propagation_rank"))
            if json_obj.get("propagation_rank")
            else None,
            policy_json=json_obj.get("policy", {}),
        )

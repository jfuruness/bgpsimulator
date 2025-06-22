from collections import defaultdict
from typing import TYPE_CHECKING, Any
from warnings import warn
from weakref import proxy

from bgpsimulator.shared.exceptions import GaoRexfordError
from bgpsimulator.simulation_engine.announcement import Announcement as Ann
from bgpsimulator.shared import Relationships
from bgpsimulator.shared import RoutingPolicySettings
from bgpsimulator.shared import Prefix, IPAddr
from bgpsimulator.route_validator import RouteValidator
from bgpsimulator.simulation_engine.routing_policy.custom_policies.aspa import ASPA
from bgpsimulator.simulation_engine.routing_policy.custom_policies.aspawn import ASPAwN
from bgpsimulator.simulation_engine.routing_policy.custom_policies.asra import ASRA
from bgpsimulator.simulation_engine.routing_policy.custom_policies.bgp import BGP
from bgpsimulator.simulation_engine.routing_policy.custom_policies.edge_filter import EdgeFilter
from bgpsimulator.simulation_engine.routing_policy.custom_policies.only_to_customers import OnlyToCustomers
from bgpsimulator.simulation_engine.routing_policy.custom_policies.enforce_first_as import EnforceFirstAS
from bgpsimulator.simulation_engine.routing_policy.custom_policies.rov import ROV
from bgpsimulator.simulation_engine.routing_policy.custom_policies.path_end import PathEnd
from bgpsimulator.simulation_engine.routing_policy.custom_policies.peerlock_lite import PeerLockLite

if TYPE_CHECKING:
    from weakref import CallableProxyType
    from bgpsimulator.as_graphs import AS


class RoutingPolicy:

    __slots__ = ("local_rib", "recv_q", "base_routing_policy_settings", "overriden_routing_policy_settings", "as_")

    most_specific_prefix_cache: dict[tuple[IPAddr, tuple[Prefix, ...]], Prefix | None] = dict()

    # Used when dumping the routing policy to JSON
    name_to_cls_dict: dict[str, type["RoutingPolicy"]] = {}

    route_validator = RouteValidator()

    def __init_subclass__(cls, **kwargs):
        """Used when dumping the routing policy to JSON

        NOTE: Rust should not support this
        """
        super().__init_subclass__(**kwargs)
        RoutingPolicy.name_to_cls_dict[cls.__name__] = cls

    def __init__(
        self,
        as_: "AS",
        base_routing_policy_settings: dict[str, bool] | None = None,
        overriden_routing_policy_settings: dict[str, bool] | None = None,
        local_rib: dict[str, Ann] | None = None,
    ) -> None:
        """Add local rib and data structures here

        This way they can be easily cleared later without having to redo
        the graph

        This is also useful for regenerating an AS from YAML
        """

        self.local_rib: dict[Prefix, Ann] = local_rib or dict()
        self.recv_q: defaultdict[Prefix, list[Ann]] = defaultdict(list)
        default_routing_policy_settings: dict[RoutingPolicySettings, bool] = {
            x: False for x in RoutingPolicySettings
        }
        # Base routing policy settings are the default settings for all ASes
        self.base_routing_policy_settings: dict[RoutingPolicySettings, bool] = base_routing_policy_settings or default_routing_policy_settings
        # Overriden routing policy settings are the settings that will be applied to the ASes
        self.overriden_routing_policy_settings: dict[RoutingPolicySettings, bool] = overriden_routing_policy_settings or dict()
        # The AS object that this routing policy is associated with
        self.as_: CallableProxyType["AS"] = proxy(as_)

    def __eq__(self, other) -> bool:
        if isinstance(other, RoutingPolicy):
            return self.to_json() == other.to_json()
        else:
            return NotImplemented

    def clear(self) -> None:
        """Clears the routing policy"""

        self.local_rib.clear()
        self.recv_q.clear()

    #########################
    # Process Incoming Anns #
    #########################

    def seed_ann(self, ann: Ann) -> None:
        """Seeds an announcement at this AS"""

        # Ensure we aren't replacing anything
        err = f"Seeding conflict {ann} {self.local_rib.get(ann.prefix)}"
        assert self.local_rib.get(ann.prefix) is None, err
        # Seed by placing in the local rib
        self.local_rib[ann.prefix] = ann

    def receive_ann(self, ann: Ann) -> None:
        """Receives an announcement from a neighbor"""

        self.recv_q[ann.prefix].append(ann)

    def process_incoming_anns(
        self,
        *,
        from_rel: Relationships,
        propagation_round: int = 0,
        **kwargs,
    ) -> None:
        """Process all announcements that were incoming from a specific rel"""

        # For each prefix, get all anns recieved
        for prefix, ann_list in self.recv_q.items():
            # Get announcement currently in local rib
            current_ann: Ann | None = self.local_rib.get(prefix)
            og_ann = current_ann

            # For each announcement that was incoming
            for new_ann in ann_list:
                current_ann = self._get_new_best_ann(current_ann, new_ann, from_rel)

            # This is a new best ann. Process it and add it to the local rib
            if og_ann != current_ann:
                # Save to local rib
                self.local_rib[current_ann.prefix] = current_ann

        self.recv_q.clear()

    def _get_new_best_ann(
        self, current_ann: Ann | None, new_ann: Ann, from_rel: Relationships
    ) -> Ann | None:
        """Cheks new_ann's validity, processes it, and returns best_ann_by_gao_rexford"""

        if self.valid_ann(new_ann, from_rel, self.as_):
            new_ann_processed = new_ann.copy(
                as_path=(self.as_.asn, *new_ann.as_path),
                recv_relationship=from_rel,
            )
            return self._get_best_ann_by_gao_rexford(current_ann, new_ann_processed)
        else:
            return current_ann

    def valid_ann(self, ann: Ann, from_rel: Relationships, as_obj: "AS") -> bool:
        """Determine if an announcement is valid or should be dropped"""

        settings = self.overriden_routing_policy_settings

        if BGP.valid_ann(ann, from_rel, as_obj):
            return False
        # ASPAwN and ASRA are supersets of ASPA
        if settings.get(RoutingPolicySettings.ASPA, False) and not settings.get(RoutingPolicySettings.ASRA, False) and not settings.get(RoutingPolicySettings.ASPA_W_N, False) and not ASPA.valid_ann(ann, from_rel, as_obj):
            return False
        if settings.get(RoutingPolicySettings.ASPA_W_N, False) and not settings.get(RoutingPolicySettings.ASRA, False) and not ASPAwN.valid_ann(ann, from_rel, as_obj):
            return False
        if settings.get(RoutingPolicySettings.ASRA, False) and not ASRA.valid_ann(ann, from_rel, as_obj):
            return False
        if settings.get(RoutingPolicySettings.EDGE_FILTER, False) and not EdgeFilter.valid_ann(ann, from_rel, as_obj):
            return False
        if settings.get(RoutingPolicySettings.ENFORCE_FIRST_AS, False) and not EnforceFirstAS.valid_ann(ann, from_rel, as_obj):
            return False
        if settings.get(RoutingPolicySettings.ONLY_TO_CUSTOMERS, False) and not OnlyToCustomers.valid_ann(ann, from_rel, as_obj):
            return False
        if settings.get(RoutingPolicySettings.ROV, False) and not ROV.valid_ann(ann, from_rel, as_obj):
            return False
        if settings.get(RoutingPolicySettings.PATH_END, False) and not PathEnd.valid_ann(ann, from_rel, as_obj):
            return False
        if settings.get(RoutingPolicySettings.PEER_LOCK_LITE, False) and not PeerLockLite.valid_ann(ann, from_rel, as_obj):
            return False

        return True

    ###############
    # Gao rexford #
    ###############

    def _get_best_ann_by_gao_rexford(
        self,
        current_ann: Ann | None,
        new_ann: Ann,
    ) -> Ann:
        """Determines if the new ann > current ann by Gao Rexford"""

        assert new_ann is not None, "New announcement can't be None"

        # When I had this as a list of funcs, it was 7x slower, resulting in bottlenecks
        # Gotta do it the ugly way unfortunately
        final_ann = (
            (new_ann if current_ann is None else None)
            or self._get_best_ann_by_local_pref(current_ann, new_ann)
            or self._get_best_ann_by_as_path(current_ann, new_ann)
            or self._get_best_ann_by_lowest_neighbor_asn_tiebreaker(current_ann, new_ann)
        )
        if final_ann:
            return final_ann
        else:
            raise GaoRexfordError("No ann was chosen")


    def _get_best_ann_by_local_pref(
        self, current_ann: Ann, new_ann: Ann
    ) -> Ann | None:
        """Returns best announcement by local pref, or None if tie. Higher is better"""

        if current_ann.recv_relationship.value > new_ann.recv_relationship.value:
            return current_ann
        elif current_ann.recv_relationship.value < new_ann.recv_relationship.value:
            return new_ann

    def _get_best_ann_by_as_path(self, current_ann: Ann, new_ann: Ann) -> Ann | None:
        """Returns best announcement by as path length, or None if tie. Shorter is better"""

        if len(current_ann.as_path) < len(new_ann.as_path):
            return current_ann
        elif len(current_ann.as_path) > len(new_ann.as_path):
            return new_ann


    def _get_best_ann_by_lowest_neighbor_asn_tiebreaker(
        self, current_ann: Ann, new_ann: Ann
    ) -> Ann:
        """Determines if the new ann > current ann by Gao Rexford for ties

        This breaks ties by lowest asn of the neighbor sending the announcement
        So if the two announcements are from the same neighbor, return current ann
        """

        current_neighbor_asn = current_ann.as_path[min(len(current_ann.as_path), 1)]
        new_neighbor_asn = new_ann.as_path[min(len(new_ann.as_path), 1)]

        return current_ann if current_neighbor_asn <= new_neighbor_asn else new_ann

    def propagate_to_providers(self) -> None:
        """Propogates to providers anns that have recv_rel from origin or customers"""

        send_rels: set[Relationships] = {Relationships.ORIGIN, Relationships.CUSTOMERS}
        self._propagate(Relationships.PROVIDERS, send_rels)


    def propagate_to_customers(self) -> None:
        """Propogates to customers anns that have a known recv_rel"""

        send_rels: set[Relationships] = {
            Relationships.ORIGIN,
            Relationships.CUSTOMERS,
            Relationships.PEERS,
            Relationships.PROVIDERS,
        }
        self._propagate(Relationships.CUSTOMERS, send_rels)


    def propagate_to_peers(self) -> None:
        """Propogates to peers anns from this AS (origin) or from customers"""

        send_rels: set[Relationships] = {Relationships.ORIGIN, Relationships.CUSTOMERS}
        self._propagate(Relationships.PEERS, send_rels)


    def _propagate(self, propagate_to: Relationships, send_rels: set[Relationships]) -> None:
        """Propogates announcements from local rib to other ASes

        send_rels are the relationships that are acceptable to send
        """

        neighbor_ases = self.as_.get_neighbor(propagate_to)

        for _prefix, unprocessed_ann in self.local_rib.items():
            # We must set the next_hop when sending
            # Copying announcements is a bottleneck for sims,
            # so we try to do this as little as possible
            if neighbor_ases and unprocessed_ann.recv_relationship in send_rels:
                ann = unprocessed_ann.copy(next_hop_asn=self.as_.asn)
            else:
                continue

            for neighbor_as in neighbor_ases:
                if ann.recv_relationship in send_rels:
                    # Policy took care of it's own propagation for this ann
                    if self.policy_propagate(neighbor_as, ann, propagate_to, send_rels):
                        continue
                    else:
                        self.process_outgoing_ann(neighbor_as, ann, propagate_to, send_rels)

    def policy_propagate(
        self,
        neighbor_as: "AS",
        ann: Ann,
        propagate_to: Relationships,
        send_rels: set[Relationships],
    ) -> bool:
        """Policies can override this to handle their own propagation and return True"""

        policy_propagate_ann = None
        if self.overriden_routing_policy_settings.get(RoutingPolicySettings.ONLY_TO_CUSTOMERS, False):
            policy_propagate_info = OnlyToCustomers.get_policy_propagate_vals(neighbor_as, ann, propagate_to, send_rels, self)
            if policy_propagate_info.policy_propagate_bool:
                policy_propagate_ann = policy_propagate_info.ann
                if not policy_propagate_info.send_ann_bool:
                    return False

        if policy_propagate_ann:
            self.process_outgoing_ann(neighbor_as, policy_propagate_ann, propagate_to, send_rels)


        return policy_propagate

    def process_outgoing_ann(
        self,
        neighbor_as: "AS",
        ann: Ann,
        propagate_to: Relationships,
        send_rels: set[Relationships],
    ) -> None:
        """Adds ann to the neighbors recv q"""

        # Add the new ann to the incoming anns for that prefix
        neighbor_as.routing_policy.receive_ann(ann)

    #########################
    # Data Plane Validation #
    #########################

    def get_most_specific_ann(self, dest_ip_addr: IPAddr) -> Ann | None:
        """Returns the most specific announcement for a destination IP address

        Uses caching whenever possible to avoid expensive lookups at each AS
        however, don't cache large RIBs, there won't be duplicates,
        and don't keep too many in the cache, there won't be duplicates
        We need to watch our RAM here
        """

        most_specific_prefix = None

        # Dont' cache massive RIBs, there won't be duplicates
        if len(self.local_rib) < 10:
            most_specific_prefix = self.most_specific_prefix_cache.get((dest_ip_addr, tuple(list(self.local_rib.keys()))))

        if most_specific_prefix is None:
            matching_prefixes = sorted(
                (p for p in self.local_rib if dest_ip_addr in p),
                key=lambda p: p.prefixlen,
                reverse=True
            )
            most_specific_prefix = matching_prefixes[0] if matching_prefixes else None

        # Don't cache massive ribs, pointless, there won't be duplicates
        if len(self.local_rib) < 10:
            self.most_specific_prefix_cache[(dest_ip_addr, tuple(list(self.local_rib.keys())))] = most_specific_prefix
            # Don't cache too many, it's pointless
            if len(self.most_specific_prefix_cache) > 10:
                self.most_specific_prefix_cache.pop()

        return self.local_rib[most_specific_prefix] if most_specific_prefix else None

    def passes_sav(self, dest_ip_addr: IPAddr, most_specific_ann: Ann) -> bool:
        """Determines if the AS passes the source address validation check"""

        return True

    ##############
    # JSON funcs #
    ##############

    def to_json(self) -> dict[str, Any]:
        """Converts the routing policy to a JSON object"""
        return {
            "local_rib": {prefix: ann.to_json() for prefix, ann in self.local_rib.items()},
            "base_routing_policy_settings": self.base_routing_policy_settings,
            "overriden_routing_policy_settings": self.overriden_routing_policy_settings,
        }

    @classmethod
    def from_json(cls, json_obj: dict[str, Any], as_: "AS") -> "RoutingPolicy":
        return cls(
            as_=as_,
            local_rib={prefix: Ann.from_json(ann) for prefix, ann in json_obj["local_rib"].items()},
            base_routing_policy_settings=json_obj["base_routing_policy_settings"],
            overriden_routing_policy_settings=json_obj["overriden_routing_policy_settings"],
        )


RoutingPolicy.name_to_cls_dict["RoutingPolicy"] = RoutingPolicy
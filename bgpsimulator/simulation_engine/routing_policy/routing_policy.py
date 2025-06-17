from typing import TYPE_CHECKING, Any
from warnings import warn

from frozendict import frozendict

from bgpsimulator.shared.exceptions import GaoRexfordError  
from bgpsimulator.simulation_engine.announcement import Announcement as Ann
from bgpsimulator.shared import Relationships

if TYPE_CHECKING:
    from weakref import CallableProxyType
    from bgpsimulator.as_graphs import AS


class RoutingPolicy:

    def __init__(
        self,
        as_: "AS",
        base_routing_policy_settings: frozendict[str, bool] = frozendict(),
        overriden_routing_policy_settings: frozendict[str, bool] = frozendict(),
        local_rib: dict[str, Ann] | None = None,
    ) -> None:
        """Add local rib and data structures here
        
        This way they can be easily cleared later without having to redo
        the graph

        This is also useful for regenerating an AS from YAML
        """

        self.local_rib: dict[str, Ann] = local_rib or dict()
        self.recv_q: defaultdict[str, list[Ann]] = defaultdict(list)
        self.base_routing_policy_settings: frozendict[str, bool] = base_routing_policy_settings
        self.overriden_routing_policy_settings: frozendict[str, bool] = overriden_routing_policy_settings
        # This gets set within the AS class so it's fine
        self.as_: CallableProxyType[AS] = as_

    def __eq__(self, other) -> bool:
        if isinstance(other, RoutingPolicy):
            return self.to_json() == other.to_json()
        else:
            return NotImplemented

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
                self.local_rib[ann.prefix] = current_ann

        self.recv_q.clear()

    def _get_new_best_ann(
        self, current_ann: Ann | None, new_ann: Ann, from_rel: Relationships
    ) -> Ann | None:
        """Cheks new_ann's validity, processes it, and returns best_ann_by_gao_rexford"""

        if self._valid_ann(new_ann, from_rel):
            new_ann_processed = new_ann.copy(
                as_path=[self.as_.asn, *new_ann.as_path],
                recv_relationship=from_rel,
            )
            return self._get_best_ann_by_gao_rexford(current_ann, new_ann_processed)
        else:
            return current_ann

    def _valid_ann(self, ann: Ann, from_rel: Relationships) -> bool:
        """Determine if an announcement is valid or should be dropped"""

        # BGP Loop Prevention Check; no AS 0 either
        return self.as_.asn not in ann.as_path and 0 not in ann.as_path

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
                ann = unprocessed_ann.copy({"next_hop_asn": self.as_.asn})
            else:
                continue

            for neighbor_as in neighbor_ases:
                if ann.recv_relationship in send_rels:
                    # Policy took care of it's own propagation for this ann
                    if self._policy_propagate(neighbor_as, ann, propagate_to, send_rels):
                        continue
                    else:
                        self._process_outgoing_ann(neighbor_as, ann, propagate_to, send_rels)

    def _policy_propagate(
        self,
        neighbor_as: AS,
        ann: Ann,
        propagate_to: Relationships,
        send_rels: set[Relationships],
    ) -> bool:
        """Policies can override this to handle their own propagation and return True"""

        return False

    def _process_outgoing_ann(
        self,
        neighbor_as: AS,
        ann: Ann,
        propagate_to: Relationships,
        send_rels: set[Relationships],
    ) -> None:
        """Adds ann to the neighbors recv q"""

        # Add the new ann to the incoming anns for that prefix
        neighbor_as.policy.receive_ann(ann)

    ##############
    # JSON funcs #
    ##############

    def to_json(self) -> dict[str, Any]:
        """Converts the routing policy to a JSON object"""
        return {
            "local_rib": self.local_rib,
            "base_routing_policy_settings": self.base_routing_policy_settings,
            "overriden_routing_policy_settings": self.overriden_routing_policy_settings,
        }

    @classmethod
    def from_json(cls, json_obj: dict[str, Any]) -> "RoutingPolicy":
        return cls(
            local_rib=json_obj["local_rib"],
            base_routing_policy_settings=json_obj["base_routing_policy_settings"],
            overriden_routing_policy_settings=json_obj["overriden_routing_policy_settings"],
        )
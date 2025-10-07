from collections import defaultdict
from typing import TYPE_CHECKING, Any, cast
from weakref import proxy

from bgpsimulator.route_validator import RouteValidator
from bgpsimulator.shared import IPAddr, Prefix, Relationships, ROAValidity, Settings
from bgpsimulator.shared.exceptions import GaoRexfordError
from bgpsimulator.simulation_engine.announcement import Announcement as Ann

from .policy_extensions import (
    ASPA,
    ASPAPP,
    ASRA,
    BGP,
    ROST,
    ROV,
    AnnounceThenWithdraw,
    Leaker,
    ASPathEdgeFilter,
    ASPAwN,
    BGPiSecTransitive,
    BGPSec,
    EnforceFirstAS,
    FirstASNStrippingPrefixHijackCustomers,
    OnlyToCustomers,
    OriginPrefixHijackCustomers,
    PathEnd,
    PeerLockLite,
    PeerROV,
    ProviderConeID,
    RoSTTrustedRepository,
    ROVPPV1Lite,
    ROVPPV2iLite,
    ROVPPV2Lite,
    NeverPropagateWithdrawals,
)
from .adj_ribs_in import AdjRIBsIn
from .adj_ribs_out import AdjRIBsOut

if TYPE_CHECKING:
    from bgpsimulator.as_graphs import AS


class Policy:
    __slots__ = (
        "local_rib",
        "recv_q",
        "settings",
        "as_",
        "adj_ribs_in",
        "adj_ribs_out",
    )

    route_validator = RouteValidator()
    rost_trusted_repository = RoSTTrustedRepository()

    def __init__(
        self,
        as_: "AS",
        settings: tuple[bool] | None = None,
        local_rib: dict[Prefix, Ann] | None = None,
        adj_ribs_in: AdjRIBsIn | None = None,
        adj_ribs_out: AdjRIBsOut | None = None,
    ) -> None:
        """Add local rib and data structures here

        This way they can be easily cleared later without having to redo
        the graph

        This is also useful for regenerating an AS from YAML
        """

        self.local_rib: dict[Prefix, Ann] = local_rib or dict()
        self.recv_q: defaultdict[Prefix, list[Ann]] = defaultdict(list)
        self.adj_ribs_in: AdjRIBsIn = adj_ribs_in or AdjRIBsIn()
        self.adj_ribs_out: AdjRIBsOut = adj_ribs_out or AdjRIBsOut()
        self.rost_trusted_repository.clear()
        if settings:
            self.settings: tuple[bool, ...] = settings
        else:
            self.settings = tuple([False for _ in Settings])
        # The AS object that this routing policy is associated with
        # Casting this so we don't ened to put callable proxy type everywhere
        self.as_: AS = cast("AS", proxy(as_))

    def __eq__(self, other) -> bool:
        if isinstance(other, Policy):
            return self.to_json() == other.to_json()
        else:
            return NotImplemented

    def clear(self) -> None:
        """Clears the routing policy"""

        self.local_rib.clear()
        self.recv_q.clear()
        self.adj_ribs_in.clear()
        self.adj_ribs_out.clear()

    #########################
    # Process Incoming Anns #
    #########################

    def seed_ann(self, ann: Ann) -> None:
        """Seeds an announcement at this AS"""

        # Ensure we aren't replacing anything
        err = f"Seeding conflict {ann} {self.local_rib.get(ann.prefix)}"
        assert self.local_rib.get(ann.prefix) is None, err

        # If BGPSEC is deployed, modify the announcement
        if (
            self.settings[Settings.BGPSEC]
            or self.settings[Settings.BGP_I_SEC]
            or self.settings[Settings.BGP_I_SEC_TRANSITIVE]
        ):
            ann = BGPSec.get_modified_seed_ann(self, ann)
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

        if self.settings[Settings.ROST]:
            ROST.preprocess_incoming_anns(
                self, from_rel=from_rel, propagation_round=propagation_round
            )

        # For each prefix, get all anns recieved
        for prefix, ann_list in self.recv_q.items():
            # Get announcement currently in local rib
            current_ann: Ann | None = self.local_rib.get(prefix)
            og_ann = current_ann

            # For each announcement that was incoming
            for new_ann in ann_list:
                # Ignore all withdrawals
                if self.settings[Settings.NEVER_WITHDRAW] and new_ann.withdraw:
                    continue

                if self.settings[Settings.BGP_FULL]:
                    # If withdrawal remove from AdjRIBsIn, otherwise add to AdjRIBsIn
                    self._process_new_ann_in_adj_ribs_in(new_ann, prefix, from_rel)

                # Process withdrawals even for invalid anns in the adj_ribs_in
                if new_ann.withdraw and self.settings[Settings.BGP_FULL]:
                    current_ann = self._remove_from_local_rib_and_get_new_best_ann(
                        new_ann, current_ann
                    )
                else:
                    # Get new best ann
                    current_ann = self._get_new_best_ann(current_ann, new_ann, from_rel)

            # This is a new best ann. Process it and add it to the local rib
            if og_ann != current_ann:
                if current_ann:
                    # Save to local rib
                    self.local_rib[current_ann.prefix] = current_ann
                if og_ann and self.settings[Settings.BGP_FULL]:
                    self.withdraw_ann_from_neighbors(
                        og_ann.copy(
                            next_hop_asn=self.as_.asn,
                            withdraw=True,
                        )
                    )

        # NOTE: all three of these have the same process_incoming_anns
        # which just adds ROV++ blackholes to the local RIB
        if (
            self.settings[Settings.ROVPP_V1_LITE]
            or self.settings[Settings.ROVPP_V2_LITE]
            or self.settings[Settings.ROVPP_V2I_LITE]
        ):
            ROVPPV1Lite.process_incoming_anns(self, from_rel, propagation_round)

        if self.settings[Settings.ROST]:
            ROST.postprocess_incoming_anns(self)

        self.recv_q.clear()

    def _get_new_best_ann(
        self, current_ann: Ann | None, new_ann: Ann, from_rel: Relationships
    ) -> Ann | None:
        """Checks new_ann's validity, processes it, returns best_ann_by_gao_rexford."""

        if self.valid_ann(new_ann, from_rel):
            new_ann_processed = self.process_ann(new_ann, from_rel)
            return self._get_best_ann_by_gao_rexford(current_ann, new_ann_processed)
        else:
            return current_ann

    def process_ann(self, unprocessed_ann: Ann, from_rel: Relationships) -> Ann:
        """Processes an announcement going from recv_q or adj_ribs_in to local rib.

        Must prepend yourself to the AS-path, change the recv_relationship, and add
        policy info if needed.
        """
        new_ann_processed = unprocessed_ann.copy(
            as_path=(self.as_.asn, *unprocessed_ann.as_path),
            recv_relationship=from_rel,
        )
        if (
            self.settings[Settings.BGP_I_SEC]
            or self.settings[Settings.BGP_I_SEC_TRANSITIVE]
        ):
            new_ann_processed = BGPiSecTransitive.process_ann(
                self, new_ann_processed, from_rel
            )
        elif self.settings[Settings.BGPSEC]:
            new_ann_processed = BGPSec.process_ann(self, new_ann_processed, from_rel)
        if self.settings[Settings.ROST]:
            new_ann_processed = ROST.process_ann(self, new_ann_processed, from_rel)
        return new_ann_processed

    def valid_ann(self, ann: Ann, from_rel: Relationships) -> bool:
        """Determine if an announcement is valid or should be dropped"""

        settings = self.settings

        if not BGP.valid_ann(self, ann, from_rel):
            return False
        # ASPAwN and ASRA are supersets of ASPA
        if (
            settings[Settings.ASPA]
            and not settings[Settings.ASRA]
            and not settings[Settings.ASPA_W_N]
            and not ASPA.valid_ann(self, ann, from_rel)
        ):
            return False
        if (
            settings[Settings.ASPA_W_N]
            and not settings[Settings.ASRA]
            and not ASPAwN.valid_ann(self, ann, from_rel)
        ):
            return False
        if settings[Settings.ASRA] and not ASRA.valid_ann(self, ann, from_rel):
            return False
        if settings[Settings.AS_PATH_EDGE_FILTER] and not ASPathEdgeFilter.valid_ann(
            self, ann, from_rel
        ):
            return False
        if settings[Settings.ENFORCE_FIRST_AS] and not EnforceFirstAS.valid_ann(
            self, ann, from_rel
        ):
            return False
        if settings[Settings.ONLY_TO_CUSTOMERS] and not OnlyToCustomers.valid_ann(
            self, ann, from_rel
        ):
            return False
        # All use ROV for validity
        if (
            settings[Settings.ROV]
            or settings[Settings.ROVPP_V1_LITE]
            or settings[Settings.ROVPP_V2_LITE]
            or settings[Settings.ROVPP_V2I_LITE]
        ) and not ROV.valid_ann(self, ann, from_rel):
            return False
        if settings[Settings.PEER_ROV] and not PeerROV.valid_ann(self, ann, from_rel):
            return False
        if settings[Settings.PATH_END] and not PathEnd.valid_ann(self, ann, from_rel):
            return False
        if settings[Settings.PEERLOCK_LITE] and not PeerLockLite.valid_ann(
            self, ann, from_rel
        ):
            return False
        if (
            settings[Settings.BGP_I_SEC] or settings[Settings.BGP_I_SEC_TRANSITIVE]
        ) and not BGPiSecTransitive.valid_ann(self, ann, from_rel):
            return False
        if settings[Settings.PROVIDER_CONE_ID] and not ProviderConeID.valid_ann(
            self, ann, from_rel
        ):
            return False
        if settings[Settings.ASPAPP] and not ASPAPP.valid_ann(self, ann, from_rel):
            return False

        return True

    def ann_is_invalid_by_roa(self, ann: Ann) -> bool:
        """Determines if an announcement is invalid by a ROA"""
        return ROAValidity.is_invalid(
            self.route_validator.get_roa_outcome(ann.prefix, ann.origin)[0]
        )

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

        # mypy also doesn't understand that current_ann can not be None for these funcs
        final_ann = (
            (new_ann if current_ann is None else None)
            or self._get_best_ann_by_local_pref(current_ann, new_ann)  # type: ignore
            or self._get_best_ann_by_as_path(current_ann, new_ann)  # type: ignore
            # BGPSec is security third (see BGPSec class docstring)
            # NOTE: BGPiSec policies don't change path preference for easier deployment
            or (
                self.settings[Settings.BGPSEC]
                and BGPSec.get_best_ann_by_bgpsec(
                    self,
                    current_ann,  # type: ignore
                    new_ann,
                )
            )
            or self._get_best_ann_by_lowest_neighbor_asn_tiebreaker(
                current_ann,  # type: ignore
                new_ann,
            )
        )
        if final_ann:
            return final_ann
        else:
            raise GaoRexfordError("No ann was chosen")

    def _get_best_ann_by_local_pref(self, current_ann: Ann, new_ann: Ann) -> Ann | None:
        """Returns best announcement by local pref, or None if tie. Higher is better"""

        if current_ann.recv_relationship.value > new_ann.recv_relationship.value:
            return current_ann
        elif current_ann.recv_relationship.value < new_ann.recv_relationship.value:
            return new_ann
        # mypy requires this and it can't be turned off
        else:
            return None

    def _get_best_ann_by_as_path(self, current_ann: Ann, new_ann: Ann) -> Ann | None:
        """Returns best announcement by as path length, or None if tie.

        Shorter is better.
        """

        if len(current_ann.as_path) < len(new_ann.as_path):
            return current_ann
        elif len(current_ann.as_path) > len(new_ann.as_path):
            return new_ann
        # mypy requires this and it can't be turned off
        else:
            return None

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

    def pre_propagation_hook(
        self, propagation_round: int, scenario: "Scenario"
    ) -> None:
        """Before propagating to anyone, pre-propagation hook"""

        # Withdraws announcements round 2
        if self.settings[Settings.ANNOUNCE_THEN_WITHDRAW]:
            AnnounceThenWithdraw.pre_propagation_hook(self, propagation_round, scenario)
        if self.settings[Settings.LEAKER]:
            Leaker.pre_propagation_hook(self, propagation_round, scenario)

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

    def propagate_to_providers(self) -> None:
        """Propogates to providers anns that have recv_rel from origin or customers"""

        send_rels: set[Relationships] = {Relationships.ORIGIN, Relationships.CUSTOMERS}
        self._propagate(Relationships.PROVIDERS, send_rels)

    def _propagate(
        self, propagate_to: Relationships, send_rels: set[Relationships]
    ) -> None:
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
                if ann.recv_relationship in send_rels and (
                    not self.settings[Settings.BGP_FULL]
                    or not self._prev_sent(neighbor_as, ann)
                ):
                    # Policy took care of it's own propagation for this ann
                    if self.policy_propagate(neighbor_as, ann, propagate_to, send_rels):
                        continue
                    else:
                        self.process_outgoing_ann(
                            neighbor_as, ann, propagate_to, send_rels
                        )

    def policy_propagate(
        self,
        neighbor_as: "AS",
        ann: Ann,
        propagate_to: Relationships,
        send_rels: set[Relationships],
    ) -> bool:
        """Policies can override this to handle their own propagation and return True

        This can no longer be as simple as it was in BGPy since many policies may
        interact with one another. So there are three values returned from each policy:
        1. policy_propagate_bool. If this is False, the policy did nothing, if it is
        true, Policy should return True from this method
        2. ann: The modified ann. This can be then be passed into the other funcs
        3. send_ann_bool. Sometimes a policy may declare the ann shoulldn't be sent at
        all (for example, ROV++V1 won't send blackholes), in which case, just return
        True immediately without sending any anns
        """

        og_ann = ann
        if (
            self.settings[Settings.BGP_I_SEC]
            or self.settings[Settings.BGP_I_SEC_TRANSITIVE]
        ):
            policy_propagate_info = BGPiSecTransitive.get_policy_propagate_vals(
                self, neighbor_as, ann, propagate_to, send_rels
            )
            if policy_propagate_info.policy_propagate_bool:
                ann = policy_propagate_info.ann
                if not policy_propagate_info.send_ann_bool:
                    return True
        # NOTE: THIS MUST BE ELIF!! BGPiSecTransitive is a superset of BGPSec and has
        # different get_policy_propagate_vals
        elif self.settings[Settings.BGPSEC]:
            policy_propagate_info = BGPSec.get_policy_propagate_vals(
                self, neighbor_as, ann, propagate_to, send_rels
            )
            if policy_propagate_info.policy_propagate_bool:
                ann = policy_propagate_info.ann
                if not policy_propagate_info.send_ann_bool:
                    return True

        if self.settings[Settings.ONLY_TO_CUSTOMERS]:
            policy_propagate_info = OnlyToCustomers.get_policy_propagate_vals(
                self, neighbor_as, ann, propagate_to, send_rels
            )
            if policy_propagate_info.policy_propagate_bool:
                ann = policy_propagate_info.ann
                if not policy_propagate_info.send_ann_bool:
                    return True

        if self.settings[Settings.ROVPP_V2I_LITE]:
            policy_propagate_info = ROVPPV2iLite.get_policy_propagate_vals(
                self, neighbor_as, ann, propagate_to, send_rels
            )
            if policy_propagate_info.policy_propagate_bool:
                ann = policy_propagate_info.ann
                if not policy_propagate_info.send_ann_bool:
                    return True
        # If V2i is deployed, don't use V2
        elif self.settings[Settings.ROVPP_V2_LITE]:
            policy_propagate_info = ROVPPV2Lite.get_policy_propagate_vals(
                self, neighbor_as, ann, propagate_to, send_rels
            )
            if policy_propagate_info.policy_propagate_bool:
                ann = policy_propagate_info.ann
                if not policy_propagate_info.send_ann_bool:
                    return True
        # If v2i or v2 are set, don't use v1 (since they are supersets)
        elif self.settings[Settings.ROVPP_V1_LITE]:
            policy_propagate_info = ROVPPV1Lite.get_policy_propagate_vals(
                self, neighbor_as, ann, propagate_to, send_rels
            )
            if policy_propagate_info.policy_propagate_bool:
                ann = policy_propagate_info.ann
                if not policy_propagate_info.send_ann_bool:
                    return True

        if self.settings[Settings.ORIGIN_PREFIX_HIJACK_CUSTOMERS]:
            policy_propagate_info = (
                OriginPrefixHijackCustomers.get_policy_propagate_vals(
                    self, neighbor_as, ann, propagate_to, send_rels
                )
            )
            if policy_propagate_info.policy_propagate_bool:
                ann = policy_propagate_info.ann
                if not policy_propagate_info.send_ann_bool:
                    return True
        if self.settings[Settings.FIRST_ASN_STRIPPING_PREFIX_HIJACK_CUSTOMERS]:
            policy_propagate_info = (
                FirstASNStrippingPrefixHijackCustomers.get_policy_propagate_vals(
                    self, neighbor_as, ann, propagate_to, send_rels
                )
            )
            if policy_propagate_info.policy_propagate_bool:
                ann = policy_propagate_info.ann
                if not policy_propagate_info.send_ann_bool:
                    return True

        if self.settings[Settings.NEVER_PROPAGATE_WITHDRAWALS]:
            policy_propagate_info = NeverPropagateWithdrawals.get_policy_propagate_vals(
                self, neighbor_as, ann, propagate_to, send_rels
            )
            if policy_propagate_info.policy_propagate_bool:
                ann = policy_propagate_info.ann
                if not policy_propagate_info.send_ann_bool:
                    return True

        if og_ann != ann:
            if not ann.withdraw and self.settings[Settings.BGP_FULL]:
                self.adj_ribs_out.add_ann(neighbor_as.asn, ann)
            self.process_outgoing_ann(neighbor_as, ann, propagate_to, send_rels)
            return True
        else:
            return False

    def process_outgoing_ann(
        self,
        neighbor_as: "AS",
        ann: Ann,
        propagate_to: Relationships,
        send_rels: set[Relationships],
    ) -> None:
        """Adds ann to the neighbors recv q"""

        if not ann.withdraw and self.settings[Settings.BGP_FULL]:
            self.adj_ribs_out.add_ann(neighbor_as.asn, ann)
        # Add the new ann to the incoming anns for that prefix
        neighbor_as.policy.receive_ann(ann)

    #########################
    # Data Plane Validation #
    #########################

    def get_most_specific_ann(self, dest_ip_addr: IPAddr) -> Ann | None:
        """Returns the most specific announcement for a destination IP address

        Uses caching whenever possible to avoid expensive lookups at each AS
        however, don't cache large RIBs, there won't be duplicates,
        and don't keep too many in the cache, there won't be duplicates
        We need to watch our RAM here

        NOTE: Caching actually slowed this down by about 1.5x so we don't do it anymore
        """

        matching_prefixes = sorted(
            (p for p in self.local_rib if p.supernet_of(dest_ip_addr)),
            key=lambda p: p.prefixlen,
            reverse=True,
        )
        most_specific_prefix = matching_prefixes[0] if matching_prefixes else None

        return self.local_rib[most_specific_prefix] if most_specific_prefix else None

    def passes_sav(self, dest_ip_addr: IPAddr, most_specific_ann: Ann) -> bool:
        """Determines if the AS passes the source address validation check"""

        return True

    ##################################################
    # BGPFull (withdrawals, ribs in, ribs out) funcs #
    ##################################################

    def _process_new_ann_in_adj_ribs_in(
        self, unprocessed_ann: Ann, prefix: Prefix, from_rel: Relationships
    ) -> None:
        """Adds ann to ribs in if the ann is not a withdrawal"""

        # Remove ann using withdrawal from AdjRIBsIn
        if unprocessed_ann.withdraw:
            neighbor = unprocessed_ann.as_path[0]
            # Remove ann from Ribs in
            self.adj_ribs_in.remove_entry(neighbor, prefix)
        # Add ann to AdjRIBsIn
        else:
            self.adj_ribs_in.add_unprocessed_ann(unprocessed_ann, from_rel)

    def _remove_from_local_rib_and_get_new_best_ann(
        self, new_ann: "Ann", local_rib_ann: "Ann | None"
    ) -> "Ann | None":
        # This is for removing the original local RIB ann
        if (
            local_rib_ann
            and new_ann.prefix == local_rib_ann.prefix
            # new_ann is unproccessed
            and new_ann.as_path == local_rib_ann.as_path[1:]
            and local_rib_ann.recv_relationship != Relationships.ORIGIN
        ):
            # Withdrawal exists in the local RIB, so remove it and reset current ann
            self.local_rib.pop(new_ann.prefix, None)
            local_rib_ann = None
            # Get the new best ann thus far
            processed_best_adj_ribs_in_ann = self._get_and_process_best_adj_ribs_in_ann(
                new_ann.prefix
            )
            if processed_best_adj_ribs_in_ann:
                local_rib_ann = self._get_best_ann_by_gao_rexford(
                    local_rib_ann,
                    processed_best_adj_ribs_in_ann,
                )

        return local_rib_ann

    def withdraw_ann_from_neighbors(self, withdraw_ann: Ann) -> None:
        """Withdraw a route from all neighbors.

        This function will not remove an announcement from the local rib, that
        should be done before calling this function.

        Note that withdraw_ann is a deep copied ann
        """
        assert withdraw_ann.withdraw is True
        assert withdraw_ann.next_hop_asn == self.as_.asn
        if self.settings[Settings.ROST]:
            ROST.withdraw_ann_from_neighbors(self, withdraw_ann)
        # Check adj_ribs_out to see where the withdrawn ann was sent
        for send_neighbor_asn in self.adj_ribs_out.populated_neighbors():
            # Delete ann from ribs out
            removed = self.adj_ribs_out.remove_entry(
                send_neighbor_asn, withdraw_ann.prefix
            )
            # If the announcement was sent to that neighbor
            if removed:
                send_rels = set(Relationships)
                if send_neighbor_asn in self.as_.customer_asns:
                    propagate_to = Relationships.CUSTOMERS
                elif send_neighbor_asn in self.as_.provider_asns:
                    propagate_to = Relationships.PROVIDERS
                elif send_neighbor_asn in self.as_.peer_asns:
                    propagate_to = Relationships.PEERS
                else:
                    raise NotImplementedError("Case not accounted for")
                send_neighbor = self.as_.as_graph.as_dict[send_neighbor_asn]
                # Policy took care of it's own propagation for this ann
                if self.policy_propagate(
                    send_neighbor, withdraw_ann, propagate_to, send_rels
                ):
                    continue
                else:
                    self.process_outgoing_ann(
                        send_neighbor, withdraw_ann, propagate_to, send_rels
                    )

    def _get_and_process_best_adj_ribs_in_ann(self, prefix: Prefix) -> "Ann | None":
        """Selects best ann from ribs in (remember, AdjRIBsIn is unprocessed"""

        # Get the best announcement
        best_ann: Ann | None = None
        for ann_info in self.adj_ribs_in.get_ann_infos(prefix):
            # This also processes the announcement
            best_ann = self._get_new_best_ann(
                best_ann, ann_info.unprocessed_ann, ann_info.recv_relationship
            )
        return best_ann

    def _prev_sent(self, neighbor: "AS", ann: Ann) -> bool:
        """Don't send what we've already sent"""

        return ann == self.adj_ribs_out.get_ann(neighbor.asn, ann.prefix)

    ##############
    # JSON funcs #
    ##############

    def to_json(self) -> dict[str, Any]:
        """Converts the routing policy to a JSON object"""
        return {
            "local_rib": {
                str(prefix): ann.to_json() for prefix, ann in self.local_rib.items()
            },
            "settings": list(self.settings),
            "adj_ribs_in": self.adj_ribs_in.to_json(),
            "adj_ribs_out": self.adj_ribs_out.to_json(),
        }

    @classmethod
    def from_json(cls, json_obj: dict[str, Any], as_: "AS") -> "Policy":
        return cls(
            as_=as_,
            local_rib={
                Prefix(prefix): Ann.from_json(ann)
                for prefix, ann in json_obj.get("local_rib", {}).items()
            },
            adj_ribs_in=AdjRIBsIn.from_json(json_obj.get("adj_ribs_in", {})),
            adj_ribs_out=AdjRIBsOut.from_json(json_obj.get("adj_ribs_out", {})),
            settings=tuple(json_obj.get("settings", [])),
        )

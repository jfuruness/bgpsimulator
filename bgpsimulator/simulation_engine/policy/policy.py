from collections import defaultdict
from typing import TYPE_CHECKING, Any
from warnings import warn
from weakref import proxy

from bgpsimulator.shared.exceptions import GaoRexfordError
from bgpsimulator.simulation_engine.announcement import Announcement as Ann
from bgpsimulator.shared import Relationships
from bgpsimulator.shared import Settings, ROAValidity
from bgpsimulator.shared import Prefix, IPAddr
from bgpsimulator.route_validator import RouteValidator
from .policy_extensions import (
    ASPathEdgeFilter,
    ASPA,
    ASPAwN,
    ASRA,
    BGP,
    OnlyToCustomers,
    EnforceFirstAS,
    ROV,
    PathEnd,
    PeerLockLite,
    ROVPPV1Lite,
    ROVPPV2Lite,
    ROVPPV2iLite,
    BGPSec,
    BGPiSecTransitive,
    ProviderConeID,
    OriginPrefixHijackCustomers,
    FirstASNStrippingPrefixHijackCustomers,
    PeerROV,
)

if TYPE_CHECKING:
    from weakref import CallableProxyType
    from bgpsimulator.as_graphs import AS


class Policy:
    __slots__ = ("local_rib", "recv_q", "settings", "as_")

    most_specific_prefix_cache: dict[
        tuple[IPAddr, tuple[Prefix, ...]], Prefix | None
    ] = dict()

    route_validator = RouteValidator()

    def __init__(
        self,
        as_: "AS",
        settings: dict[str, bool] | None = None,
        local_rib: dict[str, Ann] | None = None,
    ) -> None:
        """Add local rib and data structures here

        This way they can be easily cleared later without having to redo
        the graph

        This is also useful for regenerating an AS from YAML
        """

        self.local_rib: dict[Prefix, Ann] = local_rib or dict()
        self.recv_q: defaultdict[Prefix, list[Ann]] = defaultdict(list)
        if settings:
            self.settings: dict[Settings, bool] = settings
        else:
            self.settings = {x: False for x in Settings}
        # The AS object that this routing policy is associated with
        self.as_: CallableProxyType["AS"] = proxy(as_)

    def __eq__(self, other) -> bool:
        if isinstance(other, Policy):
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

        # If BGPSEC is deployed, modify the announcement
        if self.settings.get(Settings.BGPSEC, False) or self.settings.get(Settings.BGP_I_SEC, False) or self.settings.get(Settings.BGP_I_SEC_TRANSITIVE, False):
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


        # NOTE: all three of these have the same process_incoming_anns
        # which just adds ROV++ blackholes to the local RIB
        if (
            self.settings.get(Settings.ROVPP_V1_LITE, False)
            or self.settings.get(Settings.ROVPP_V2_LITE, False)
            or self.settings.get(Settings.ROVPP_V2I_LITE, False)
        ):
            ROVPPV1Lite.process_incoming_anns(self, from_rel, propagation_round)

        self.recv_q.clear()

    def _get_new_best_ann(
        self, current_ann: Ann | None, new_ann: Ann, from_rel: Relationships
    ) -> Ann | None:
        """Cheks new_ann's validity, processes it, and returns best_ann_by_gao_rexford"""

        if self.valid_ann(new_ann, from_rel):
            new_ann_processed = self.process_ann(new_ann, from_rel)
            return self._get_best_ann_by_gao_rexford(current_ann, new_ann_processed)
        else:
            return current_ann

    def process_ann(self, unprocessed_ann: Ann, from_rel: Relationships) -> Ann:
        """Processes an announcement going from recv_q or ribs_in to local rib
        
        Must prepend yourself to the AS-path, change the recv_relationship, and add policy info if needed
        """
        new_ann_processed = unprocessed_ann.copy(
            as_path=(self.as_.asn, *unprocessed_ann.as_path),
            recv_relationship=from_rel,
        )
        if self.settings.get(Settings.BGP_I_SEC, False) or self.settings.get(Settings.BGP_I_SEC_TRANSITIVE, False):
            new_ann_processed = BGPiSecTransitive.process_ann(
                self, new_ann_processed, from_rel
            )
        elif self.settings.get(Settings.BGPSEC, False):
            new_ann_processed = BGPSec.process_ann(
                self, new_ann_processed, from_rel
            )
        return new_ann_processed

    def valid_ann(self, ann: Ann, from_rel: Relationships) -> bool:
        """Determine if an announcement is valid or should be dropped"""

        settings = self.settings

        if not BGP.valid_ann(self, ann, from_rel):
            return False
        # ASPAwN and ASRA are supersets of ASPA
        if (
            settings.get(Settings.ASPA, False)
            and not settings.get(Settings.ASRA, False)
            and not settings.get(Settings.ASPA_W_N, False)
            and not ASPA.valid_ann(self, ann, from_rel)
        ):
            return False
        if (
            settings.get(Settings.ASPA_W_N, False)
            and not settings.get(Settings.ASRA, False)
            and not ASPAwN.valid_ann(self, ann, from_rel)
        ):
            return False
        if settings.get(Settings.ASRA, False) and not ASRA.valid_ann(
            self, ann, from_rel
        ):
            return False
        if settings.get(
            Settings.AS_PATH_EDGE_FILTER, False
        ) and not ASPathEdgeFilter.valid_ann(self, ann, from_rel):
            return False
        if settings.get(
            Settings.ENFORCE_FIRST_AS, False
        ) and not EnforceFirstAS.valid_ann(self, ann, from_rel):
            return False
        if settings.get(
            Settings.ONLY_TO_CUSTOMERS, False
        ) and not OnlyToCustomers.valid_ann(self, ann, from_rel):
            return False
        # All use ROV for validity
        if (settings.get(Settings.ROV, False) or settings.get(Settings.ROVPP_V1_LITE, False) or settings.get(Settings.ROVPP_V2_LITE, False) or settings.get(Settings.ROVPP_V2I_LITE, False)) and not ROV.valid_ann(self, ann, from_rel):
            return False
        if settings.get(Settings.PEER_ROV, False) and not PeerROV.valid_ann(self, ann, from_rel):
            return False
        if settings.get(Settings.PATH_END, False) and not PathEnd.valid_ann(
            self, ann, from_rel
        ):
            return False
        if settings.get(Settings.PEERLOCK_LITE, False) and not PeerLockLite.valid_ann(
            self, ann, from_rel
        ):
            return False
        if (settings.get(Settings.BGP_I_SEC, False) or settings.get(Settings.BGP_I_SEC_TRANSITIVE, False)) and not BGPiSecTransitive.valid_ann(self, ann, from_rel):
            return False
        if settings.get(Settings.PROVIDER_CONE_ID, False) and not ProviderConeID.valid_ann(self, ann, from_rel):
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
        final_ann = (
            (new_ann if current_ann is None else None)
            or self._get_best_ann_by_local_pref(current_ann, new_ann)
            or self._get_best_ann_by_as_path(current_ann, new_ann)
            # BGPSec is security third (see BGPSec class docstring)
            # NOTE: BGPiSec policies don't change path preference for easier deployment
            or (
                self.settings.get(Settings.BGPSEC, False)
                and BGPSec.get_best_ann_by_bgpsec(self, current_ann, new_ann)
            )
            or self._get_best_ann_by_lowest_neighbor_asn_tiebreaker(
                current_ann, new_ann
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
                if ann.recv_relationship in send_rels:
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
        3. send_ann_bool. Sometimes a policy may declare the ann shoulldn't be sent at all
        (for example, ROV++V1 won't send blackholes), in which case, just return True immediately
        without sending any anns
        """

        og_ann = ann
        if self.settings.get(Settings.BGP_I_SEC, False) or self.settings.get(Settings.BGP_I_SEC_TRANSITIVE, False):
            policy_propagate_info = BGPiSecTransitive.get_policy_propagate_vals(
                self, neighbor_as, ann, propagate_to, send_rels
            )
            if policy_propagate_info.policy_propagate_bool:
                ann = policy_propagate_info.ann
                if not policy_propagate_info.send_ann_bool:
                    return True
        # NOTE: THIS MUST BE ELIF!! BGPiSecTransitive is a superset of BGPSec and has different get_policy_propagate_vals
        elif self.settings.get(Settings.BGPSEC, False):
            policy_propagate_info = BGPSec.get_policy_propagate_vals(
                self, neighbor_as, ann, propagate_to, send_rels
            )
            if policy_propagate_info.policy_propagate_bool:
                ann = policy_propagate_info.ann
                if not policy_propagate_info.send_ann_bool:
                    return True

        if self.settings.get(Settings.ONLY_TO_CUSTOMERS, False):
            policy_propagate_info = OnlyToCustomers.get_policy_propagate_vals(
                self, neighbor_as, ann, propagate_to, send_rels
            )
            if policy_propagate_info.policy_propagate_bool:
                ann = policy_propagate_info.ann
                if not policy_propagate_info.send_ann_bool:
                    return True


        if self.settings.get(Settings.ROVPP_V2I_LITE, False):
            policy_propagate_info = ROVPPV2iLite.get_policy_propagate_vals(
                self, neighbor_as, ann, propagate_to, send_rels
            )
            if policy_propagate_info.policy_propagate_bool:
                ann = policy_propagate_info.ann
                if not policy_propagate_info.send_ann_bool:
                    return True
        # If V2i is deployed, don't use V2
        elif self.settings.get(Settings.ROVPP_V2_LITE, False):
            policy_propagate_info = ROVPPV2Lite.get_policy_propagate_vals(
                self, neighbor_as, ann, propagate_to, send_rels
            )
            if policy_propagate_info.policy_propagate_bool:
                ann = policy_propagate_info.ann
                if not policy_propagate_info.send_ann_bool:
                    return True
        # If v2i or v2 are set, don't use v1 (since they are supersets)
        elif self.settings.get(Settings.ROVPP_V1_LITE, False):
            policy_propagate_info = ROVPPV1Lite.get_policy_propagate_vals(
                self, neighbor_as, ann, propagate_to, send_rels
            )
            if policy_propagate_info.policy_propagate_bool:
                ann = policy_propagate_info.ann
                if not policy_propagate_info.send_ann_bool:
                    return True

        if self.settings.get(Settings.ORIGIN_PREFIX_HIJACK_CUSTOMERS, False):
            policy_propagate_info = OriginPrefixHijackCustomers.get_policy_propagate_vals(
                self, neighbor_as, ann, propagate_to, send_rels
            )
            if policy_propagate_info.policy_propagate_bool:
                ann = policy_propagate_info.ann
                if not policy_propagate_info.send_ann_bool:
                    return True
        if self.settings.get(Settings.FIRST_ASN_STRIPPING_PREFIX_HIJACK_CUSTOMERS, False):
            policy_propagate_info = FirstASNStrippingPrefixHijackCustomers.get_policy_propagate_vals(
                self, neighbor_as, ann, propagate_to, send_rels
            )
            if policy_propagate_info.policy_propagate_bool:
                ann = policy_propagate_info.ann
                if not policy_propagate_info.send_ann_bool:
                    return True

        if og_ann != ann:
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
        """

        most_specific_prefix = None

        # Dont' cache massive RIBs, there won't be duplicates
        if len(self.local_rib) < 10:
            most_specific_prefix = self.most_specific_prefix_cache.get(
                (dest_ip_addr, tuple(list(self.local_rib.keys())))
            )

        if most_specific_prefix is None:
            matching_prefixes = sorted(
                (p for p in self.local_rib if p.supernet_of(dest_ip_addr)),
                key=lambda p: p.prefixlen,
                reverse=True,
            )
            most_specific_prefix = matching_prefixes[0] if matching_prefixes else None

        # Don't cache massive ribs, pointless, there won't be duplicates
        if len(self.local_rib) < 10:
            self.most_specific_prefix_cache[
                (dest_ip_addr, tuple(list(self.local_rib.keys())))
            ] = most_specific_prefix
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
            "local_rib": {
                str(prefix): ann.to_json() for prefix, ann in self.local_rib.items()
            },
            "settings": self.settings,
        }

    @classmethod
    def from_json(cls, json_obj: dict[str, Any], as_: "AS") -> "Policy":
        return cls(
            as_=as_,
            local_rib={
                Prefix(prefix): Ann.from_json(ann)
                for prefix, ann in json_obj["local_rib"].items()
            },
            settings=json_obj["settings"],
        )
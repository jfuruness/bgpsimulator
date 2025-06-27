from typing import TYPE_CHECKING

from bgpsimulator.shared import (
    PolicyPropagateInfo,
    Relationships,
    ROARouted,
    ROAValidity,
)

from .rov import ROV
from .rovpp_v2_lite import ROVPPV2Lite

if TYPE_CHECKING:
    from bgpsimulator.as_graphs import AS
    from bgpsimulator.simulation_engine import Announcement as Ann
    from bgpsimulator.simulation_engine.policy.policy import Policy


class ROVPPV2iLite:
    """A Policy that deploys ROV++V2i Lite, an improved version of ROV++V2 Lite"""

    @staticmethod
    def process_incoming_anns(
        policy: "Policy", from_rel: Relationships, propagation_round: int
    ) -> None:
        """Additional processing for incoming announcements.

        The same as ROV++v2 (adding blackholes).
        """

        return ROVPPV2Lite.process_incoming_anns(policy, from_rel, propagation_round)

    @staticmethod
    def get_policy_propagate_vals(
        policy: "Policy",
        neighbor_as: "AS",
        ann: "Ann",
        propagate_to: Relationships,
        send_rels: set[Relationships],
    ) -> PolicyPropagateInfo:
        if ann.rovpp_blackhole:
            if ROVPPV2iLite.send_competing_hijack_allowed(policy, ann, propagate_to):
                return PolicyPropagateInfo(
                    policy_propagate_bool=True, ann=ann, send_ann_bool=True
                )
            else:
                return PolicyPropagateInfo(
                    policy_propagate_bool=True, ann=ann, send_ann_bool=False
                )
        else:
            return PolicyPropagateInfo(
                policy_propagate_bool=False, ann=ann, send_ann_bool=True
            )

    @staticmethod
    def send_competing_hijack_allowed(
        policy: "Policy", ann: "Ann", propagate_to: Relationships
    ) -> bool:
        """You can send blackhole to customers if from peer/provider.

        And either subprefix or non-routed.
        """

        roa_validity, roa_routed = policy.route_validator.get_roa_outcome(
            ann.prefix, ann.origin
        )
        # If we are the origin, then we can't send a competing hijack
        return (
            # NOTE: This is the part that was removed from ROV++v2 Lite
            # From peer/provider
            # ann.recv_relationship
            # in (Relationships.PEERS, Relationships.PROVIDERS, Relationships.ORIGIN)
            # Sending to customers
            propagate_to == Relationships.CUSTOMERS
            # subprefix or non routed (don't send blackholes for prefixes)
            # To tell if it's a subprefix hijack we check if it's invalid by length
            and (
                roa_validity
                not in (
                    ROAValidity.INVALID_LENGTH,
                    ROAValidity.INVALID_LENGTH_AND_ORIGIN,
                )
                or roa_routed == ROARouted.NON_ROUTED
            )
        )

    @staticmethod
    def valid_ann(policy: "Policy", ann: "Ann", from_rel: Relationships) -> bool:
        """Determines ROV++V2 Lite validity"""

        return ROV.valid_ann(policy, ann, from_rel)

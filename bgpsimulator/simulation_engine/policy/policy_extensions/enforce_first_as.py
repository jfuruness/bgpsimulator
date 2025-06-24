from typing import TYPE_CHECKING

from bgpsimulator.shared.enums import Relationships

if TYPE_CHECKING:
    from bgpsimulator.simulation_engine import Announcement as Ann
    from bgpsimulator.simulation_engine.policy.policy import Policy


class EnforceFirstAS:
    """A Policy that enforces the first AS in the AS-Path to be the origin AS"""

    @staticmethod
    def valid_ann(policy: "Policy", ann: "Ann", from_rel: Relationships) -> bool:
        """Ensures the first ASN in the AS-Path is a neighbor

        NOTE: normally this would check for an exact match, but since we don't
        store which ASN the announcement came from anywhere, we just check if it
        is a neighbor to simulate, since we've always picked attackers at the edge
        """

        return (
            ann.next_hop_asn == ann.as_path[0]
            # Super janky, TODO
            and ann.next_hop_asn in policy.as_.neighbor_asns
        )

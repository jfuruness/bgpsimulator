from typing import TYPE_CHECKING

from bgpsimulator.shared.enums import Relationships

if TYPE_CHECKING:
    from bgpsimulator.simulation_engine import Announcement as Ann
    from bgpsimulator.simulation_engine.policy.policy import Policy


class ASPathEdgeFilter:
    """A Policy that filters announcements based on the edge of the AS-Path"""

    @staticmethod
    def valid_ann(policy: "Policy", ann: "Ann", from_rel: Relationships) -> bool:
        """Returns invalid if an edge AS is announcing a path containing other ASNs"""

        origin_asn = ann.as_path[0]

        if origin_asn in policy.as_.neighbor_asns:
            neighbor_as_obj = policy.as_.as_graph.as_dict[origin_asn]
            if (neighbor_as_obj.stub or neighbor_as_obj.multihomed) and set(
                ann.as_path
            ) != {neighbor_as_obj.asn}:
                return False
        return True

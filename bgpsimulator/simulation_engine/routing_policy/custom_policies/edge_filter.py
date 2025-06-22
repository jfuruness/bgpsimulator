from bgpsimulator.simulation_engine import Announcement as Ann
from bgpsimulator.shared.enums import Relationships
from bgpsimulator.as_graph import AS

class EdgeFilter:
    """A Policy that filters announcements based on the edge of the AS-Path"""

    @staticmethod
    def valid_ann(ann: Ann, from_rel: Relationships, as_obj: "AS") -> bool:
        """Returns invalid if an edge AS is announcing a path containing other ASNs"""

        origin_asn = ann.as_path[0]
       
        if origin_asn in as_obj.neighbor_asns:
            neighbor_as_obj = as_obj.as_graph.as_dict[origin_asn]
            if (neighbor_as_obj.stub or neighbor_as_obj.multihomed) and set(
                ann.as_path
            ) != {neighbor_as_obj.asn}:
                return False
        return True
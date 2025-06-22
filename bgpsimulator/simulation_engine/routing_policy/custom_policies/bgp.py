from bgpsimulator.simulation_engine import Announcement as Ann
from bgpsimulator.shared.enums import Relationships
from bgpsimulator.as_graph import AS

class BGP:
    """A Policy that deploys BGP"""

    @staticmethod
    def valid_ann(ann: Ann, from_rel: Relationships, as_obj: "AS") -> bool:
        """Determine if an announcement is valid or should be dropped"""

        # BGP Loop Prevention Check; no AS 0 either
        return as_obj.asn not in ann.as_path and 0 not in ann.as_path
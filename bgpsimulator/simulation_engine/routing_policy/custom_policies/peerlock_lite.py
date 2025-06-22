from bgpsimulator.simulation_engine import Announcement as Ann
from bgpsimulator.shared.enums import Relationships
from bgpsimulator.as_graph import AS

class PeerLockLite:
    """A Policy that deploys PeerLock Lite"""

    @staticmethod
    def valid_ann(ann: Ann, from_rel: Relationships, as_obj: "AS") -> bool:
        """Returns False if ann is PeerLock Lite invalid"""

        as_dict = as_obj.as_graph.as_dict
        if from_rel == Relationships.CUSTOMERS:
            # Tier-1 ASes have no providers, so if they are your customer,
            # there is a route leakage
            for asn in ann.as_path:
                if as_dict[asn].tier:
                    return False
        return True
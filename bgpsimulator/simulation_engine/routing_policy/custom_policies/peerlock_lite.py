from bgpsimulator.simulation_engine import Announcement as Ann
from bgpsimulator.shared.enums import Relationships
from bgpsimulator.as_graph import AS
from bgpsimulator.simulation_engine.policy.policy import Policy

class PeerLockLite:
    """A Policy that deploys PeerLock Lite"""

    @staticmethod
    def valid_ann(policy: "Policy", ann: Ann, from_rel: Relationships) -> bool:
        """Returns False if ann is PeerLock Lite invalid"""

        as_dict = policy.as_.as_graph.as_dict
        if from_rel == Relationships.CUSTOMERS:
            # Tier-1 ASes have no providers, so if they are your customer,
            # there is a route leakage
            for asn in ann.as_path:
                if as_dict[asn].tier_1:
                    return False
        return True
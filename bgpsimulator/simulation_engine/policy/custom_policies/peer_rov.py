from bgpsimulator.simulation_engine import Announcement as Ann
from bgpsimulator.shared.enums import Relationships, ROAValidity
from bgpsimulator.as_graph import AS
from .rov import ROV
from bgpsimulator.simulation_engine.policy.policy import Policy

class PeerROV:
    """A Policy that deploys Peer ROV (ROV only at peers)"""

    @staticmethod
    def valid_ann(policy: "Policy", ann: Ann, from_rel: Relationships) -> bool:
        """Returns False if ann is ROV invalid and is from a peer"""
        if from_rel == Relationships.PEERS:
            return ROV.valid_ann(policy, ann, from_rel)
        return True
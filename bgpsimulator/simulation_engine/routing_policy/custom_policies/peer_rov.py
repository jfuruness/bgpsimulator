from bgpsimulator.simulation_engine import Announcement as Ann
from bgpsimulator.shared.enums import Relationships, ROAValidity
from bgpsimulator.as_graph import AS
from .rov import ROV

class PeerROV:
    """A Policy that deploys Peer ROV (ROV only at peers)"""

    @staticmethod
    def valid_ann(ann: Ann, from_rel: Relationships, as_obj: "AS") -> bool:
        """Returns False if ann is ROV invalid and is from a peer"""
        if from_rel == Relationships.PEERS:
            return ROV.valid_ann(ann, from_rel, as_obj)
        return True
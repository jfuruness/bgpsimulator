from typing import TYPE_CHECKING

from bgpsimulator.shared import Relationships

from .rov import ROV

if TYPE_CHECKING:
    from bgpsimulator.simulation_engine.policy.policy import Policy
    from bgpsimulator.simulationengine import Announcement as Ann


class PeerROV:
    """A Policy that deploys Peer ROV (ROV only at peers)"""

    @staticmethod
    def valid_ann(policy: "Policy", ann: "Ann", from_rel: Relationships) -> bool:
        """Returns False if ann is ROV invalid and is from a peer"""
        if from_rel == Relationships.PEERS:
            return ROV.valid_ann(policy, ann, from_rel)
        return True

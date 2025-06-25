from typing import TYPE_CHECKING

from bgpsimulator.shared.enums import Relationships, Settings

if TYPE_CHECKING:
    from bgpsimulator.as_graphs import AS
    from bgpsimulator.simulation_engine import Announcement as Ann
    from bgpsimulator.simulation_engine.policy.policy import Policy


class ASPAPP:
    """A Policy that deploys ASPAPP"""

    @staticmethod
    def valid_ann(policy: "Policy", ann: "Ann", from_rel: Relationships) -> bool:
        """Returns False if ann from peer/customer when ASPAPP is set"""

        raise NotImplementedError("ASPAPP is not supported yet")
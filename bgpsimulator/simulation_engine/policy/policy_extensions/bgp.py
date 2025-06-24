from typing import TYPE_CHECKING

from bgpsimulator.shared.enums import Relationships

if TYPE_CHECKING:
    from bgpsimulator.simulation_engine import Announcement as Ann
    from bgpsimulator.simulation_engine.policy.policy import Policy


class BGP:
    """A Policy that deploys BGP"""

    @staticmethod
    def valid_ann(policy: "Policy", ann: "Ann", from_rel: Relationships) -> bool:
        """Determine if an announcement is valid or should be dropped"""

        # BGP Loop Prevention Check; no AS 0 either
        return policy.as_.asn not in ann.as_path and 0 not in ann.as_path

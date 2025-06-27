from typing import TYPE_CHECKING

from bgpsimulator.shared import Relationships, ROAValidity

if TYPE_CHECKING:
    from bgpsimulator.simulation_engine import Announcement as Ann
    from bgpsimulator.simulation_engine.policy.policy import Policy


class ROV:
    """A Policy that deploys ROV"""

    @staticmethod
    def valid_ann(policy: "Policy", ann: "Ann", from_rel: Relationships) -> bool:
        """Returns False if ann is ROV invalid"""
        (roa_validity, roa_routed) = policy.route_validator.get_roa_outcome(
            ann.prefix, ann.origin
        )
        # NOTE: Must work off of isinvalid, since Valid could be False but value could
        # be ROAValidity.UNKNOWN, which should not result in a reject.
        return not ROAValidity.is_invalid(roa_validity)

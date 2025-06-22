from bgpsimulator.simulation_engine import Announcement as Ann
from bgpsimulator.shared.enums import Relationships, ROAValidity
from bgpsimulator.as_graph import AS

class ROV:
    """A Policy that deploys ROV"""

    @staticmethod
    def valid_ann(ann: Ann, from_rel: Relationships, as_obj: "AS") -> bool:
        """Returns False if ann is ROV invalid"""
        (roa_validity, roa_routed) = as_obj.routing_policy.route_validator.validate_roa(ann)
        # NOTE: Must work off of isinvalid, since Valid could be False but value could be ROAValidity.UNKNOWN, which should not result in a reject.
        return not ROAValidity.is_invalid(roa_validity)
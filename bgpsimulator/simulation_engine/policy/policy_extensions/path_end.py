from typing import TYPE_CHECKING

from bgpsimulator.shared.enums import Relationships, Settings

if TYPE_CHECKING:
    from bgpsimulator.simulation_engine import Announcement as Ann
    from bgpsimulator.simulation_engine.policy.policy import Policy

from .rov import ROV


class PathEnd:
    """A Policy that deploys Path-End

    Jump starting BGP with Path-End validation
    """

    @staticmethod
    def valid_ann(policy: "Policy", ann: "Ann", from_rel: Relationships) -> bool:
        """Path-End extends ROV by checking the next-hop of the origin"""

        if not ROV.valid_ann(policy, ann, from_rel):
            return False

        origin_asn = ann.origin
        origin_as_obj = policy.as_.as_graph.as_dict.get(origin_asn)
        # If the origin is deploying pathend and the path is longer than 1
        if (
            origin_as_obj
            and origin_as_obj.policy.settings[Settings.PATH_END]
            and len(ann.as_path) > 1
        ):
            # If the provider is real, do the loop check
            for neighbor_asn in origin_as_obj.neighbor_asns:
                if neighbor_asn == ann.as_path[-2]:
                    return True
            # Provider is fake, return False
            return False
        else:
            return True

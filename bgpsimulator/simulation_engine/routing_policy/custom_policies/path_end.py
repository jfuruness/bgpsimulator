from bgpsimulator.simulation_engine import Announcement as Ann
from bgpsimulator.shared.enums import Relationships, RoutingPolicySettings
from bgpsimulator.as_graph import AS
from .rov import ROV

class PathEnd:
    """A Policy that deploys Path-End
    
    Jump starting BGP with Path-End validation"""

    @staticmethod
    def valid_ann(ann: Ann, from_rel: Relationships, as_obj: "AS") -> bool:
        """Path-End extends ROV by checking the next-hop of the origin"""

        if not ROV.valid_ann(ann, from_rel, as_obj):
            return False

        origin_asn = ann.origin
        origin_as_obj = as_obj.as_graph.as_dict.get(origin_asn)
        # If the origin is deploying pathend and the path is longer than 1
        if (
            origin_as_obj
            and origin_as_obj.routing_policy.overriden_routing_policy_settings.get(RoutingPolicySettings.PATH_END, False)
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
from bgpsimulator.simulation_engine import Announcement as Ann
from bgpsimulator.shared.enums import Relationships
from bgpsimulator.as_graph import AS

class OnlyToCustomers:
    """A Policy that deploys only to customers, RFC 9234"""

    @staticmethod
    def valid_ann(ann: Ann, from_rel: Relationships, as_obj: "AS") -> bool:
        """Returns validity for OTC attributes (RFC 9234)"""

        if (
            ann.only_to_customers
            and from_rel == Relationships.PEERS
            and ann.next_hop_asn != ann.only_to_customers
        ) or (
            ann.only_to_customers
            and from_rel == Relationships.CUSTOMERS
        ):
            return False
        else:
            return True

    @staticmethod
    def get_policy_propagate_vals(neighbor_as_obj: "AS", ann: Ann, propagate_to: Relationships, send_rels: list[Relationships], routing_policy: "RoutingPolicy") -> bool:
        """If propagating to custmoers and only_to_customers isn't set, set it"""

        if propagate_to in (Relationships.CUSTOMERS, Relationships.PROVIDERS):
            ann = ann.copy(only_to_customers=routing_policy.as_obj.asn)
            routing_policy.process_outgoing_ann(neighbor_as_obj, ann, propagate_to, send_rels)
            return PolicyPropagateInfo(
                policy_propagate_bool=True,
                ann=ann,
                send_ann_bool=True
            )
        else:
            return PolicyPropagateInfo(
                policy_propagate_bool=False,
                ann=ann,
                send_ann_bool=False
            )
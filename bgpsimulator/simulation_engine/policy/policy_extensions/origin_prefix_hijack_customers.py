from typing import TYPE_CHECKING

from bgpsimulator.shared import PolicyPropagateInfo, Relationships

if TYPE_CHECKING:
    from bgpsimulator.as_graphs import AS
    from bgpsimulator.simulation_engine import Announcement as Ann
    from bgpsimulator.simulation_engine.policy.policy import Policy


class OriginPrefixHijackCustomers:
    """A Policy that performs prefix origin hijacks against customers

    This is particularly useful against ASPA, which doesn't validate anns
    coming from providers. ASRA and ASPAwN thwards this, as do some other policies
    """

    @staticmethod
    def get_policy_propagate_vals(
        policy: "Policy",
        neighbor_as: "AS",
        ann: "Ann",
        propagate_to: Relationships,
        send_rels: set[Relationships],
    ) -> PolicyPropagateInfo:
        """Performs origin hijacks against customers"""

        # This ann is originating from here, the attacker, so it's an attacker's ann
        # If as path length is 1 (like it would be against BGP), don't modify it
        if (
            propagate_to == Relationships.CUSTOMERS
            and ann.recv_relationship == Relationships.ORIGIN
            and len(ann.as_path) > 1
        ):
            # Only need origin hijack when sending to customers
            return PolicyPropagateInfo(
                policy_propagate_bool=True,
                ann=ann.copy(as_path=(policy.as_.asn, ann.origin)),
                send_ann_bool=True,
            )
        else:
            return PolicyPropagateInfo(
                policy_propagate_bool=False,
                ann=ann,
                send_ann_bool=True,
            )

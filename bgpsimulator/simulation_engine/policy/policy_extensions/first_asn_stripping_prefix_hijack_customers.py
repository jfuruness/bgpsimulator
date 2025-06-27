from typing import TYPE_CHECKING

from bgpsimulator.shared import PolicyPropagateInfo, Relationships

if TYPE_CHECKING:
    from bgpsimulator.as_graphs import AS
    from bgpsimulator.simulation_engine import Announcement as Ann
    from bgpsimulator.simulation_engine.policy.policy import Policy


class FirstASNStrippingPrefixHijackCustomers:
    """A Policy that performs prefix origin hijacks against customers.

    But strips the first ASN.

    ASPA and enforce-first-asn prevent this
    """

    @staticmethod
    def get_policy_propagate_vals(
        policy: "Policy",
        neighbor_as: "AS",
        ann: "Ann",
        propagate_to: Relationships,
        send_rels: set[Relationships],
    ) -> PolicyPropagateInfo:
        """Performs prefix origin hijacks against customers, but strips the first ASN"""

        # This ann is originating from here, the attacker, so it's an attacker's ann
        # If as path length is 1 (like it would be against BGP), don't modify it
        if (
            propagate_to == Relationships.CUSTOMERS
            and ann.recv_relationship == Relationships.ORIGIN
            and len(ann.as_path) > 1
        ):
            # Only need when sending to customers
            return PolicyPropagateInfo(
                policy_propagate_bool=True,
                ann=ann.copy(as_path=(ann.origin,)),
                send_ann_bool=True,
            )
        else:
            return PolicyPropagateInfo(
                policy_propagate_bool=False,
                ann=ann,
                send_ann_bool=True,
            )

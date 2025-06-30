from typing import TYPE_CHECKING, Iterator

from bgpsimulator.shared import PolicyPropagateInfo, Relationships, Settings, Timestamps
from bgpsimulator.simulation_engine import Announcement as Ann

from .rov import ROV

if TYPE_CHECKING:
    from bgpsimulator.as_graphs import AS
    from bgpsimulator.simulation_engine.policy.policy import Policy


class SuppressWithdrawals:
    """A Policy that suppresses withdrawals"""

    @staticmethod
    def get_policy_propagate_vals(
        policy: "Policy",
        neighbor_as: "AS",
        ann: "Ann",
        propagate_to: Relationships,
        send_rels: set[Relationships],
    ) -> PolicyPropagateInfo:
        if ann.withdraw:
            return PolicyPropagateInfo(
                policy_propagate_bool=True, ann=ann, send_ann_bool=False
            )
        else:
            return PolicyPropagateInfo(
                policy_propagate_bool=False, ann=ann, send_ann_bool=True
            )

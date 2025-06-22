from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from bgpsimulator.simulation_engine import Announcement as Ann


@dataclass(frozen=True)
class PolicyPropagateInfo:
    """Information about the policy propagation"""

    policy_propagate_bool: bool
    ann: "Ann"
    # Whether or not the announcement should be sent
    # Ex: In ROV++v1, the announcement is not sent if it's a blackhole,
    # but policy_propagate would still be true since the policy dealt with
    # propagation
    send_ann_bool: bool

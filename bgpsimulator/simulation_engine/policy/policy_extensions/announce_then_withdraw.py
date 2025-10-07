from typing import TYPE_CHECKING

from bgpsimulator.shared import Relationships

if TYPE_CHECKING:
    from bgpsimulator.simulation_engine.policy.policy import Policy
    from bgpsimulator.simulation_framework import Scenario


class AnnounceThenWithdraw:
    """In the second round of propagation, withdraw everything that was announced"""

    @staticmethod
    def pre_propagation_hook(
        policy: "Policy", propagation_round: int, scenario: "Scenario"
    ) -> None:
        """In the second round, withdraw everything you announced"""

        if propagation_round == 1:
            for ann in list(policy.local_rib.values()):
                # Withdraw everything that we announced
                if ann.recv_relationship == Relationships.ORIGIN:
                    withdraw_ann = policy.local_rib.pop(ann.prefix).copy(withdraw=True)
                    policy.withdraw_ann_from_neighbors(withdraw_ann)

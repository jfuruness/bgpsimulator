from typing import TYPE_CHECKING

from bgpsimulator.shared import Relationships

if TYPE_CHECKING:
    from bgpsimulator.simulation_engine.policy.policy import Policy
    from bgpsimulator.simulation_framework import Scenario


class Leaker:
    """Leaks everything second round of propagation

    Generally this is more efficient to do with the ScenarioCls
    of AccidentalRouteLeak but this is helpful for the website
    """

    @staticmethod
    def pre_propagation_hook(
        policy: "Policy", propagation_round: int, scenario: "Scenario"
    ) -> None:
        """Leak everything second round of propagation (which is zero indexed)"""

        if propagation_round == 1:
            for ann in list(policy.local_rib.values()):
                if ann.recv_relationship != Relationships.ORIGIN:
                    new_ann = policy.local_rib.pop(ann.prefix).copy(
                        recv_relationship=Relationships.CUSTOMERS
                    )
                    policy.local_rib[new_ann.prefix] = new_ann

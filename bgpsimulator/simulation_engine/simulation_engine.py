from typing import TYPE_CHECKING, Any

from bgpsimulator.as_graphs import ASGraph
from bgpsimulator.shared import Relationships

if TYPE_CHECKING:
    from bgpsimulator.simulation_engine import Announcement as Ann
    from bgpsimulator.simulation_framework import Scenario


class SimulationEngine:
    """Python simulation engine representation"""

    def __init__(self, as_graph: "ASGraph") -> None:
        self.as_graph = as_graph

    def __eq__(self, other) -> bool:
        """Returns if two simulators contain the same BGPDAG's"""

        if isinstance(other, SimulationEngine):
            return self.as_graph == other.as_graph
        else:
            return NotImplemented

    ###############
    # Setup funcs #
    ###############

    def setup(self, scenario: "Scenario") -> None:
        """Sets AS classes and seeds announcements"""

        self._clear_as_routing_policies()
        self._set_settings(scenario)
        self._seed_announcements(scenario.seed_asn_ann_dict)

    def _clear_as_routing_policies(self) -> None:
        """Clears the routing policies for each AS"""

        for as_obj in self.as_graph:
            as_obj.policy.clear()

    def _set_settings(self, scenario: "Scenario") -> None:
        """Sets the routing policy settings for each AS"""

        for as_obj in self.as_graph:
            scenario.set_settings(as_obj)

    def _seed_announcements(self, seed_asn_ann_dict: dict[int, list["Ann"]]) -> None:
        """Seeds announcement at the proper AS

        Since this is the simulator engine, we should
        never have to worry about overlapping announcements
        """

        for asn, anns in seed_asn_ann_dict.items():
            for ann in anns:
                self.as_graph.as_dict[asn].policy.seed_ann(ann)

    #####################
    # Propagation funcs #
    #####################

    def propagate(self, propagation_round: int, scenario: "Scenario") -> None:
        """Propogates announcements

        to stick with Gao Rexford, we propagate to
        0. providers
        1. peers
        2. customers
        """

        self._pre_propagation_hook(propagation_round, scenario)
        self._propagate_to_providers(propagation_round, scenario)
        self._propagate_to_peers(propagation_round, scenario)
        self._propagate_to_customers(propagation_round, scenario)

    def _pre_propagation_hook(self, propagation_round, scenario) -> None:
        """Pre-propagation hook func in the policy

        Mainly for policies like LEAKER and ANNOUNCE_THEN_WITHDRAW
        """

        for as_obj in self.as_graph.as_dict.values():
            as_obj.policy.pre_propagation_hook(propagation_round, scenario)

    def _propagate_to_providers(
        self, propagation_round: int, scenario: "Scenario"
    ) -> None:
        """Propogate to providers"""

        # Propogation ranks go from stubs to input_clique in ascending order
        # By customer provider pairs (peers are ignored for the ranks)
        for i, rank in enumerate(self.as_graph.propagation_ranks):
            # Nothing to process at the start
            if i > 0:
                # Process first because maybe it recv from lower ranks
                for as_obj in rank:
                    as_obj.policy.process_incoming_anns(
                        from_rel=Relationships.CUSTOMERS,
                        propagation_round=propagation_round,
                        scenario=scenario,
                    )
            # Send to the higher ranks
            for as_obj in rank:
                as_obj.policy.propagate_to_providers()

    def _propagate_to_peers(self, propagation_round: int, scenario: "Scenario") -> None:
        """Propagate to peers"""

        # The reason you must separate this for loop here
        # is because propagation ranks do not take into account peering
        # It'd be impossible to take into account peering
        # since different customers peer to different ranks
        # So first do customer to provider propagation, then peer propagation
        for as_obj in self.as_graph:
            as_obj.policy.propagate_to_peers()
        for as_obj in self.as_graph:
            as_obj.policy.process_incoming_anns(
                from_rel=Relationships.PEERS,
                propagation_round=propagation_round,
                scenario=scenario,
            )

    def _propagate_to_customers(
        self, propagation_round: int, scenario: "Scenario"
    ) -> None:
        """Propagate to customers"""

        # Propogation ranks go from stubs to input_clique in ascending order
        # By customer provider pairs (peers are ignored for the ranks)
        # So here we start at the highest rank(input_clique) and propagate down
        for i, rank in enumerate(reversed(self.as_graph.propagation_ranks)):
            # There are no incomming Anns at the top
            if i > 0:
                for as_obj in rank:
                    as_obj.policy.process_incoming_anns(
                        from_rel=Relationships.PROVIDERS,
                        propagation_round=propagation_round,
                        scenario=scenario,
                    )
            for as_obj in rank:
                as_obj.policy.propagate_to_customers()

    ##############
    # JSON funcs #
    ##############

    def to_json(self) -> dict[str, Any]:
        """Returns a JSON representation of the simulation engine"""

        return {"as_graph": self.as_graph.to_json()}

    @classmethod
    def from_json(cls, json_obj: dict[str, Any]) -> "SimulationEngine":
        """Returns a SimulationEngine from a JSON representation"""

        return cls(as_graph=ASGraph.from_json(json_obj["as_graph"]))

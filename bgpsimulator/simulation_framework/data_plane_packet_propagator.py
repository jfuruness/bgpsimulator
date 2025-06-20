from bgpsimulator.shared import Outcomes
from bgpsimulator.as_graphs import AS
from bgpsimulator.simulation_engine import Announcement as Ann, SimulationEngine
from bgpsimulator.shared import IPAddr

class DataPlanePacketPropagator:
    def get_as_outcomes_for_data_plane_packet(self, dest_ip_addr: IPAddr, simulation_engine: SimulationEngine) -> dict[int, Outcomes]:
        """For each AS, determine the outcome of a packet sent to the destination IP address
        
        See ROV++ paper as to why the control plane is a bad metric;
        so we only focus on the data plane
        """

        outcomes: dict[int, Outcomes] = dict()
        for as_obj in simulation_engine.as_graph:
            self.store_as_data_plane_outcomes(as_obj, simulation_engine.as_graph, dest_ip_addr, outcomes=outcomes, visited_asns=set())
        return outcomes

    def store_as_data_plane_outcomes(self, as_obj: AS, engine: SimulationEngine, dest_ip_addr: IPAddr, outcomes: dict[int, Outcomes], visited_asns: set[int]):
        """Recursively stores the outcomes of the AS on the data plane"""

        if as_obj.asn in outcomes:
            return outcomes[as_obj.asn]
        else:
            most_specific_ann = as_obj.routing_policy.get_most_specific_ann(dest_ip_addr)
            outcome = self._determine_data_plane_outcome(as_obj, engine, dest_ip_addr, most_specific_ann, visited_asns)
            if outcome == Outcomes.UNDETERMINED:
                # next as in the AS path to traceback to
                # Ignore type because only way for this to be here
                # Is if the most specific "Ann" was NOT None.
                next_as = engine.as_graph.as_dict[
                    # NOTE: this is the next hop,
                    # not the next ASN in the AS PATH
                    # This is more in line with real BGP and allows for more
                    # advanced types of hijacks such as origin spoofing hijacks
                    most_specific_ann.next_hop_asn
                ]
                visited_asns.add(as_obj.asn)
                outcome = self.store_as_data_plane_outcomes(next_as, engine, dest_ip_addr, outcomes, visited_asns)
            outcomes[as_obj.asn] = outcome
            return outcome

    def _determine_data_plane_outcome(self, as_obj: AS, engine: SimulationEngine, dest_ip_addr: IPAddr, most_specific_ann: Ann, visited_asns: set[int]) -> Outcomes:
        """Determines the outcome at an AS"""

        if as_obj.asn in self.scenario.attacker_asns:
            return Outcomes.ATTACKER_SUCCESS
        elif as_obj.asn in self.scenario.victim_asns:
            return Outcomes.VICTIM_SUCCESS
        # End of traceback
        elif (
            most_specific_ann is None
            or len(most_specific_ann.as_path) == 1
            or most_specific_ann.recv_relationship.value == Relationships.ORIGIN.value
            or most_specific_ann.next_hop_asn == as_obj.asn
            or not as_obj.routing_policy.passes_sav(dest_ip_addr, most_specific_ann)
        ):
            return Outcomes.DISCONNECTED
        elif (as_obj.asn in visited_asns) or (len(visited_asns) > 64):
            return Outcomes.DATA_PLANE_LOOP
        else:
            return Outcomes.UNDETERMINED
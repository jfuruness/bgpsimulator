from bgpsimulator.route_validator import ROA
from bgpsimulator.shared import IPAddr
from bgpsimulator.shared.enums import CommonPrefixes, Relationships, Timestamps
from bgpsimulator.simulation_engine import Announcement as Ann
from bgpsimulator.simulation_engine import SimulationEngine
from bgpsimulator.simulation_framework.scenarios.scenario import Scenario


class NonRoutedSuperprefixHijack(Scenario):
    """Attacker announces a superprefix that is not covered by a RIA and is not
    routed by the legitimate origin.
    """

    def _get_seed_asn_ann_dict(self, engine: SimulationEngine) -> dict[int, list[Ann]]:
        anns = dict()
        for attacker_asn in self.attacker_asns:
            anns[attacker_asn] = [
                Ann(
                    prefix=CommonPrefixes.SUPERPREFIX.value,
                    as_path=(attacker_asn,),
                    next_hop_asn=attacker_asn,
                    recv_relationship=Relationships.ORIGIN,
                    timestamp=Timestamps.ATTACKER,
                )
            ]

        return anns

    def _get_roas(
        self,
        *,
        seed_asn_ann_dict: dict[int, list[Ann]],
        engine: SimulationEngine,
    ) -> list[ROA]:
        """Returns a list of ROAs"""

        # Use 0 as the ASN for the ROA, since it's not routed by the legitimate origin
        return [ROA(CommonPrefixes.PREFIX.value, 0)]

    def _get_dest_ip_addr(self) -> IPAddr:
        """Returns the destination IP address for the scenario"""

        return IPAddr("1.2.3.4")

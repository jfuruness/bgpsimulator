from bgpsimulator.route_validator import ROA
from bgpsimulator.shared import IPAddr
from bgpsimulator.shared.enums import CommonPrefixes, Relationships, Timestamps
from bgpsimulator.simulation_engine import Announcement as Ann
from bgpsimulator.simulation_engine import SimulationEngine
from bgpsimulator.simulation_framework.scenarios.scenario import Scenario


class PrefixHijack(Scenario):
    """Victim announces a prefix covered by a ROA, attacker announces the same
    prefix (invalid by ROA).
    """

    def _get_seed_asn_ann_dict(self, engine: SimulationEngine) -> dict[int, list[Ann]]:
        anns = dict()
        for legitimate_origin_asn in self.legitimate_origin_asns:
            anns[legitimate_origin_asn] = [
                Ann(
                    prefix=CommonPrefixes.PREFIX.value,
                    as_path=(legitimate_origin_asn,),
                    next_hop_asn=legitimate_origin_asn,
                    recv_relationship=Relationships.ORIGIN,
                    timestamp=Timestamps.LEGITIMATE_ORIGIN,
                )
            ]

        for attacker_asn in self.attacker_asns:
            anns[attacker_asn] = [
                Ann(
                    prefix=CommonPrefixes.PREFIX.value,
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

        return [
            ROA(CommonPrefixes.PREFIX.value, x) for x in self.legitimate_origin_asns
        ]

    def _get_dest_ip_addr(self) -> IPAddr:
        """Returns the destination IP address for the scenario"""

        return IPAddr("1.2.3.4")

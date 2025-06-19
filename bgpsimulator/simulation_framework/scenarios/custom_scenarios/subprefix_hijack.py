from ipaddress import ip_network
from typing import TYPE_CHECKING, Optional

from bgpsimulator.route_validator import ROA
from bgpsimulator.simulation_engine import Announcement as Ann
from bgpsimulator.simulation_engine import SimulationEngine
from bgpsimulator.shared.enums import CommonPrefixes, Relationships, Timestamps
from bgpsimulator.simulation_framework.scenarios.scenario import Scenario
from bgpsimulator.shared import IPAddr


class SubprefixHijack(Scenario):
    """Victim announces a prefix, attacker announces a more specific subprefix"""

    def _get_announcements(self, engine: SimulationEngine) -> dict[int, list[Ann]]:

        anns = dict()
        for victim_asn in self.victim_asns:
            anns[victim_asn] = [
                Ann(
                    prefix=CommonPrefixes.PREFIX.value,
                    as_path=(victim_asn,),
                    next_hop_asn=victim_asn,
                    recv_relationship=Relationships.ORIGIN,
                    timestamp=Timestamps.VICTIM.value,
                )
            ]

        for attacker_asn in self.attacker_asns:
            anns[attacker_asn] = [
                Ann(
                    prefix=CommonPrefixes.SUBPREFIX.value,
                    as_path=(attacker_asn,),
                    next_hop_asn=attacker_asn,
                    recv_relationship=Relationships.ATTACKER,
                    timestamp=Timestamps.ATTACKER.value,
                )
            ]

        return anns

    def _get_roas(
        self,
        *,
        announcements: dict[int, list[Ann]],
        engine: SimulationEngine,
    ) -> list[ROA]:
        """Returns a tuple of ROAs"""

        return [ROA(CommonPrefixes.PREFIX.value, x) for x in self.victim_asns]

    def _get_dest_ip_addr(self) -> IPAddr:
        """Returns the destination IP address for the scenario"""

        return IPAddr("1.2.3.4")
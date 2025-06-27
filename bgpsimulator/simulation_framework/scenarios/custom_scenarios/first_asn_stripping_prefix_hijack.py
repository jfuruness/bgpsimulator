from bgpsimulator.route_validator import ROA
from bgpsimulator.shared import IPAddr
from bgpsimulator.shared.enums import CommonPrefixes, Relationships, Timestamps
from bgpsimulator.simulation_engine import Announcement as Ann
from bgpsimulator.simulation_engine import SimulationEngine

from .shortest_path_prefix_hijack import (
    ShortestPathPrefixHijack,
)


class FirstASNStrippingPrefixHijack(ShortestPathPrefixHijack):
    """Attacker announces a prefix with the first ASN stripped"""

    def _get_seed_asn_ann_dict(self, engine: SimulationEngine) -> dict[int, list[Ann]]:
        seed_asn_ann_dict = dict()
        for legitimate_origin_asn in self.legitimate_origin_asns:
            seed_asn_ann_dict[legitimate_origin_asn] = [
                Ann(
                    prefix=CommonPrefixes.PREFIX.value,
                    as_path=(legitimate_origin_asn,),
                    next_hop_asn=legitimate_origin_asn,
                    recv_relationship=Relationships.ORIGIN,
                    timestamp=Timestamps.LEGITIMATE_ORIGIN,
                )
            ]
        seed_asn_ann_dict = {
            **seed_asn_ann_dict,
            **self._get_first_asn_stripped_attacker_seed_asn_ann_dict(engine),
        }
        return seed_asn_ann_dict

    def _get_first_asn_stripped_attacker_seed_asn_ann_dict(
        self, engine: SimulationEngine
    ) -> dict[int, list[Ann]]:
        attacker_seed_asn_ann_dict = self._get_attacker_seed_asn_ann_dict(engine)
        stripped_attacker_seed_asn_ann_dict: dict[int, list[Ann]] = {
            attacker_asn: [] for attacker_asn in self.attacker_asns
        }
        for attacker_asn, anns in attacker_seed_asn_ann_dict.items():
            for ann in anns:
                # Remove the attacker's ASN
                if len(ann.as_path) > 1:
                    stripped_ann = ann.copy(as_path=ann.as_path[1:])
                # Can't remove when path is less than or equal to 1
                else:
                    stripped_ann = ann
                stripped_attacker_seed_asn_ann_dict[attacker_asn].append(stripped_ann)
        return stripped_attacker_seed_asn_ann_dict

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

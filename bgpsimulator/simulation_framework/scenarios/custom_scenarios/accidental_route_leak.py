from ipaddress import ip_network
from typing import TYPE_CHECKING, Optional

from bgpsimulator.route_validator import ROA
from bgpsimulator.simulation_engine import Announcement as Ann
from bgpsimulator.simulation_engine import SimulationEngine
from bgpsimulator.shared.enums import CommonPrefixes, Relationships, Timestamps, Settings
from bgpsimulator.simulation_framework.scenarios.scenario import Scenario
from bgpsimulator.shared import IPAddr, ASNGroups
from bgpsimulator.shared import bgpsimulator_logger


class AccidentalRouteLeak(Scenario):
    """Attacker leaks anns received from peers/providers"""

    min_propagation_rounds: int = 2

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._attacker_customer_cone_asns: set[int] = set()
        self._validate_attacker_asn_group()

    def _validate_attacker_asn_group(self):
        """Validates that the attacker is in an ASN group that can leak"""

        if self.scenario_config.attacker_asn_group in self.warning_asn_groups and not self.scenario_config.override_attacker_asns:
            msg = (
                "You used the ASNGroup of "
                f"{self.scenario_config.attacker_asn_group} "
                f"for your scenario {self.__class__.__name__}, "
                f"but {self.__class__.__name__} can't leak from stubs. "
                "To suppress this warning, override warning_as_groups. "
                "To change the ASNGroup to something other than stubs, you can "
                " set attacker_asn_group=ASNGroups.MULTIHOMED.value, "
                " in the scenario config after importing like "
                "from bgpsimulator.shared import ASNGroups"
            )
            warning.warn(msg, RuntimeWarning, stacklevel=2)

    @property
    def warning_asn_groups(self) -> frozenset[str]:
        """Returns a frozenset of ASNGroups that should raise a warning"""

        return frozenset(
            [
                ASNGroups.STUBS_OR_MH.value,
                ASNGroups.STUBS.value,
                ASNGroups.ALL_WOUT_IXPS.value,
            ]
        )
    def post_propagation_hook(
        self,
        engine: "SimulationEngine",
        percent_ases_randomly_adopting: float,
        trial: int,
        propagation_round: int,
    ) -> None:
        """Causes an accidental route leak

        Changes the valid prefix to be received from a customer
        so that in the second propagation round, the AS will export to all
        relationships

        NOTE: the old way of doing this was to simply alter the attackers
        local RIB and then propagate again. However - this has some drawbacks
        Then the attacker must deploy BGPFull (that uses withdrawals) and
        the entire graph has to propagate again. BGPFull (and subclasses
        of it) are MUCH slower than BGP due to all the extra
        computations for withdrawals, RIBsIn, RIBsOut, etc. Additionally,
        propagating a second round after the ASGraph is __already__ full
        is wayyy more expensive than propagating when the AS graph is empty.

        Instead, we now get the announcement that the attacker needs to leak
        after the first round of propagating the valid prefix.
        Then we clear the graph, seed those announcements, and propagate again
        This way, we avoid needing BGPFull (since the graph has been cleared,
        there is no need for withdrawals), and we avoid propagating a second
        time after the graph is alrady full.

        Since this simulator treats each propagation round as if it all happens
        at once, this is possible.

        Additionally, you could also do the optimization in the first propagation
        round to only propagate from ASes that can reach the attacker. But we'll
        forgo this for now for simplicity.
        """

        if propagation_round == 0:
            seed_asn_ann_dict: dict[int, list[Ann]] = self.seed_asn_ann_dict.copy()
            for attacker_asn in self.attacker_asns:
                if not engine.as_graph.as_dict[attacker_asn].policy.local_rib:
                    bgpsimulator_logger.warning(
                        "Attacker did not recieve announcement, can't leak."
                    )
                for _prefix, ann in engine.as_graph.as_dict[
                    attacker_asn
                ].policy.local_rib.items():
                    seed_asn_ann_dict[attacker_asn].append(
                        ann.copy(
                            recv_relationship=Relationships.ORIGIN,
                            timestamp=Timestamps.ATTACKER.value,
                        )
                    )
            self.seed_asn_ann_dict = seed_asn_ann_dict
            self.setup_engine(engine)
        elif propagation_round > 1:
            raise NotImplementedError

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

    @property
    def untracked_asns(self) -> set[int]:
        """Returns ASNs that shouldn't be tracked by the data tracker

        By default just the default adopters and non adopters
        however for the route leak, we don't want to track the customers of the
        leaker, since you can not "leak" to your own customers
        """

        return super().untracked_asns | self._attackers_customer_cones_asns

    def _get_attacker_asns(self, *args, **kwargs):
        raise NotImplementedError
    def _get_legitimate_origin_asns(self, *args, **kwargs):
        raise NotImplementedError
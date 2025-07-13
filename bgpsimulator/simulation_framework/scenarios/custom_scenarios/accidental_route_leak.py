import warnings
from collections import deque

from bgpsimulator.route_validator import ROA
from bgpsimulator.shared import ASNGroups, IPAddr, bgpsimulator_logger
from bgpsimulator.shared.enums import (
    CommonPrefixes,
    Relationships,
    Timestamps,
)
from bgpsimulator.simulation_engine import Announcement as Ann
from bgpsimulator.simulation_engine import SimulationEngine
from bgpsimulator.simulation_framework.scenarios.scenario import Scenario


class AccidentalRouteLeak(Scenario):
    """Attacker leaks anns received from peers/providers"""

    min_propagation_rounds: int = 2

    def __init__(self, *args, **kwargs):
        self._attackers_customer_cone_asns: set[int] = set()
        super().__init__(*args, **kwargs)
        self._validate_attacker_asn_group()

    def _validate_attacker_asn_group(self):
        """Validates that the attacker is in an ASN group that can leak"""

        if (
            self.scenario_config.attacker_asn_group in self.warning_asn_groups
            and not self.scenario_config.override_attacker_asns
        ):
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
            warnings.warn(msg, RuntimeWarning, stacklevel=2)

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
        computations for withdrawals, AdjRIBsIn, AdjRIBsOut, etc. Additionally,
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
                    seed_asn_ann_dict.setdefault(attacker_asn, []).append(
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

        return super().untracked_asns | self._attackers_customer_cone_asns

    def _get_attacker_asns(
        self,
        override_attacker_asns: set[int] | None,
        prev_attacker_asns: set[int] | None,
        engine: SimulationEngine,
    ) -> set[int]:
        """Gets attacker ASNs, overriding the valid prefix which has no attackers

        There is a very rare case where the attacker can not perform the route leak
        due to a disconnection, which happens around .1% in the CAIDA topology.
        In theory - you could just look at the provider cone of the victim,
        and then the peers of that provider cone (and of the victim itself), and
        then the customer cones of all of those ASes to get the list of possible
        valid attackers. However, we consider the attacker being unable to attack
        in extremely rare cases a valid result, and thus do not change the random
        selection. Doing so would also be a lot slower for a very extreme edge case
        """

        attacker_asns = super()._get_attacker_asns(
            override_attacker_asns, prev_attacker_asns, engine
        )
        # Add customer cones so that we can avoid them when tracking data
        for attacker_asn in attacker_asns:
            self._attackers_customer_cone_asns.update(
                self._get_customer_cone_asns(attacker_asn, engine)
            )
        return attacker_asns

    def _get_customer_cone_asns(self, asn: int, engine: SimulationEngine) -> set[int]:
        """Returns the customer cone of an AS"""

        customer_cone_asns: set[int] = set()
        fifo_queue: deque[int] = deque([asn])
        while fifo_queue:
            asn = fifo_queue.popleft()
            customer_cone_asns.update(engine.as_graph.as_dict[asn].customer_asns)
            fifo_queue.extend(engine.as_graph.as_dict[asn].customer_asns)
        return customer_cone_asns

    def _get_possible_legitimate_origin_asns(
        self,
        engine: SimulationEngine,
        percent_ases_randomly_adopting: float,
    ) -> set[int]:
        """Returns possible legitimate_origin ASNs, defaulted from config

        Removes attacker's customer cones from possible victims (or else
        there would be no leakage)
        """

        possible_asns = super()._get_possible_legitimate_origin_asns(
            engine, percent_ases_randomly_adopting
        )
        # Remove attacker's customer conesfrom possible victims
        possible_asns = possible_asns.difference(self._attackers_customer_cone_asns)
        return possible_asns

import math
import random
from functools import cached_property
from typing import TYPE_CHECKING, ClassVar

from bgpsimulator.route_validator import ROA, RouteValidator
from bgpsimulator.shared import IPAddr, Settings
from bgpsimulator.simulation_engine import Announcement as Ann
from bgpsimulator.simulation_engine import SimulationEngine

if TYPE_CHECKING:
    from bgpsimulator.as_graphs import AS

    from .scenario_config import ScenarioConfig


class Scenario:
    """Contains information regarding a scenario/attack

    This represents a single trial and a single engine run
    """

    min_propagation_rounds: int = 1

    # Used when dumping the scenario_config to JSON
    name_to_cls_dict: ClassVar[dict[str, type["Scenario"]]] = {}

    def __init_subclass__(cls, **kwargs):
        """Used when dumping the scenario_config to JSON

        NOTE: When converting to rust, just keep a hardcoded list of scenarios
        """
        super().__init_subclass__(**kwargs)
        Scenario.name_to_cls_dict[cls.__name__] = cls

    def __init__(
        self,
        *,
        scenario_config: "ScenarioConfig",
        engine: SimulationEngine,
        route_validator: RouteValidator,
        percent_ases_randomly_adopting: float = 0,
        attacker_asns: set[int] | None = None,
        legitimate_origin_asns: set[int] | None = None,
        adopting_asns: set[int] | None = None,
    ):
        """inits attrs

        Any kwarg prefixed with default is only required for the test suite/YAML
        """

        # Config's ScenarioCls must be the same as instantiated Scenario
        assert scenario_config.ScenarioCls == self.__class__, (
            "The config's scenario class is "
            f"{scenario_config.ScenarioCls.__name__}, but the scenario used is "
            f"{self.__class__.__name__}"
        )

        self.scenario_config: ScenarioConfig = scenario_config
        self.percent_ases_randomly_adopting: float = percent_ases_randomly_adopting

        self.attacker_asns: set[int] = self._get_attacker_asns(
            scenario_config.override_attacker_asns,
            attacker_asns,
            engine,
        )

        self.legitimate_origin_asns: set[int] = self._get_legitimate_origin_asns(
            scenario_config.override_legitimate_origin_asns,
            legitimate_origin_asns,
            engine,
        )
        self.adopting_asns: set[int] = self._get_adopting_asns(
            scenario_config.override_adopting_asns,
            adopting_asns,
            engine,
        )

        if self.scenario_config.override_seed_asn_ann_dict is not None:
            self.seed_asn_ann_dict: dict[int, list[Ann]] = (
                self.scenario_config.override_seed_asn_ann_dict.copy()
            )
        else:
            self.seed_asn_ann_dict = self._get_seed_asn_ann_dict(engine=engine)

        if self.scenario_config.override_roas is not None:
            self.roas: list[ROA] = self.scenario_config.override_roas.copy()
        else:
            self.roas = self._get_roas(
                seed_asn_ann_dict=self.seed_asn_ann_dict, engine=engine
            )
        self._reset_and_add_roas_to_route_validator(route_validator)

        if self.scenario_config.override_dest_ip_addr is not None:
            self.dest_ip_addr: IPAddr = self.scenario_config.override_dest_ip_addr
        else:
            self.dest_ip_addr = self._get_dest_ip_addr()

    def _reset_and_add_roas_to_route_validator(self, route_validator) -> None:
        """Clears & adds ROAs to route_validator.

        Which serves as RPKI+Routinator combo.
        """

        route_validator.clear()
        for roa in self.roas:
            route_validator.add_roa(roa)

    #################
    # Get attackers #
    #################

    def _get_attacker_asns(
        self,
        override_attacker_asns: set[int] | None,
        prev_attacker_asns: set[int] | None,
        engine: SimulationEngine,
    ) -> set[int]:
        """Returns attacker ASN at random"""

        # This is hardcoded, do not recalculate
        if override_attacker_asns is not None:
            attacker_asns = override_attacker_asns.copy()
            branch = 0
        # Reuse the attacker from the last scenario for comparability
        elif (
            prev_attacker_asns
            and len(prev_attacker_asns) == self.scenario_config.num_attackers
        ):
            attacker_asns = prev_attacker_asns
            branch = 1
        # This is being initialized for the first time, or old scenario has a
        # different number of attackers
        else:
            branch = 3
            assert engine
            possible_attacker_asns = self._get_possible_attacker_asns(
                engine, self.percent_ases_randomly_adopting
            )

            assert len(possible_attacker_asns) >= self.scenario_config.num_attackers
            # https://stackoverflow.com/a/15837796/8903959
            attacker_asns = set(
                random.sample(
                    tuple(possible_attacker_asns), self.scenario_config.num_attackers
                )
            )

        # Validate attacker asns
        err = f"Number of attackers is different from attacker length: Branch {branch}"
        assert len(attacker_asns) == self.scenario_config.num_attackers, err

        return attacker_asns

    def _get_possible_attacker_asns(
        self,
        engine: SimulationEngine,
        percent_ases_randomly_adopting: float,
    ) -> set[int]:
        """Returns possible attacker ASNs, defaulted from config"""

        possible_asns = engine.as_graph.asn_groups[
            self.scenario_config.attacker_asn_group
        ]
        return possible_asns

    ###############
    # Get Victims #
    ###############

    def _get_legitimate_origin_asns(
        self,
        override_legitimate_origin_asns: set[int] | None,
        prev_legitimate_origin_asns: set[int] | None,
        engine: SimulationEngine,
    ) -> set[int]:
        """Returns legitimate_origin ASN at random"""

        # This is coming from YAML, do not recalculate
        if override_legitimate_origin_asns is not None:
            legitimate_origin_asns = override_legitimate_origin_asns.copy()
        # Reuse the legitimate_origin from the last scenario for comparability
        elif (
            prev_legitimate_origin_asns
            and len(prev_legitimate_origin_asns)
            == self.scenario_config.num_legitimate_origins
        ):
            legitimate_origin_asns = prev_legitimate_origin_asns
        # This is being initialized for the first time
        else:
            assert engine
            possible_legitimate_origin_asns = self._get_possible_legitimate_origin_asns(
                engine, self.percent_ases_randomly_adopting
            )
            # https://stackoverflow.com/a/15837796/8903959
            legitimate_origin_asns = set(
                random.sample(
                    tuple(possible_legitimate_origin_asns),
                    self.scenario_config.num_legitimate_origins,
                )
            )

        err = (
            "Number of legitimate_origins is different from "
            f"legitimate_origin length {len(legitimate_origin_asns)} "
            f"{self.scenario_config.num_legitimate_origins}"
        )
        assert (
            len(legitimate_origin_asns) == self.scenario_config.num_legitimate_origins
        ), err

        return legitimate_origin_asns

    def _get_possible_legitimate_origin_asns(
        self,
        engine: SimulationEngine,
        percent_ases_randomly_adopting: float,
    ) -> set[int]:
        """Returns possible legitimate_origin ASNs, defaulted from config"""

        possible_asns = engine.as_graph.asn_groups[
            self.scenario_config.legitimate_origin_asn_group
        ]
        # Remove attackers from possible legitimate_origins
        possible_asns = possible_asns.difference(self.attacker_asns)
        return possible_asns

    #######################
    # Adopting ASNs funcs #
    #######################

    def _get_adopting_asns(
        self,
        override_adopting_asns: set[int] | None,
        adopting_asns: set[int] | None,
        engine: SimulationEngine,
    ) -> set[int]:
        """Returns all asns that will be adopting self.AdoptPolicyCls"""

        if override_adopting_asns is not None:
            return override_adopting_asns.copy()
        # By default use the same adopting ASes as the last scenario config
        elif adopting_asns:
            return adopting_asns
        else:
            adopting_asns = self._get_randomized_adopting_asns(engine)

        return adopting_asns

    def _get_randomized_adopting_asns(
        self,
        engine: SimulationEngine,
    ) -> set[int]:
        """Returns the set of adopting ASNs (aside from hardcoded ASNs)"""

        adopting_asns: list[int] = list()
        # Randomly adopt in all three subcategories
        for subcategory in self.scenario_config.adoption_asn_groups:
            asns = engine.as_graph.asn_groups[subcategory]
            # Remove ASes that are already pre-set
            # Ex: Attackers and legitimate_origins,
            # self.scenario_config.hardcoded_asn_cls_dict
            possible_adopters = asns.difference(self.preset_asns)

            # Get how many ASes should be adopting (store as k)
            if self.percent_ases_randomly_adopting == 0:
                k = 0
            else:
                k = math.ceil(
                    len(possible_adopters) * self.percent_ases_randomly_adopting / 100
                )

            try:
                # https://stackoverflow.com/a/15837796/8903959
                adopting_asns.extend(random.sample(tuple(possible_adopters), k))
            except ValueError as e:
                raise ValueError(
                    f"{k} can't be sampled from {len(possible_adopters)}"
                ) from e
        return set(adopting_asns)

    @cached_property
    def default_adopters(self) -> set[int]:
        """By default, legitimate_origin always adopts"""

        return self.legitimate_origin_asns

    @cached_property
    def default_non_adopters(self) -> set[int]:
        """By default, attacker always does not adopt"""

        return self.attacker_asns

    @cached_property
    def preset_asns(self) -> set[int]:
        """ASNs that have a preset adoption policy"""

        # Returns the union of default adopters and non adopters
        hardcoded_asns = set(self.scenario_config.override_adoption_settings)
        return self.default_adopters | self.default_non_adopters | hardcoded_asns

    @property
    def untracked_asns(self) -> set[int]:
        """Returns ASNs that shouldn't be tracked by the graphing tools

        By default just the default adopters and non adopters, and hardcoded ASNs
        """

        return self.default_adopters | self.default_non_adopters

    #############################
    # Engine Manipulation Funcs #
    #############################

    def set_settings(self, as_obj: "AS") -> None:
        """Sets the routing policy settings for a given AS"""

        # NOTE: Most important updates go last

        settings = [False for _ in Settings]

        for setting, val in self.scenario_config.default_base_settings.items():
            settings[setting] = val

        for setting, val in self.scenario_config.override_base_settings.get(
            as_obj.asn, {}
        ).items():
            settings[setting] = val

        asn = as_obj.asn
        if asn in self.scenario_config.override_adoption_settings:
            for setting, val in self.scenario_config.override_adoption_settings[
                asn
            ].items():
                settings[setting] = val
        elif asn in self.adopting_asns or asn in self.default_adopters:
            for setting, val in self.scenario_config.default_adoption_settings.items():
                settings[setting] = val

        if asn in self.attacker_asns:
            for setting, val in self.scenario_config.attacker_settings.items():
                settings[setting] = val
        elif asn in self.legitimate_origin_asns:
            for setting, val in self.scenario_config.legitimate_origin_settings.items():
                settings[setting] = val

        as_obj.policy.settings = tuple(settings)

    def setup_engine(self, engine: SimulationEngine) -> None:
        """Nice hook func for setting up the engine.

        With adopting ASes, routing policy settings, etc.
        """
        engine.setup(self)

    ##################
    # Subclass Funcs #
    ##################

    def _get_seed_asn_ann_dict(self, engine: SimulationEngine) -> dict[int, list[Ann]]:
        """Returns a dict of ASNs to announcements

        Empty by default for testing, typically subclassed
        """

        return {}

    def _get_roas(
        self,
        *,
        seed_asn_ann_dict: dict[int, list[Ann]],
        engine: SimulationEngine,
    ) -> list[ROA]:
        """Returns a list of ROA's

        Not abstract and by default does nothing for
        backwards compatability
        """
        return []

    def _get_dest_ip_addr(self) -> IPAddr:
        """Returns the destination IP address for the scenario

        Subclass must implement this
        """

        raise NotImplementedError("Subclass must implement this")

    def pre_aggregation_hook(
        self,
        engine: SimulationEngine,
        percent_ases_randomly_adopting: float,
        trial: int,
        propagation_round: int,
    ) -> None:
        """Useful hook for changes/checks
        prior to results aggregation.
        """
        pass

    def post_propagation_hook(
        self,
        engine: SimulationEngine,
        percent_ases_randomly_adopting: float,
        trial: int,
        propagation_round: int,
    ) -> None:
        """Useful hook for post propagation"""

        pass

    # NOTE: No JSON funcs since you can't store the engine


Scenario.name_to_cls_dict["Scenario"] = Scenario

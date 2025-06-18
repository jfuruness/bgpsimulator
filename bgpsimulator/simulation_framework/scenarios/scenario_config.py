from dataclasses import asdict, dataclass, field
from typing import TYPE_CHECKING, Any
from warnings import warn
import importlib

from frozendict import frozendict
from roa_checker import ROA

from bgpsimulator.shared import ASNGroups, RoutingPolicySettings
from bgpsimulator.simulation_engine import RoutingPolicy, Announcement as Ann

if TYPE_CHECKING:
    from .scenario import Scenario


class ScenarioConfig:
    """Config reused across trials to set up a scenario/attack"""

    def __init__(
        self,
        scenario_label: str,
        scenario_cls: type["Scenario"],
        propagation_rounds: int | None = None,
        attacker_routing_policy_settings: dict[RoutingPolicySettings, bool] | None = None,
        victim_routing_policy_settings: dict[RoutingPolicySettings, bool] | None = None,
        override_adopt_routing_policy_settings: dict[int, dict[RoutingPolicySettings, bool]] | None = None,
        override_base_routing_policy_settings: dict[int, dict[RoutingPolicySettings, bool]] | None = None,
        default_adopt_routing_policy_settings: dict[RoutingPolicySettings, bool] | None = None,
        default_base_routing_policy_settings: dict[RoutingPolicySettings, bool] | None = None,
        num_attackers: int = 1,
        num_victims: int = 1,
        attacker_asn_group: str = ASNGroups.STUBS_OR_MH.value,
        victim_asn_group: str = ASNGroups.STUBS_OR_MH.value,
        adoption_asn_groups: list[str] | None = None,
        override_attacker_asns: set[int] | None = None,
        override_victim_asns: set[int] | None = None,
        override_adopting_asns: set[int] | None = None,
        override_announcements: set[Ann] | None = None,
        override_roas: set[ROA] | None = None,
    ):
        # Label used for graphing, typically name it after the adopting policy
        self.scenario_label: str = scenario_label
        self.ScenarioCls: type["Scenario"] = scenario_cls
        self.propagation_rounds: int | None = propagation_rounds
        if self.propagation_rounds is None:
            # BGP-iSec needs this.
            for routing_policy_setting in [RoutingPolicySettings.BGP_I_SEC, RoutingPolicySettings.BGP_I_SEC_TRANSITIVE]:
                if (any(x[routing_policy_setting] for x in [attacker_routing_policy_settings, victim_routing_policy_settings, override_adopt_routing_policy_settings, override_base_routing_policy_settings, default_adopt_routing_policy_settings, default_base_routing_policy_settings])):
                    from bgpsimulator.simulation_framework.scenarios.shortest_path_prefix_hijack import ShortestPathPrefixHijack

                    if issubclass(self.ScenarioCls, ShortestPathPrefixHijack):
                        # ShortestPathPrefixHijack needs 2 propagation rounds
                        self.propagation_rounds = 2
                    else:
                        self.propagation_rounds = self.ScenarioCls.min_propagation_rounds
            if self.propagation_rounds is None:
                self.propagation_rounds = self.ScenarioCls.min_propagation_rounds

        ###########################
        # Routing Policy Settings #
        ###########################

        # When determining if an AS is using a setting, the following order is used:
        # 1. attacker_routing_policy_settings or victim_routing_policy_settings (if AS is an attacker or victim)
        # 2. override_adopt_routing_policy_settings (if set)
        # 3. override_base_routing_policy_settings
        # 4. default_adopt_routing_policy_settings
        # 5. default_base_routing_policy_settings

        # 1a. This will update the base routing policy settings for the attacker ASes
        self.attacker_routing_policy_settings: dict[RoutingPolicySettings, bool] = attacker_routing_policy_settings or dict()
        # 1v. This will update the base routing policy settings for the victim ASes
        self.victim_routing_policy_settings: dict[RoutingPolicySettings, bool] = victim_routing_policy_settings or dict()
        # 2. This will completely override the default adopt routing policy settings
        self.override_adopt_routing_policy_settings: dict[int, dict[str, bool]] = override_adopt_routing_policy_settings or dict()
        # 3. This will completely override the default base routing policy settings
        self.override_base_routing_policy_settings: dict[int, dict[str, bool]] = override_base_routing_policy_settings or dict()
        # 4. This will update the base routing policy settings for the adopting ASes
        self.default_adopt_routing_policy_settings: dict[str, bool] = default_adopt_routing_policy_settings or dict()
        # 5. Base routing policy settings that will be applied to all ASes
        self.default_base_routing_policy_settings: dict[str, bool] = default_base_routing_policy_settings or {
            x: False for x in RoutingPolicySettings
        }

        # Number of attackers/victims/adopting ASes
        self.num_attackers: int = num_attackers
        self.num_victims: int = num_victims

        # Attackers are randomly selected from this ASN group
        self.attacker_asn_group: str = attacker_asn_group
        # Victims are randomly selected from this ASN group
        self.victim_asn_group: str = victim_asn_group
        # Adoption is equal across these ASN groups
        self.adoption_asn_groups: list[str] = adoption_asn_groups or [ASNGroups.STUBS_OR_MH.value, ASNGroups.ETC.value, ASNGroups.TIER_1.value]

        # Forces the attackers/victims/adopting ASes to be a specific set of ASes rather than random
        self.override_attacker_asns: set[int] | None = override_attacker_asns
        self.override_victim_asns: set[int] | None = override_victim_asns
        self.override_adopting_asns: set[int] | None = override_adopting_asns
        # Forces the announcements/roas to be a specific set of announcements/roas
        # rather than generated dynamically based on attackers/victims
        self.override_announcements: set[Ann] | None = override_announcements
        self.override_roas: set[ROA] | None = override_roas

        if self.ScenarioCls.min_propagation_rounds > self.propagation_rounds:
            raise ValueError(
                f"{self.ScenarioCls.__name__} requires a minimum of "
                f"{self.ScenarioCls.min_propagation_rounds} propagation rounds "
                f"but this scenario_config has only {self.propagation_rounds} "
                "propagation rounds"
            )

    ##############
    # JSON Funcs #
    ##############

    def to_json(self) -> dict[str, Any]:
        """Converts the scenario config to a JSON object"""
        vals = vars(self)
        vals["ScenarioCls"] = vals["ScenarioCls"].__name__
        return vals

    @classmethod
    def from_json(cls, json_obj: dict[str, Any]) -> "ScenarioConfig":
        """Converts a JSON object to a scenario config"""
        vals = json_obj.copy()
        vals["ScenarioCls"] = Scenario.name_to_cls_dict[vals["ScenarioCls"]]
        return cls(**vals)
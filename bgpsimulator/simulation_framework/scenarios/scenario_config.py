from dataclasses import asdict, dataclass, field
from typing import TYPE_CHECKING, Any
from warnings import warn
import importlib

from frozendict import frozendict

from bgpsimulator.route_validator import ROA
from bgpsimulator.shared import ASNGroups, Settings
from bgpsimulator.simulation_engine import Policy, Announcement as Ann
from bgpsimulator.shared import IPAddr

if TYPE_CHECKING:
    from .scenario import Scenario


class ScenarioConfig:
    """Config reused across trials to set up a scenario/attack"""

    def __init__(
        self,
        label: str,
        ScenarioCls: type["Scenario"],
        policy_cls: type[Policy] = Policy,
        propagation_rounds: int | None = None,
        attacker_settings: dict[Settings, bool] | None = None,
        legitimate_origin_settings: dict[Settings, bool] | None = None,
        override_adoption_settings: dict[int, dict[Settings, bool]] | None = None,
        override_base_settings: dict[int, dict[Settings, bool]] | None = None,
        default_adoption_settings: dict[Settings, bool] | None = None,
        default_base_settings: dict[Settings, bool] | None = None,
        num_attackers: int = 1,
        num_legitimate_origins: int = 1,
        attacker_asn_group: str = ASNGroups.STUBS_OR_MH.value,
        legitimate_origin_asn_group: str = ASNGroups.STUBS_OR_MH.value,
        adoption_asn_groups: list[str] | None = None,
        override_attacker_asns: set[int] | None = None,
        override_legitimate_origin_asns: set[int] | None = None,
        override_adopting_asns: set[int] | None = None,
        override_announcements: set[Ann] | None = None,
        override_roas: set[ROA] | None = None,
        override_dest_ip_addr: IPAddr | None = None,
    ):
        # Label used for graphing, typically name it after the adopting policy
        self.label: str = label
        self.ScenarioCls: type["Scenario"] = ScenarioCls
        self.PolicyCls: type[Policy] = policy_cls
        self.propagation_rounds: int | None = propagation_rounds


        ###########################
        # Routing Policy Settings #
        ###########################

        # When determining if an AS is using a setting, the following order is used:
        # 1. attacker_settings or legitimate_origin_settings (if AS is an attacker or legitimate_origin)
        # 2. override_adoption_settings (if set)
        # 3. override_base_settings
        # 4. default_adoption_settings
        # 5. default_base_settings

        # 1a. This will update the base routing policy settings for the attacker ASes
        self.attacker_settings: dict[Settings, bool] = attacker_settings or dict()
        # 1v. This will update the base routing policy settings for the legitimate_origin ASes
        self.legitimate_origin_settings: dict[Settings, bool] = legitimate_origin_settings or dict()
        # 2. This will completely override the default adopt routing policy settings
        self.override_adoption_settings: dict[int, dict[str, bool]] = override_adoption_settings or dict()
        # 3. This will completely override the default base routing policy settings
        self.override_base_settings: dict[int, dict[str, bool]] = override_base_settings or dict()
        # 4. This will update the base routing policy settings for the adopting ASes
        self.default_adoption_settings: dict[str, bool] = default_adoption_settings or dict()
        # 5. Base routing policy settings that will be applied to all ASes
        self.default_base_settings: dict[str, bool] = default_base_settings or {
            x: False for x in Settings
        }

        # Number of attackers/legitimate_origins/adopting ASes
        self.num_attackers: int = num_attackers
        self.num_legitimate_origins: int = num_legitimate_origins

        # Attackers are randomly selected from this ASN group
        self.attacker_asn_group: str = attacker_asn_group
        # Victims are randomly selected from this ASN group
        self.legitimate_origin_asn_group: str = legitimate_origin_asn_group
        # Adoption is equal across these ASN groups
        self.adoption_asn_groups: list[str] = adoption_asn_groups or [ASNGroups.STUBS_OR_MH.value, ASNGroups.ETC.value, ASNGroups.TIER_1.value]

        # Forces the attackers/legitimate_origins/adopting ASes to be a specific set of ASes rather than random
        self.override_attacker_asns: set[int] | None = override_attacker_asns
        self.override_legitimate_origin_asns: set[int] | None = override_legitimate_origin_asns
        self.override_adopting_asns: set[int] | None = override_adopting_asns
        # Forces the announcements/roas to be a specific set of announcements/roas
        # rather than generated dynamically based on attackers/legitimate_origins
        self.override_announcements: set[Ann] | None = override_announcements
        self.override_roas: set[ROA] | None = override_roas
        # Every AS will attempt to send a packet to this IP address post propagation
        # This is used for the ASGraphAnalyzer to determine the outcome of a packet
        self.override_dest_ip_addr: IPAddr | None = override_dest_ip_addr
        if self.propagation_rounds is None:
            # BGP-iSec needs this.
            for policy_setting in [Settings.BGP_I_SEC, Settings.BGP_I_SEC_TRANSITIVE]:
                if (any(x.get(policy_setting) for x in [self.attacker_settings, self.legitimate_origin_settings, self.override_adoption_settings, self.override_base_settings, self.default_adoption_settings, self.default_base_settings])):
                    from bgpsimulator.simulation_framework.scenarios.shortest_path_prefix_hijack import ShortestPathPrefixHijack

                    if issubclass(self.ScenarioCls, ShortestPathPrefixHijack):
                        # ShortestPathPrefixHijack needs 2 propagation rounds
                        self.propagation_rounds = 2
                    else:
                        self.propagation_rounds = self.ScenarioCls.min_propagation_rounds
            if self.propagation_rounds is None:
                self.propagation_rounds = self.ScenarioCls.min_propagation_rounds
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

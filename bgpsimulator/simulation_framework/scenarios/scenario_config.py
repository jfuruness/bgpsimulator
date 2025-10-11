from functools import cached_property
from typing import Any

from bgpsimulator.route_validator import ROA
from bgpsimulator.shared import ASNGroups, IPAddr, Settings
from bgpsimulator.simulation_engine import Announcement as Ann

from .scenario import Scenario


class ScenarioConfig:
    """Config reused across trials to set up a scenario/attack"""

    def __eq__(self, other):
        if isinstance(other, ScenarioConfig):
            return self.to_json() == other.to_json()
        else:
            return NotImplemented

    def __init__(
        self,
        label: str,
        ScenarioCls: type["Scenario"],
        propagation_rounds: int | None = None,
        attacker_settings: dict[Settings, bool] | None = None,
        legitimate_origin_settings: dict[Settings, bool] | None = None,
        override_adoption_settings: dict[int, dict[Settings, bool]] | None = None,
        override_base_settings: dict[int, dict[Settings, bool]] | None = None,
        default_adoption_settings: dict[Settings, bool] | None = None,
        default_base_settings: dict[Settings, bool] | None = None,
        # NOTE: we don't want behavior where attackers and victims are
        # randomly added... especially for the website. It was never
        # proper behavior though, so we default to 0.
        num_attackers: int = 0,
        num_legitimate_origins: int = 0,
        attacker_asn_group: str = ASNGroups.STUBS_OR_MH.value,
        legitimate_origin_asn_group: str = ASNGroups.STUBS_OR_MH.value,
        adoption_asn_groups: list[str] | None = None,
        override_attacker_asns: set[int] | None = None,
        override_legitimate_origin_asns: set[int] | None = None,
        override_adopting_asns: set[int] | None = None,
        override_seed_asn_ann_dict: dict[int, list[Ann]] | None = None,
        override_roas: list[ROA] | None = None,
        override_dest_ip_addr: IPAddr | None = None,
    ):
        # Label used for graphing, typically name it after the adopting policy
        self.label: str = label
        self.ScenarioCls: type[Scenario] = ScenarioCls

        ###########################
        # Routing Policy Settings #
        ###########################

        # When determining if an AS is using a setting, the following order is used:
        # 1. attacker_settings or legitimate_origin_settings (if AS is an attacker or
        #    legitimate_origin)
        # 2. override_adoption_settings (if set)
        # 3. override_base_settings
        # 4. default_adoption_settings
        # 5. default_base_settings

        # 1a. This will update the base routing policy settings for the attacker ASes
        self.attacker_settings: dict[Settings, bool] = (
            self.update_supersets(attacker_settings) or dict()
        )
        # 1v. This will update the base routing policy settings for the
        #     legitimate_origin ASes
        self.legitimate_origin_settings: dict[Settings, bool] = (
            self.update_supersets(legitimate_origin_settings) or dict()
        )
        # 2. This will completely override the default adopt routing policy settings
        self.override_adoption_settings: dict[int, dict[Settings, bool]] = dict()
        if override_adoption_settings:
            self.override_adoption_setting = {
                asn: self.update_supersets(settings_dict)
                for asn, settings_dict in override_adoption_settings.items()
            }
        # 3. This will completely override the default base routing policy settings
        self.override_base_settings: dict[int, dict[Settings, bool]] = dict()
        if override_base_settings:
            self.override_base_settings = {
                asn: self.update_supersets(settings_dict)
                for asn, settings_dict in override_base_settings.items()
            }
        # 4. This will update the base routing policy settings for the adopting ASes
        self.default_adoption_settings: dict[Settings, bool] = (
            self.update_supersets(default_adoption_settings) or dict()
        )
        # 5. Base routing policy settings that will be applied to all ASes
        self.default_base_settings: dict[Settings, bool] = (
            self.update_supersets(default_base_settings) or dict()
        )

        # Attackers are randomly selected from this ASN group
        self.attacker_asn_group: str = attacker_asn_group
        # Victims are randomly selected from this ASN group
        self.legitimate_origin_asn_group: str = legitimate_origin_asn_group
        # Adoption is equal across these ASN groups
        self.adoption_asn_groups: list[str] = adoption_asn_groups or [
            ASNGroups.STUBS_OR_MH.value,
            ASNGroups.ETC.value,
            ASNGroups.TIER_1.value,
        ]

        # Number of attackers/legitimate_origins/adopting ASes
        # Ensure consistency: empty sets should be treated as None, and num should be 0
        if not override_attacker_asns:
            self.override_attacker_asns = None
            self.num_attackers = 0
        else:
            self.override_attacker_asns = override_attacker_asns
            self.num_attackers = len(override_attacker_asns)

        if not override_legitimate_origin_asns:
            self.override_legitimate_origin_asns = None
            self.num_legitimate_origins = 0
        else:
            self.override_legitimate_origin_asns = override_legitimate_origin_asns
            self.num_legitimate_origins = len(override_legitimate_origin_asns)

        # Forces the adopting ASes to be a specific set rather than random
        self.override_adopting_asns: set[int] | None = override_adopting_asns if override_adopting_asns else None
        # Forces the announcements/roas to be a specific set of announcements/roas
        # rather than generated dynamically based on attackers/legitimate_origins

        self.override_seed_asn_ann_dict: dict[int, list[Ann]] | None = (
            override_seed_asn_ann_dict
        )
        self.override_roas: list[ROA] | None = override_roas
        # Every AS will attempt to send a packet to this IP address post propagation
        # This is used for the ASGraphAnalyzer to determine the outcome of a packet
        self.override_dest_ip_addr: IPAddr | None = override_dest_ip_addr

        # Below this point 99% of devs will not need to touch
        self.propagation_rounds = propagation_rounds
        if self.propagation_rounds is None:
            # BGP-iSec needs this.
            if any(
                x in self.all_used_settings
                for x in [Settings.BGP_I_SEC, Settings.BGP_I_SEC_TRANSITIVE]
            ):
                from bgpsimulator.simulation_framework.scenarios.shortest_path_prefix_hijack import (  # noqa: E501
                    ShortestPathPrefixHijack,
                )

                if issubclass(self.ScenarioCls, ShortestPathPrefixHijack):
                    # ShortestPathPrefixHijack needs 2 propagation rounds
                    self.propagation_rounds: int = 2
                else:
                    self.propagation_rounds = self.ScenarioCls.min_propagation_rounds
            else:
                self.propagation_rounds = self.ScenarioCls.min_propagation_rounds
        if self.ScenarioCls.min_propagation_rounds > self.propagation_rounds:
            raise ValueError(
                f"{self.ScenarioCls.__name__} requires a minimum of "
                f"{self.ScenarioCls.min_propagation_rounds} propagation rounds "
                f"but this scenario_config has only {self.propagation_rounds} "
                "propagation rounds"
            )
        self.modify_for_withdrawals()

    def modify_for_withdrawals(self) -> bool:
        """Modifies the required settings for withdrawals"""

        # NOTE: ROST also deals with withdrawals, must be in this list
        requires_bgp_full = (
            Settings.LEAKER,
            Settings.ANNOUNCE_THEN_WITHDRAW,
            Settings.ROST,
        )
        if any(setting in self.all_used_settings for setting in requires_bgp_full):
            self.default_base_settings[Settings.BGP_FULL] = True
            if self.propagation_rounds == 1:
                self.propagation_rounds = 2

    @staticmethod
    def update_supersets(
        policy_settings: dict[Settings, bool] | None,
    ) -> dict[Settings, bool]:
        """Updates the supersets of a policy setting"""

        if policy_settings is None:
            return dict()

        new_settings = policy_settings.copy()
        if policy_settings.get(Settings.BGP_I_SEC, False):
            new_settings[Settings.BGP_I_SEC_TRANSITIVE] = True
            new_settings[Settings.PROVIDER_CONE_ID] = True
            new_settings[Settings.ONLY_TO_CUSTOMERS] = True
        if policy_settings.get(Settings.PATH_END, False):
            new_settings[Settings.ROV] = True
        if any(
            policy_settings.get(x)
            for x in [Settings.ROVPP_V2_LITE, Settings.ROVPP_V2I_LITE]
        ):
            new_settings[Settings.ROVPP_V1_LITE] = True
            new_settings[Settings.ROV] = True
        if policy_settings.get(Settings.ROVPP_V1_LITE, False):
            new_settings[Settings.ROV] = True
        if any(policy_settings.get(x) for x in [Settings.ASRA, Settings.ASPA_W_N]):
            new_settings[Settings.ASPA] = True
        if any(policy_settings.get(x) for x in [Settings.ASPAPP]):
            new_settings[Settings.ASPA] = True
            new_settings[Settings.ASRA] = True
            new_settings[Settings.PROVIDER_CONE_ID] = True
        return new_settings

    @cached_property
    def all_used_settings(self) -> frozenset[Settings]:
        """Returns all the settings that are used in the scenario config"""
        used_settings = set()
        for settings_dict in [
            self.attacker_settings,
            self.legitimate_origin_settings,
            self.default_adoption_settings,
            self.default_base_settings,
        ]:
            # Mypy can't detect this type is {Settings: bool} for some reason
            for setting, bool_val in settings_dict.items():
                if bool_val:
                    used_settings.add(setting)
        for asn_to_settings_dict in (
            self.override_adoption_settings,
            self.override_base_settings,
        ):
            for settings_dict in asn_to_settings_dict.values():
                for setting, bool_val in settings_dict.items():
                    if bool_val:
                        used_settings.add(setting)
        return frozenset(used_settings)

    ##############
    # JSON Funcs #
    ##############

    def to_json(self) -> dict[str, Any]:
        """Converts the scenario config to a JSON object"""
        # Only include fields that are constructor parameters
        vals = {
            "label": self.label,
            "ScenarioCls": self.ScenarioCls.__name__,
            "propagation_rounds": self.propagation_rounds,
            "attacker_settings": self.attacker_settings,
            "legitimate_origin_settings": self.legitimate_origin_settings,
            "override_adoption_settings": self.override_adoption_settings,
            "override_base_settings": self.override_base_settings,
            "default_adoption_settings": self.default_adoption_settings,
            "default_base_settings": self.default_base_settings,
            "num_attackers": self.num_attackers,
            "num_legitimate_origins": self.num_legitimate_origins,
            "attacker_asn_group": self.attacker_asn_group,
            "legitimate_origin_asn_group": self.legitimate_origin_asn_group,
            "adoption_asn_groups": self.adoption_asn_groups,
            "override_attacker_asns": self.override_attacker_asns,
            "override_legitimate_origin_asns": self.override_legitimate_origin_asns,
            "override_adopting_asns": self.override_adopting_asns,
            "override_seed_asn_ann_dict": self.override_seed_asn_ann_dict,
            "override_roas": self.override_roas,
            "override_dest_ip_addr": self.override_dest_ip_addr,
        }

        # Handle override_seed_asn_ann_dict
        if vals.get("override_seed_asn_ann_dict") is not None:
            vals["override_seed_asn_ann_dict"] = {
                str(asn): [ann.to_json() for ann in anns]
                for asn, anns in vals["override_seed_asn_ann_dict"].items()  # type: ignore
            }

        # Handle override_roas
        if vals.get("override_roas") is not None:
            vals["override_roas"] = [roa.to_json() for roa in vals["override_roas"]]  # type: ignore

        # Handle override_dest_ip_addr
        if vals.get("override_dest_ip_addr") is not None:
            vals["override_dest_ip_addr"] = str(vals["override_dest_ip_addr"])

        # Convert sets to lists for JSON serialization
        # Only include non-empty sets (empty sets should be omitted/null)
        if vals.get("override_attacker_asns") is not None and vals["override_attacker_asns"]:
            vals["override_attacker_asns"] = list(vals["override_attacker_asns"])  # type: ignore
        else:
            vals["override_attacker_asns"] = None

        if vals.get("override_legitimate_origin_asns") is not None and vals["override_legitimate_origin_asns"]:
            vals["override_legitimate_origin_asns"] = list(  # type: ignore
                vals["override_legitimate_origin_asns"]
            )
        else:
            vals["override_legitimate_origin_asns"] = None

        if vals.get("override_adopting_asns") is not None and vals["override_adopting_asns"]:
            vals["override_adopting_asns"] = list(vals["override_adopting_asns"])  # type: ignore
        else:
            vals["override_adopting_asns"] = None

        return vals

    @classmethod
    def from_json(cls, json_obj: dict[str, Any]) -> "ScenarioConfig":
        """Converts a JSON object to a scenario config"""
        vals = json_obj.copy()
        vals["ScenarioCls"] = Scenario.name_to_cls_dict[vals["ScenarioCls"]]

        # Handle override_seed_asn_ann_dict
        if vals.get("override_seed_asn_ann_dict") is not None:
            vals["override_seed_asn_ann_dict"] = {
                int(asn): [Ann.from_json(ann) for ann in anns]
                for asn, anns in vals["override_seed_asn_ann_dict"].items()
            }

        fields_to_convert_keys_to_ints = (
            "override_adoption_settings",
            "override_base_settings",
        )
        for field in fields_to_convert_keys_to_ints:
            if vals.get(field):
                vals[field] = {int(k): v for k, v in vals[field].items()}

        # Handle override_roas
        if vals.get("override_roas") is not None:
            from bgpsimulator.route_validator import ROA

            vals["override_roas"] = [
                ROA.from_json(roa) for roa in vals["override_roas"]
            ]

        # Handle override_dest_ip_addr
        if vals.get("override_dest_ip_addr") is not None:
            from bgpsimulator.shared import IPAddr

            vals["override_dest_ip_addr"] = IPAddr(vals["override_dest_ip_addr"])

        # Convert lists back to sets
        if vals.get("override_attacker_asns") is not None:
            vals["override_attacker_asns"] = set(vals["override_attacker_asns"])
        if vals.get("override_legitimate_origin_asns") is not None:
            vals["override_legitimate_origin_asns"] = set(
                vals["override_legitimate_origin_asns"]
            )
        if vals.get("override_adopting_asns") is not None:
            vals["override_adopting_asns"] = set(vals["override_adopting_asns"])

        return cls(**vals)

from typing import TYPE_CHECKING

from bgpsimulator.shared import PolicyPropagateInfo, Relationships, Settings

if TYPE_CHECKING:
    from bgpsimulator.as_graphs import AS
    from bgpsimulator.simulation_engine import Announcement as Ann
    from bgpsimulator.simulation_engine.policy.policy import Policy


class BGPSec:
    """A Policy that deploys BGPSEC as defined in the BGPSEC RFC

    Since there are no real world implementations,
    we assume a secure path preference of security third,
    which is in line with the majority of users
    for the survey results in "A Survey of Interdomain Routing Policies"
    https://www.cs.bu.edu/~goldbe/papers/survey.pdf
    """

    @staticmethod
    def get_modified_seed_ann(policy: "Policy", ann: "Ann") -> "Ann":
        """Seeds an announcement into the local RIB and inits bgpsec_as_path"""

        # If the path is valid, add bgpsec_as_path
        if ann.as_path == (policy.as_.asn,):
            return ann.copy(bgpsec_as_path=ann.as_path)
        return ann

    @staticmethod
    def bgpsec_valid(policy: "Policy", ann: "Ann") -> bool:
        """Checks if an announcement is valid for BGPSEC"""
        return (
            ann.bgpsec_next_asn == policy.as_.asn and ann.bgpsec_as_path == ann.as_path
        )

    @staticmethod
    def get_policy_propagate_vals(
        policy: "Policy",
        neighbor_as: "AS",
        ann: "Ann",
        propagate_to: Relationships,
        send_rels: set[Relationships],
    ) -> PolicyPropagateInfo:
        """Gets the policy propagate values for a given announcement"""

        neighbor_bgpsec = any(
            neighbor_as.policy.settings[setting]
            for setting in [
                Settings.BGPSEC,
                Settings.BGP_I_SEC,
                Settings.BGP_I_SEC_TRANSITIVE,
            ]
        )
        if neighbor_bgpsec:
            next_asn = neighbor_as.asn
            path = ann.bgpsec_as_path
        else:
            next_asn = None
            path = ()
        send_ann = ann.copy(bgpsec_next_asn=next_asn, bgpsec_as_path=path)
        return PolicyPropagateInfo(
            policy_propagate_bool=True, ann=send_ann, send_ann_bool=True
        )

    @staticmethod
    def process_ann(policy: "Policy", ann: "Ann", from_rel: Relationships) -> "Ann":
        """Sets the bgpsec_as_path. Prepends ASN if valid, otherwise clears"""

        # NOTE: must only look after the first ASN in the path, since the new ASN will
        # already have been prepended in the Policy class.
        if BGPSec.bgpsec_valid(policy, ann.copy(as_path=ann.as_path[1:])):
            return ann.copy(bgpsec_as_path=ann.as_path)
        else:
            return ann.copy(bgpsec_as_path=())

    @staticmethod
    def get_best_ann_by_bgpsec(
        policy: "Policy", current_ann: "Ann", new_ann: "Ann"
    ) -> "Ann | None":
        """Gets the best announcement by BGPSEC"""

        current_ann_valid = BGPSec.bgpsec_valid(policy, current_ann)
        new_ann_valid = BGPSec.bgpsec_valid(policy, new_ann)

        if current_ann_valid and not new_ann_valid:
            return current_ann
        elif not current_ann_valid and new_ann_valid:
            return new_ann
        else:
            return None

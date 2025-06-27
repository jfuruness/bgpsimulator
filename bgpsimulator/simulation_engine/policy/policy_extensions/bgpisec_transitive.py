from typing import TYPE_CHECKING

from bgpsimulator.shared import PolicyPropagateInfo, Relationships, Settings

from .bgpsec import BGPSec

if TYPE_CHECKING:
    from bgpsimulator.as_graphs import AS
    from bgpsimulator.simulation_engine import Announcement as Ann
    from bgpsimulator.simulation_engine.policy.policy import Policy


class BGPiSecTransitive:
    """A Policy that deploys BGPiSec-Transitive as defined in the BGPiSec paper

    Extends BGPSec, aside from the path preference mechanism, which BGPiSec reverts
    to BGP. Additionally, this is only the transitive signatures of BGPiSec, not the
    entire policy
    """

    @staticmethod
    def get_modified_seed_ann(policy: "Policy", ann: "Ann") -> "Ann":
        return BGPSec.get_modified_seed_ann(policy, ann)

    @staticmethod
    def get_policy_propagate_vals(
        policy: "Policy",
        neighbor_as: "AS",
        ann: "Ann",
        propagate_to: Relationships,
        send_rels: set[Relationships],
    ) -> PolicyPropagateInfo:
        """Always set the BGPSec vals when propagating for BGPiSec"""

        send_ann = ann.copy(
            bgpsec_next_asn=neighbor_as.asn, bgpsec_as_path=ann.bgpsec_as_path
        )
        return PolicyPropagateInfo(
            policy_propagate_bool=True, ann=send_ann, send_ann_bool=True
        )

    @staticmethod
    def process_ann(policy: "Policy", ann: "Ann", from_rel: Relationships) -> "Ann":
        """Sets the bgpsec_as_path always for transitive signatures"""

        return ann.copy(bgpsec_as_path=(policy.as_.asn, *ann.bgpsec_as_path))

    @staticmethod
    def valid_ann(policy: "Policy", ann: "Ann", from_rel: Relationships) -> bool:
        """Determines bgp-isec transitive validity

        If any ASes along the AS path are adopting and are not in the bgpsec_as_path,
        that means those ASes didn't add signatures, therefore the ann is missing
        signatures and should be dropped
        """

        as_graph = policy.as_.as_graph
        bgpsec_signatures = ann.bgpsec_as_path
        for asn in ann.as_path:
            if asn not in bgpsec_signatures and (
                as_graph.as_dict[asn].policy.settings[Settings.BGP_I_SEC]
                or as_graph.as_dict[asn].policy.settings[Settings.BGP_I_SEC_TRANSITIVE]
            ):
                return False
        return True

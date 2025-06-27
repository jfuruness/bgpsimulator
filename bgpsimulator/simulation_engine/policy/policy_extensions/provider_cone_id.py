from typing import TYPE_CHECKING

from bgpsimulator.shared import Relationships, Settings

if TYPE_CHECKING:
    from bgpsimulator.simulation_engine import Announcement as Ann
    from bgpsimulator.simulation_engine.policy.policy import Policy


class ProviderConeID:
    """A Policy that deploys Provider Cone ID as defined in the BGP-iSec paper

    For simplicity, we just put the full provider cone
    """

    @staticmethod
    def valid_ann(policy: "Policy", ann: "Ann", from_rel: Relationships) -> bool:
        """Determines Provider Cone ID validity from customers"""

        if from_rel == Relationships.CUSTOMERS:
            as_dict = policy.as_.as_graph.as_dict
            provider_cone_asns = as_dict[ann.origin].provider_cone_asns
            # We don't look at the last ASN in the path, since that's the origin
            # The ASes ASN is also not yet in the announcement, so we add it here
            for asn in (policy.as_.asn, *ann.as_path[:-1]):
                # not in provider cone of the origin, and is adopting
                if asn not in provider_cone_asns and (
                    as_dict[asn].policy.settings[Settings.BGP_I_SEC]
                    or as_dict[asn].policy.settings[Settings.PROVIDER_CONE_ID]
                    or as_dict[asn].policy.settings[Settings.ASPAPP]
                ):
                    return False

        return True

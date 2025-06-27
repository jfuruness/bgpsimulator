from typing import TYPE_CHECKING

from bgpsimulator.shared import Relationships, Settings

from .aspa import ASPA

if TYPE_CHECKING:
    from bgpsimulator.simulation_engine import Announcement as Ann
    from bgpsimulator.simulation_engine.policy.policy import Policy


class ASPAwN:
    """ASRA: Esentially ASPA and checking neighbors at every AS together

    NOTE: Updated 12/26/2024. This is the same as ASRA algo B, confirmed

    Originally we had this policy coded for ASPAwN, an extension of ASPA that
    we had developed independently of ASRA in parallel. Upon publishing an ASPA
    evaluation paper, we received feedback from an ASPA RFC author and converted
    ASPAwN into ASRA

    That being said, ASRA is not yet finalized, and at the time of this writing the
    draft wasn't even published. This policy assumes ASRA3 records (not specifying
    the neighbor type) and also assumes the strict algorithm.

    As ASPAwN is equivalent to ASRA, this is merely vestigial and I would recommend
    using the ASRA policy. However - ASRA is the same as ASPAwN and imo this is a
    vastly more simple algorithm.
    """

    @staticmethod
    def valid_ann(policy: "Policy", ann: "Ann", from_rel: Relationships) -> bool:
        """Checks neighbors at every AS in the AS-Path"""

        as_path = ann.as_path
        as_dict = policy.as_.as_graph.as_dict
        for i, asn in enumerate(as_path):
            # Get the AS object for the current AS in the AS Path
            asra_as_obj = as_dict.get(asn)
            # If the AS is an ASRA AS
            if asra_as_obj and asra_as_obj.policy.settings[Settings.ASPA_W_N]:
                # Check that both of it's neighbors are in the valid next hops
                for neighbor_index in (i - 1, i + 1):
                    # Can't use try except IndexError here, since -1 is a valid index
                    if 0 <= neighbor_index < len(as_path):
                        neighbor_asn = as_path[neighbor_index]
                        if neighbor_asn not in asra_as_obj.neighbor_asns:
                            return False
        # This is a superset of ASPA
        return ASPA.valid_ann(policy, ann, from_rel)

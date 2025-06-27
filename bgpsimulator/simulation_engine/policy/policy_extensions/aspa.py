from typing import TYPE_CHECKING

from bgpsimulator.shared.enums import Relationships, Settings

if TYPE_CHECKING:
    from bgpsimulator.simulation_engine import Announcement as Ann
    from bgpsimulator.simulation_engine.policy.policy import Policy


class ASPA:
    """A Policy that deploys ASPA and ASPA Records

    We experimented with adding a cache to the provider_check
    but this has a negligible impact on performance

    Removing the path reversals sped up performance by about 5%
    but made the code a lot less readable and deviated from the RFC,
    so we decided to forgo those as well

    This is now up to date with the V18 proposal
    """

    @staticmethod
    def valid_ann(policy: "Policy", ann: "Ann", from_rel: Relationships) -> bool:
        """Returns False if ann from peer/customer when ASPA is set"""

        # Note: This first if check has to be removed if you want to implement
        # route server to RS-Client behaviour
        if not ASPA._next_hop_valid(policy, ann):
            return False
        # Most ASes recieve anns from providers (moved here for speed)
        elif from_rel == Relationships.PROVIDERS:
            return ASPA._downstream_check(policy, ann, from_rel)
        elif from_rel in (Relationships.CUSTOMERS, Relationships.PEERS):
            return ASPA._upstream_check(policy, ann, from_rel)
        else:
            raise NotImplementedError("Should never reach here")

    @staticmethod
    def _next_hop_valid(policy: "Policy", ann: "Ann") -> bool:
        """Ensures the next hop is the first ASN in the AS-Path

        Route servers are allowed to strip their own ASN (and in most cases are
        obligated to)
        """

        return ann.next_hop_asn == ann.as_path[0] or policy.as_.ixp

    @staticmethod
    def _upstream_check(
        policy: "Policy", ann: "Ann", from_rel: "Relationships"
    ) -> bool:
        """ASPA upstream check"""

        # Upstream check
        if len(ann.as_path) == 1:
            return True
        # For every adopting ASPA AS in the path,
        # The next ASN in the path must be in their providers list
        # Since this is checking from customers

        # 4. If max_up_ramp < N, the procedure halts with the outcome "Invalid".
        elif ASPA._get_max_up_ramp_length(policy, ann) < len(ann.as_path):
            return False

        # ASPA valid or unknown
        return True

    @staticmethod
    def _get_max_up_ramp_length(policy: "Policy", ann: "Ann") -> int:
        """See desc

        Determine the maximum up-ramp length as I, where I is the minimum
        index for which authorized(A(I), A(I+1)) returns "Not Provider+".  If
        there is no such I, the maximum up-ramp length is set equal to the
        AS_PATH length N.  This parameter is defined as max_up_ramp

        The up-ramp starts at AS(1) and each hop AS(i) to AS(i+1) represents
        Customer and Provider peering relationship. [i.e they reverse the path]
        """

        reversed_path = ann.as_path[::-1]

        for i in range(len(reversed_path) - 1):
            if not ASPA._provider_check(policy, reversed_path[i], reversed_path[i + 1]):
                return i + 1
        return len(ann.as_path)

    @staticmethod
    def _downstream_check(
        policy: "Policy", ann: "Ann", from_rel: "Relationships"
    ) -> bool:
        """ASPA downstream check"""

        # 4. If max_up_ramp + max_down_ramp < N,
        # the procedure halts with the outcome "Invalid".
        max_up_ramp = ASPA._get_max_up_ramp_length(policy, ann)
        max_down_ramp = ASPA._get_max_down_ramp_length(policy, ann)
        if max_up_ramp + max_down_ramp < len(ann.as_path):
            return False

        # ASPA Valid or Unknown (but not invalid)
        return True

    @staticmethod
    def _get_max_down_ramp_length(policy: "Policy", ann: "Ann") -> int:
        """See desc

        Similarly, the maximum down-ramp length can be determined as N - J +
        1 where J is the maximum index for which authorized(A(J), A(J-1))
        returns "Not Provider+".  If there is no such J, the maximum down-
        ramp length is set equal to the AS_PATH length N.  This parameter is
        defined as max_down_ramp.

        In the down-ramp, each pair AS(j) to
        AS(j-1) represents Customer and Provider peering relationship
        """

        reversed_path = ann.as_path[::-1]

        # We want the max J, so start at the end of the reversed Path
        # This is the most efficient way to traverse this
        for i in range(len(reversed_path) - 1, 0, -1):
            if not ASPA._provider_check(policy, reversed_path[i], reversed_path[i - 1]):
                # Must add one due to zero indexing in python, vs 1 indexing in RFC
                J = i + 1
                return len(reversed_path) - J + 1
        return len(ann.as_path)

    @staticmethod
    def _provider_check(policy: "Policy", asn1: int, asn2: int) -> bool:
        """Returns False if asn2 is not in asn1's provider_asns, AND asn1 adopts ASPA

        This also essentially can take the place of the "hop check" listed in
        ASPA RFC section 5 in ASPA v16
        or in ASPAv18 it takes the place of the provider auth func

        False indicates Not Provider+
        True indicates No Attestation or Provider+

        Updated so that if either AS doesn't exist, this function returns properly
        """

        cur_as_obj = policy.as_.as_graph.as_dict.get(asn1)
        if cur_as_obj and cur_as_obj.policy.settings[Settings.ASPA]:
            next_as_obj = policy.as_.as_graph.as_dict.get(asn2)
            next_asn = next_as_obj.asn if next_as_obj else next_as_obj
            if next_asn not in cur_as_obj.provider_asns:
                return False
        return True

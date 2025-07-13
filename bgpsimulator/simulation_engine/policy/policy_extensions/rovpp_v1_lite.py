from typing import TYPE_CHECKING, Iterator

from bgpsimulator.shared import PolicyPropagateInfo, Relationships, Settings, Timestamps
from bgpsimulator.simulation_engine import Announcement as Ann

from .rov import ROV

if TYPE_CHECKING:
    from bgpsimulator.as_graphs import AS
    from bgpsimulator.simulation_engine.policy.policy import Policy


class ROVPPV1Lite:
    """A Policy that deploys ROV++V1 Lite as defined in the ROV++ paper"""

    @staticmethod
    def get_policy_propagate_vals(
        policy: "Policy",
        neighbor_as: "AS",
        ann: "Ann",
        propagate_to: Relationships,
        send_rels: set[Relationships],
    ) -> PolicyPropagateInfo:
        if ann.rovpp_blackhole:
            return PolicyPropagateInfo(
                policy_propagate_bool=True, ann=ann, send_ann_bool=False
            )
        else:
            return PolicyPropagateInfo(
                policy_propagate_bool=False, ann=ann, send_ann_bool=True
            )

    @staticmethod
    def process_incoming_anns(
        policy: "Policy", from_rel: Relationships, propagation_round: int
    ) -> None:
        """Additional processing for incoming announcements"""

        ROVPPV1Lite.add_blackholes(policy, from_rel)
        ROVPPV1Lite.recount_blackholes(policy, propagation_round)

    @staticmethod
    def add_blackholes(policy: "Policy", from_rel: Relationships) -> None:
        """Adds blackholes announcements to the local RIB

        First add all non routed prefixes from ROAs as blackholes
        Then for each ann in th elocal RIB, if you recieived an
        invalid subprefix from the same neighbor,
        add it to the local RIB as a blackhole
        """

        non_routed_blackholes = ROVPPV1Lite.get_non_routed_blackholes_to_add(policy)
        routed_blackholes = ROVPPV1Lite.get_routed_blackholes_to_add(policy, from_rel)
        ROVPPV1Lite.add_blackholes_to_local_rib(
            policy, non_routed_blackholes + routed_blackholes
        )

    @staticmethod
    def get_non_routed_blackholes_to_add(policy: "Policy") -> list["Ann"]:
        """Gets all non routed blackholes to add to the local RIB"""

        non_routed_blackholes_to_add = []
        for roa in policy.route_validator.roas:
            if not roa.is_routed:
                non_routed_blackholes_to_add.append(
                    Ann(
                        prefix=roa.prefix,
                        next_hop_asn=policy.as_.asn,
                        as_path=(policy.as_.asn,),
                        # Victim's timestamp since it's upon ROA creation pre-attacker
                        timestamp=Timestamps.LEGITIMATE_ORIGIN,
                        recv_relationship=Relationships.ORIGIN,
                        rovpp_blackhole=True,
                    )
                )
        return non_routed_blackholes_to_add

    @staticmethod
    def get_routed_blackholes_to_add(
        policy: "Policy", from_rel: Relationships
    ) -> list["Ann"]:
        """Gets all routed blackholes from the anns you just recieved"""

        routed_blackholes_to_add = []
        for ann in policy.local_rib.values():
            for unprocessed_sub_ann in ROVPPV1Lite.invalid_subprefixes_from_neighbor(
                policy, ann
            ):
                processed_sub_ann = policy.process_ann(unprocessed_sub_ann, from_rel)
                # Add blackhole attributes to the processed ann
                blackhole_ann = processed_sub_ann.copy(
                    next_hop_asn=policy.as_.asn,
                    rovpp_blackhole=True,
                )
                routed_blackholes_to_add.append(blackhole_ann)
        return routed_blackholes_to_add

    @staticmethod
    def invalid_subprefixes_from_neighbor(
        policy: "Policy", ann: "Ann"
    ) -> Iterator["Ann"]:
        """Returns all invalid subprefixes from the neighbor"""

        # If we are the origin, then there are zero invalid anns from the same neighbor
        if ann.recv_relationship == Relationships.ORIGIN:
            return
        # for each subprefix ann recieved (NOTE: these aren't in local RIB since
        # they're invalid) and dropped by default (but they are recieved so we can
        # check there)
        for recvq_prefix, recvq_anns_list in policy.recv_q.items():
            # recvq prefix is a subprefix of ann
            if ann.prefix.supernet_of(recvq_prefix) and ann.prefix != recvq_prefix:
                for recvq_ann in recvq_anns_list:
                    if (
                        policy.ann_is_invalid_by_roa(recvq_ann)
                        # Check the first one in the path since it's already processed
                        and recvq_ann.as_path[0] == ann.as_path[1]
                    ):
                        yield recvq_ann

    @staticmethod
    def add_blackholes_to_local_rib(
        policy: "Policy", blackhole_anns: list["Ann"]
    ) -> None:
        """Adds blackholes to the local RIB"""

        for blackhole_ann in blackhole_anns:
            existing_ann = policy.local_rib.get(blackhole_ann.prefix)
            # Don't overwrite existing valid announcements
            if existing_ann is None:
                policy.local_rib[blackhole_ann.prefix] = blackhole_ann
            elif policy.ann_is_invalid_by_roa(existing_ann):
                # Not sure why anyone would ever need this
                # so I'm not implementing it for now
                # Also how would an existing ann be invalid in ROV++?
                # TODO: Implement this
                if policy.settings[Settings.BGP_FULL]:
                    raise NotImplementedError("Withdrawals not supported for ROV++")
                policy.local_rib[blackhole_ann.prefix] = blackhole_ann

    @staticmethod
    def recount_blackholes(policy: "Policy", propagation_round: int) -> None:
        """Recounts blackholes in the local RIB"""

        # It's possible that we had a previously valid prefix
        # Then later recieved a subprefix that was invalid
        # Or there was previously an invalid subprefix
        # But later that invalid subprefix was removed
        # So we must recount the holes of each ann in local RIB
        # NOTE June 22 2024: I think doing this may require the use of the AdjRIBsIn
        # because you could recieve a subprefix hijack round 1, and round 2 receive
        # the valid prefix from the same neighbor
        # not going to implement because of that, and because I don't think there's
        # a need to, because as far as I know there aren't any two round attacks
        # against ROV++. If someone comes up with one let me know and I can try to
        # help out, email at jfuruness@gmail.com.
        # NOTE: Additionally, we don't account for withdrawals at all...
        if propagation_round != 0:
            raise NotImplementedError("TODO: support ROV++ for multiple rounds")

    @staticmethod
    def valid_ann(policy: "Policy", ann: "Ann", from_rel: Relationships) -> bool:
        """Determines ROV++V1 Lite validity"""

        return ROV.valid_ann(policy, ann, from_rel)

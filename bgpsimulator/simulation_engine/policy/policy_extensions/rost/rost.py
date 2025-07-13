from typing import TYPE_CHECKING

from bgpsimulator.shared import Relationships

if TYPE_CHECKING:
    from bgpsimulator.simulation_engine import Announcement as Ann
    from bgpsimulator.simulation_engine.policy.policy import Policy


class ROST:
    """A Policy that deploys ROST"""

    @staticmethod
    def withdraw_ann_from_neighbors(policy: "Policy", withdraw_ann: "Ann") -> None:
        """Adds withdrawals you create to RoST Trusted Repo"""

        policy.rost_trusted_repository.add_ann(
            withdraw_ann, policy.as_.asn, active=False
        )

    @staticmethod
    def preprocess_incoming_anns(
        policy: "Policy",
        *,
        from_rel: Relationships,
        propagation_round: int = 0,
        **kwargs,
    ) -> None:
        """Adds withdrawals and anns you received to the rost trusted repo"""

        ROST.remove_anns_from_recv_q_that_should_be_withdrawn(policy)
        ROST.add_suppressed_withdrawals_back_to_recv_q(policy)

    @staticmethod
    def postprocess_incoming_anns(policy: "Policy") -> None:
        """sets local rib anns to active in rost trusted repo"""

        for ann in policy.local_rib.values():
            policy.rost_trusted_repository.add_ann(ann, policy.as_.asn, active=True)

    @staticmethod
    def remove_anns_from_recv_q_that_should_be_withdrawn(policy: "Policy") -> None:
        for prefix, ann_list in policy.recv_q.copy().items():
            new_ann_list = list()
            for ann in ann_list:
                # So long as it's not a new ann that has a suppressed withdrawal
                # add to recv_q
                if not (
                    ann.withdraw is False
                    and policy.rost_trusted_repository.seen_withdrawal(ann)
                ):
                    new_ann_list.append(ann)
            policy.recv_q[prefix] = new_ann_list

    @staticmethod
    def add_suppressed_withdrawals_back_to_recv_q(policy: "Policy") -> None:
        for inner_dict in policy.adj_ribs_in.values():
            for ann_info in inner_dict.values():
                adj_ribs_in_ann = ann_info.unprocessed_ann

                # Determine if the AdjRIBsIn ann is already being withdrawn
                withdrawal_in_recv_q = False
                for ann in policy.recv_q.get(adj_ribs_in_ann.prefix, []):
                    if adj_ribs_in_ann.as_path == ann.as_path:
                        withdrawal_in_recv_q = True

                # if adj_ribs_in_ann withdrawal not in the recv_q,
                # and adj_ribs_in_ann in the trusted repo, create a withdrawal
                if (
                    not withdrawal_in_recv_q
                    and policy.rost_trusted_repository.seen_withdrawal(adj_ribs_in_ann)
                ):
                    policy.recv_q[adj_ribs_in_ann.prefix].append(
                        adj_ribs_in_ann.copy(withdraw=True)
                    )

    @staticmethod
    def process_ann(policy: "Policy", ann: "Ann", from_rel: "Relationships") -> "Ann":
        """Processes an announcement for RoST"""

        return ann.copy(rost_ids=(policy.as_.asn, *ann.rost_ids))

from collections import UserDict
import dataclasses
from typing import TYPE_CHECKING


if TYPE_CHECKING:
    from bgpsimulator.shared import Relationships, Prefix
    from bgpsimulator.simulation_engine import Announcement as Ann


@dataclasses.dataclass(frozen=True, slots=True)
class AnnInfo:
    """Dataclass for storing a ribs in Ann info

    These announcements are unprocessed, so we store
    the unprocessed_ann and also the recv_relationship
    (since the recv_relationship on the announcement is
    from the last AS and has not yet been updated)
    """

    unprocessed_ann: "Ann"
    recv_relationship: "Relationships"

    def to_json(self) -> dict[str, Ann | Relationships]:
        """Returns a JSON representation of the AnnInfo"""

        return {
            "unprocessed_ann": self.unprocessed_ann,
            "recv_relationship": self.recv_relationship,
        }

    @classmethod    
    def from_json(cls, json: dict[str, Ann | Relationships]) -> "AnnInfo":
        """Returns an AnnInfo from a JSON representation"""

        return cls(
            unprocessed_ann=json["unprocessed_ann"],
            recv_relationship=json["recv_relationship"],
        )


class RIBsIn(UserDict[int, dict[Prefix, AnnInfo]]):
    """Incomming announcements for a BGP AS

    neighbor: {prefix: (unprocessed_ann, relationship)}
    """

    def get_unprocessed_ann_recv_rel(
        self, neighbor_asn: int, prefix: Prefix
    ) -> AnnInfo | None:
        """Returns AnnInfo for a neighbor ASN and prefix"""

        return self.data.get(neighbor_asn, dict()).get(prefix)

    def add_unprocessed_ann(
        self,
        unprocessed_ann: "Ann",
        recv_relationship: "Relationships",
    ):
        """Adds an unprocessed ann to ribs in"""

        # Shorten the var name
        ann = unprocessed_ann
        if ann.as_path[0] not in self.data:
            self.data[ann.as_path[0]] = {
                ann.prefix: AnnInfo(
                    unprocessed_ann=unprocessed_ann, recv_relationship=recv_relationship
                )
            }
        else:
            self.data[ann.as_path[0]][ann.prefix] = AnnInfo(
                unprocessed_ann=unprocessed_ann, recv_relationship=recv_relationship
            )

    def get_ann_infos(self, prefix: str) -> list[AnnInfo]:
        """Returns AnnInfos for a given prefix"""

        ann_infos = []
        for prefix_ann_info in self.data.values():
            ann_info = prefix_ann_info.get(prefix)
            if ann_info:
                ann_infos.append(ann_info)
        return ann_infos

    def remove_entry(self, neighbor_asn: int, prefix: Prefix):
        """Removes AnnInfo from RibsIn

        In real life, ASes ignore cases where withdrawals don't have a corresponding
        announcement, which is why we don't raise an error here
        """

        try:
            del self.data[neighbor_asn][prefix]
        except KeyError:
            pass

    def to_json(self) -> dict[int, dict[str, dict[str, Ann | Relationships]]]:
        """Returns a JSON representation of the RIBsIn"""

        return {
            neighbor_asn: {
                str(prefix): ann_info.to_json()
                for prefix, ann_info in self.data.items()
            }
        }

    @classmethod
    def from_json(cls, json: dict[int, dict[str, dict[str, dict[str, Ann | Relationships]]]]) -> "RIBsIn":
        """Returns a RIBsIn from a JSON representation"""

        ribs_in = cls()
        for neighbor_asn, prefix_ann_infos in json.items():
            for prefix, ann_info_json in prefix_ann_infos.items():
                ann_info = AnnInfo.from_json(ann_info_json)
                ribs_in.add_unprocessed_ann(ann_info.unprocessed_ann, ann_info.recv_relationship)
        return ribs_in
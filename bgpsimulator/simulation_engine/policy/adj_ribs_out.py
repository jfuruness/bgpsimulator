from collections import UserDict

from bgpsimulator.shared import Prefix
from bgpsimulator.simulation_engine import Announcement as Ann


class AdjRIBsOut(UserDict[int, dict[Prefix, Ann]]):
    """Incomming announcements for a BGP AS

    neighbor: {prefix: announcement}
    """

    def get_ann(self, neighbor_asn: int, prefix: Prefix) -> Ann | None:
        """Returns Ann for a given neighbor asn and prefix"""

        return self.data.get(neighbor_asn, dict()).get(prefix)

    def add_ann(self, neighbor_asn: int, ann: Ann) -> None:
        """Adds announcement to the ribs out"""

        if neighbor_asn in self.data:
            self.data[neighbor_asn][ann.prefix] = ann
        else:
            self.data[neighbor_asn] = {ann.prefix: ann}

    def remove_entry(self, neighbor_asn: int, prefix: Prefix) -> bool:
        """Removes ann from ribs out"""

        try:
            del self.data[neighbor_asn][prefix]
            return True
        except KeyError:
            return False

    def populated_neighbors(self) -> list[int]:
        """Return all neighbors from the ribs out"""

        return list(self.data.keys())

    def to_json(self) -> dict[int, dict[str, dict[str, dict[str, Ann]]]]:
        """Returns a JSON representation of the AdjRIBsOut"""

        return {
            neighbor_asn: {
                str(prefix): ann.to_json() for prefix, ann in prefix_anns.items()
            }
            for neighbor_asn, prefix_anns in self.data.items()
        }

    @classmethod
    def from_json(
        cls, json: dict[int, dict[str, dict[str, dict[str, Ann]]]]
    ) -> "AdjRIBsOut":
        """Returns a AdjRIBsOut from a JSON representation"""

        adj_ribs_out = cls()
        for neighbor_asn, prefix_anns in json.items():
            for _prefix, ann_json in prefix_anns.items():
                adj_ribs_out.add_ann(neighbor_asn, Ann.from_json(ann_json))
        return adj_ribs_out

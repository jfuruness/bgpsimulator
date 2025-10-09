from typing import Any

from .as_graph_utils import ASGraphUtils
from .base_as import AS


class ASGraph:
    """BGP Topology"""

    def __eq__(self, other) -> bool:
        if isinstance(other, ASGraph):
            return self.as_dict == other.as_dict
        else:
            return NotImplemented

    ##############
    # Init Funcs #
    ##############

    def __init__(
        self,
        graph_data: dict[str, Any],
    ) -> None:
        """Reads in relationship data from a JSON and generate graph"""

        # Always add cycles, provider cones, and propagation ranks
        # if it hasn't been done already
        ASGraphUtils.add_extra_setup(graph_data)
        # populate basic info
        self.as_dict = {
            int(asn): AS.from_json(info, as_graph=self)
            for asn, info in graph_data["ases"].items()
        }
        # Populate ASN groups
        self.asn_groups = {
            asn_group_key: {int(x) for x in asn_group}
            for asn_group_key, asn_group in graph_data["asn_groups"].items()
        }
        # populate objects
        self._populate_objects()
        # Add propagation ranks
        self.propagation_ranks: list[list[AS]] = [
            [self.as_dict[int(asn)] for asn in rank]
            for rank in graph_data["propagation_rank_asns"]
        ]

    def _populate_objects(self) -> None:
        """Populates the AS objects with the relationships"""
        for _asn, as_obj in self.as_dict.items():
            as_obj.set_relations()

    ##################
    # Iterator funcs #
    ##################

    # https://stackoverflow.com/a/7542261/8903959
    def __getitem__(self, asn: int) -> AS:
        return self.as_dict[asn]

    def __iter__(self):
        return iter(self.as_dict.values())

    def __len__(self) -> int:
        return len(self.as_dict)

    ##############
    # JSON funcs #
    ##############

    def to_json(self) -> dict[str, Any]:
        """Converts the ASGraph to a JSON object"""

        return {
            "ases": {asn: as_obj.to_json() for asn, as_obj in self.as_dict.items()},
            "asn_groups": {
                asn_group_key: sorted(asn_group)
                for asn_group_key, asn_group in self.asn_groups.items()
            },
            "extra_setup_complete": True,
            "cycles_detected": False,
            "propagation_rank_asns": [
                [x.asn for x in rank] for rank in self.propagation_ranks
            ],
        }

    @classmethod
    def from_json(cls, json_obj: dict[str, Any]) -> "ASGraph":
        """Converts the ASGraph to a JSON object"""

        # Convert back to sets
        json_obj["asn_groups"] = {
            asn_group_key: {int(x) for x in asn_group}
            for asn_group_key, asn_group in json_obj.get("asn_groups", dict()).items()
        }
        json_obj["ases"] = {
            int(asn): as_json for asn, as_json in json_obj.get("ases", dict()).items()
        }
        json_obj["propagation_rank_asns"] = [
            [int(x) for x in rank] for rank in json_obj.get("propagation_rank_asns", [])
        ]
        return cls(json_obj)

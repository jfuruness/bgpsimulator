from .base_as import AS
from .as_graph_utils import ASGraphUtils
from typing import Any
from weakref import proxy

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

        # Always add cycles, provider cones, and propagation ranks if it hasn't been done already
        ASGraphUtils.add_extra_setup(graph_data)
        # populate basic info
        self.as_dict = {asn: AS(as_graph=self, **info) for asn, info in graph_data["ases"].items()}
        # Populate ASN groups
        self.asn_groups = {asn_group_key: set(asn_group) for asn_group_key, asn_group in graph_data["asn_groups"].items()}
        # populate objects
        self._populate_objects()
        # Add propagation ranks
        self.propagation_ranks = [
            [self.as_dict[asn] for asn in rank] for rank in graph_data["propagation_ranks"]
        ]

    def _populate_objects(self) -> None:
        """Populates the AS objects with the relationships"""
        for asn, as_obj in self.as_dict.items():
            as_obj.set_relations()

    ##################
    # Iterator funcs #
    ##################

    # https://stackoverflow.com/a/7542261/8903959
    def __getitem__(self, index: int) -> AS:
        return self.ases[index]

    def __len__(self) -> int:
        return len(self.as_dict)

    ##############
    # JSON funcs #
    ##############

    def to_json(self) -> dict[str, Any]:
        """Converts the ASGraph to a JSON object"""

        return {
            "ases": {asn: as_obj.to_json() for asn, as_obj in self.as_dict.items()},
            "asn_groups": {asn_group_key: set(asn_group) for asn_group_key, asn_group in self.asn_groups.items()},
            "extra_setup_complete": True,
            "cycles_detected": False,
            "propagation_ranks": [[x.asn for x in rank] for rank in self.propagation_ranks],
        }

    @classmethod
    def from_json(cls, json_obj: dict[str, Any]) -> "ASGraph":
        """Converts the ASGraph to a JSON object"""

        return cls(json_obj)
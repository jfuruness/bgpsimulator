from .base_as import AS
from frozendict import frozendict
from typing import Any
from weakref import proxy

class ASGraph:
    """BGP Topology"""

    def __eq__(self, other) -> bool:
        if isinstance(other, ASGraph):
            return self.to_json() == other.to_json()
        else:
            return NotImplemented

    ##############
    # Init Funcs #
    ##############

    def __init__(
        self,
        graph_data: dict[int, dict[str, Any]],
    ) -> None:
        """Reads in relationship data from a JSON and generate graph"""

        # populate basic info
        self.as_dict = {asn: AS(as_graph=self, **info) for asn, info in graph_data["ases"].items()}
        # populate objects
        self._populate_objects()
        # Always add cycles, provider cones, and propagation ranks if it hasn't been done already
        ASGraphUtils.add_extra_setup(graph_data)

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
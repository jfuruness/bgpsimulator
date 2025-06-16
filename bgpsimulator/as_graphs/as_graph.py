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
        graph_data_cache_path: Path | None = None,
    ) -> None:
        """Reads in relationship data from a JSON and generate graph"""

        # populate basic info
        self.as_dict = {asn: AS(**info) for asn, info in graph_data["ases"].items()}

        # populate objects
        self._populate_objects()
        # Store extra info (prop rank, provider_cones, cycles) if not done already
        self._store_extra_info(graph_data, graph_data_cache_path)
        self._assign_extra_info()

    def _populate_objects(self) -> None:
        """Populates the AS objects with the relationships"""
        for asn, as_obj in self.as_dict.items():
            as_obj.peers = set([self.as_dict[asn] for asn in as_obj.peers])
            as_obj.customers = set([self.as_dict[asn] for asn in as_obj.customers])
            as_obj.providers = set([self.as_dict[asn] for asn in as_obj.providers])
            as_obj.as_graph = proxy(self)

    def _store_extra_info(self, graph_data: dict[int, dict[str, Any]], graph_data_cache_path: Path | None) -> None:
        """Stores extra info (prop rank, provider_cones, cycles) if not done already"""

        if graph_data["extra_setup_complete"]:
            return
        else:
            raise NotImplementedError("prop rank, provider cones, cycles and store in cache")
        
    def _assign_extra_info(self) -> None:
        """Assigns extra info (prop rank, provider_cones, cycles) to the AS objects"""

        raise NotImplementedError("prop rank, provider cones, cycles and assign to AS objects")

    ##################
    # Iterator funcs #
    ##################

    # https://stackoverflow.com/a/7542261/8903959
    def __getitem__(self, index: int) -> AS:
        return self.ases[index]

    def __len__(self) -> int:
        return len(self.as_dict)
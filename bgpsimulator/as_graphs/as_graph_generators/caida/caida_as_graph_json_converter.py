import json
from pathlib import Path
from typing import Any, Callable

from frozendict import frozendict

from bgpsimulator.as_graphs.as_graph import AS, ASGraphUtils
from bgpsimulator.shared import SINGLE_DAY_CACHE_DIR, bgpsimulator_logger
from bgpsimulator.simulation_engine.policy import Policy

from .caida_as_graph_collector import CAIDAASGraphCollector


class CAIDAASGraphJSONConverter:
    """Converts the serial-2 to a JSON file that can be ingested to create a graph"""

    def __init__(self, cache_dir: Path = SINGLE_DAY_CACHE_DIR) -> None:
        self.cache_dir: Path = cache_dir

    def run(
        self,
        caida_as_graph_path: Path | None = None,
        additional_asn_group_filters: frozendict[
            str, Callable[[dict[int, AS]], frozenset[int]]
        ] = frozendict(),
        PolicyCls: type[Policy] = Policy,
    ) -> tuple[dict[str, Any], Path]:
        """Generates AS graph in the following steps:

        1. download file from source using the GraphCollector if you haven't already
        2. Convert the CAIDA file to JSON
        3. Write to JSON path if it is set
        4. Return JSON info for speed (rather than rereading it later)
        """

        caida_as_graph_path = caida_as_graph_path or CAIDAASGraphCollector().run()
        # /home/anon/.cache/bgpsimulator/2025-06-24/
        # CAIDAASGraphCollector_2025.06.14.json
        json_cache_path = caida_as_graph_path.with_suffix(".json")
        if not json_cache_path.exists():
            self._write_as_graph_json(
                caida_as_graph_path,
                json_cache_path,
                additional_asn_group_filters,
                PolicyCls,
            )
        try:
            as_graph_info = json.loads(json_cache_path.read_text())
            # Must convert keys to ints when coming from JSON
            as_graph_info["ases"] = {
                int(asn): info for asn, info in as_graph_info["ases"].items()
            }
            return as_graph_info, json_cache_path
        except json.JSONDecodeError:
            bgpsimulator_logger.error(
                f"JSON file {json_cache_path} is corrupted, it will now be deleted"
            )
            json_cache_path.unlink()
            raise

    def _write_as_graph_json(
        self,
        caida_as_graph_path: Path,
        json_cache_path: Path,
        additional_asn_group_filters: frozendict[
            str, Callable[[dict[int, AS]], frozenset[int]]
        ],
        PolicyCls: type[Policy],
    ) -> None:
        """Writes as graph JSON from CAIDAs raw file"""

        asn_to_as: dict[int, AS] = dict()
        lines = caida_as_graph_path.read_text().splitlines()
        for line in lines:
            # Get Caida input clique. See paper on site for what this is
            if line.startswith("# input clique"):
                self._extract_tier_1_asns(line, asn_to_as)
            # Get detected Caida IXPs. See paper on site for what this is
            elif line.startswith("# IXP ASes"):
                self._extract_ixp_asns(line, asn_to_as)
            # Not a comment, must be a relationship
            elif not line.startswith("#"):
                # Extract all customer provider pairs
                if "-1" in line:
                    self._extract_provider_customers(line, asn_to_as)
                # Extract all peers
                else:
                    self._extract_peers(line, asn_to_as)

        final_json: dict[str, Any] = {
            "ases": {k: as_.to_json() for k, as_ in asn_to_as.items()},
        }
        ASGraphUtils.add_extra_setup(final_json, additional_asn_group_filters)

        with json_cache_path.open("w") as f:
            # add separators to make JSON as short as possible
            # ensure_ascii set to false also gives a speed boost
            json.dump(final_json, f, separators=(",", ":"), ensure_ascii=False)

    #################
    # Parsing funcs #
    #################

    def _extract_tier_1_asns(self, line: str, asn_to_as: dict[int, AS]) -> None:
        """Adds all ASNs within input clique line to ases dict"""

        # Gets all input ASes for clique
        for asn in line.split(":")[-1].strip().split(" "):
            as_ = asn_to_as.setdefault(int(asn), AS(asn=int(asn)))
            as_.tier_1 = True

    def _extract_ixp_asns(self, line: str, asn_to_as: dict[int, AS]) -> None:
        """Adds all ASNs that are detected IXPs to ASes dict"""

        # Get all IXPs that Caida lists
        for asn in line.split(":")[-1].strip().split(" "):
            as_ = asn_to_as.setdefault(int(asn), AS(asn=int(asn)))
            as_.ixp = True

    def _extract_provider_customers(self, line: str, asn_to_as: dict[int, AS]) -> None:
        """Extracts provider customers: <provider-as>|<customer-as>|-1"""

        provider_asn, customer_asn, _, source = line.split("|")

        provider_as = asn_to_as.setdefault(int(provider_asn), AS(asn=int(provider_asn)))
        provider_as.customer_asns.add(int(customer_asn))

        customer_as = asn_to_as.setdefault(int(customer_asn), AS(asn=int(customer_asn)))
        customer_as.provider_asns.add(int(provider_asn))

    def _extract_peers(self, line: str, asn_to_as: dict[int, AS]) -> None:
        """Extracts peers: <peer-as>|<peer-as>|0|<source>"""

        peer1_asn, peer2_asn, _, source = line.split("|")

        peer1_as = asn_to_as.setdefault(int(peer1_asn), AS(asn=int(peer1_asn)))
        peer1_as.peer_asns.add(int(peer2_asn))

        peer2_as = asn_to_as.setdefault(int(peer2_asn), AS(asn=int(peer2_asn)))
        peer2_as.peer_asns.add(int(peer1_asn))

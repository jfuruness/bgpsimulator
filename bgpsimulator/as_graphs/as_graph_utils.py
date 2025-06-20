from typing import Any

from bgpsimulator.shared import CycleError


class ASGraphUtils:
    """Utility functions for ASGraph"""

    @staticmethod
    def add_extra_setup(as_graph_json: dict[int, dict[str, Any]]) -> None:
        """Adds cycles, provider cone, and propagation ranks to the AS graph"""

        if not as_graph_json.get("extra_setup_complete", False):
            ASGraphUtils.check_for_cycles(as_graph_json)
            ASGraphUtils.add_provider_cone_asns(as_graph_json)
            ASGraphUtils.assign_as_propagation_rank(as_graph_json)
            ASGraphUtils.assign_as_graph_propagation_ranks(as_graph_json)
            as_graph_json["extra_setup_complete"] = True

    ###############
    # Cycle funcs #
    ###############

    @staticmethod
    def check_for_cycles(as_graph_json: dict[int, dict[str, Any]]) -> None:
        """Checks for cycles in the AS graph"""

        # Apply cycle detection to each node in the graph
        for key in ("provider_asns", "customer_asns"):
            visited = set()  # To track nodes that have been fully processed
            rec_stack = set()  # Tracks current recursion stack (for cycle detection)

            for asn, as_info in as_graph_json["ases"].items():
                if asn not in visited:
                    ASGraphUtils._validate_no_cycles_helper(
                        asn, as_info, as_graph_json, visited, rec_stack, key
                    )
        as_graph_json["cycles_detected"] = False

    @staticmethod
    def _validate_no_cycles_helper(
        asn: int,
        as_info: dict[str, Any],
        as_graph_json: dict[int, dict[str, Any]],
        visited: set[int],
        rec_stack: set[int],
        key: str,
    ) -> None:
        """Helper function to detect cycles using DFS"""

        if asn not in visited:
            visited.add(asn)
            rec_stack.add(asn)

            # Visit all the providers (similar to graph neighbors) recursively
            for neighbor_asn in as_info[key]:
                if neighbor_asn not in visited:
                    ASGraphUtils._validate_no_cycles_helper(
                        neighbor_asn, as_graph_json["ases"][neighbor_asn], as_graph_json, visited, rec_stack, key
                    )
                elif neighbor_asn in rec_stack:
                    raise CycleError(f"Cycle detected in {key} for AS {asn}")

        rec_stack.remove(asn)

    #################
    # Provider cone #
    #################

    @staticmethod
    def add_provider_cone_asns(as_graph_json: dict[int, dict[str, Any]]) -> None:
        """Adds provider cone ASNs to the AS graph"""

        cone_dict: dict[int, set[int]] = {}
        for asn, as_info in as_graph_json["ases"].items():
            provider_cone: set[int] = ASGraphUtils._get_cone_helper(
                as_info, cone_dict, as_graph_json, "provider_asns"
            )
            as_info["provider_cone_asns"] = list(provider_cone)


    @staticmethod
    def _get_cone_helper(
        as_info: dict[str, Any],
        cone_dict: dict[int, set[int]],
        as_graph_json: dict[int, dict[str, Any]],
        rel_key: str,
    ) -> set[int]:
        """Recursively determines the cone of an AS"""

        as_asn = as_info["asn"]
        if as_asn in cone_dict:
            return cone_dict[as_asn]
        else:
            cone_dict[as_asn] = set()
            for neighbor_asn in as_info[rel_key]:
                cone_dict[as_asn].add(neighbor_asn)
                if neighbor_asn not in cone_dict:
                    ASGraphUtils._get_cone_helper(as_graph_json["ases"][neighbor_asn], cone_dict, as_graph_json, rel_key)
                cone_dict[as_asn].update(cone_dict[neighbor_asn])
        return cone_dict[as_asn]

    ##########################
    # Propagation rank funcs #
    ##########################

    @staticmethod
    def assign_as_propagation_rank(as_graph_json: dict[int, dict[str, Any]]) -> None:
        """Adds propagation rank from the leafs to the input clique"""

        for as_info in as_graph_json["ases"].values():
            # Always set this to None since you can't trust this value
            as_info["propagation_rank"] = None
            ASGraphUtils._assign_ranks_helper(as_info, 0, as_graph_json)


    @staticmethod
    def _assign_ranks_helper(as_info: dict[str, Any], rank: int, as_graph_json: dict[int, dict[str, Any]]) -> None:
        """Assigns ranks to all ases in customer/provider chain recursively"""

        if as_info["propagation_rank"] is None or as_info["propagation_rank"] < rank:
            as_info["propagation_rank"] = rank
            # Only update it's providers if it's rank becomes higher
            # This avoids a double for loop of writes
            for provider_asn in as_info["provider_asns"]:
                ASGraphUtils._assign_ranks_helper(as_graph_json["ases"][provider_asn], rank + 1, as_graph_json)

    @staticmethod
    def assign_as_graph_propagation_ranks(as_graph_json: dict[int, dict[str, Any]]) -> None:
        """Orders ASes by rank"""

        max_rank: int = max(x["propagation_rank"] for x in as_graph_json["ases"].values())
        # Create a list of empty lists
        # Ignore types here for speed purposes
        ranks: list[list[int]] = [list() for _ in range(max_rank + 1)]
        # Append the ASes into their proper rank
        for asn, as_info in as_graph_json["ases"].items():
            ranks[as_info["propagation_rank"]].append(asn)

        # Create tuple ranks
        as_graph_json["propagation_rank_asns"] = [list(sorted(rank)) for rank in ranks]
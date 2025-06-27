from typing import Any, Callable

from frozendict import frozendict

from bgpsimulator.shared import ASNGroups, CycleError

from .base_as import AS


class ASGraphUtils:
    """Utility functions for ASGraph"""

    @staticmethod
    def add_extra_setup(
        as_graph_json: dict[str, Any],
        additional_asn_group_filters: frozendict[
            str, Callable[[dict[int, AS]], frozenset[int]]
        ] = frozendict(),
    ) -> None:
        """Adds cycles, provider cone, asn_groups, and propagation ranks
        to the AS graph
        """

        if not as_graph_json.get("extra_setup_complete", False):
            # Conver to ints when pulling from JSON
            as_graph_json["ases"] = {
                int(asn): info for asn, info in as_graph_json["ases"].items()
            }
            ASGraphUtils.check_for_cycles(as_graph_json)
            ASGraphUtils.add_provider_cone_asns(as_graph_json)
            ASGraphUtils.assign_as_propagation_rank(as_graph_json)
            ASGraphUtils.assign_as_graph_propagation_ranks(as_graph_json)
            ASGraphUtils.add_asn_groups(as_graph_json, additional_asn_group_filters)
            as_graph_json["extra_setup_complete"] = True

    ###############
    # Cycle funcs #
    ###############

    @staticmethod
    def check_for_cycles(as_graph_json: dict[str, Any]) -> None:
        """Checks for cycles in the AS graph"""

        # Apply cycle detection to each node in the graph
        for key in ("provider_asns", "customer_asns"):
            visited: set[int] = set()  # To track nodes that have been fully processed
            rec_stack: set[int] = (
                set()
            )  # Tracks current recursion stack (for cycle detection)

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
        as_graph_json: dict[str, Any],
        visited: set[int],
        rec_stack: set[int],
        key: str,
    ) -> None:
        """Helper function to detect cycles using DFS"""

        if asn not in visited:
            visited.add(asn)
            rec_stack.add(asn)

            # Visit all the providers (similar to graph neighbors) recursively
            for neighbor_asn in as_info.get(key, []):
                if neighbor_asn not in visited:
                    ASGraphUtils._validate_no_cycles_helper(
                        neighbor_asn,
                        as_graph_json["ases"][neighbor_asn],
                        as_graph_json,
                        visited,
                        rec_stack,
                        key,
                    )
                elif neighbor_asn in rec_stack:
                    raise CycleError(f"Cycle detected in {key} for AS {asn}")

        rec_stack.remove(asn)

    #################
    # Provider cone #
    #################

    @staticmethod
    def add_provider_cone_asns(as_graph_json: dict[str, Any]) -> None:
        """Adds provider cone ASNs to the AS graph"""

        cone_dict: dict[int, set[int]] = {}
        for _asn, as_info in as_graph_json["ases"].items():
            provider_cone: set[int] = ASGraphUtils._get_cone_helper(
                as_info, cone_dict, as_graph_json, "provider_asns"
            )
            as_info["provider_cone_asns"] = list(provider_cone)

    @staticmethod
    def _get_cone_helper(
        as_info: dict[str, Any],
        cone_dict: dict[int, set[int]],
        as_graph_json: dict[str, Any],
        rel_key: str,
    ) -> set[int]:
        """Recursively determines the cone of an AS"""

        as_asn = as_info["asn"]
        if as_asn in cone_dict:
            return cone_dict[as_asn]
        else:
            cone_dict[as_asn] = set()
            for neighbor_asn in as_info.get(rel_key, []):
                cone_dict[as_asn].add(neighbor_asn)
                if neighbor_asn not in cone_dict:
                    ASGraphUtils._get_cone_helper(
                        as_graph_json["ases"][neighbor_asn],
                        cone_dict,
                        as_graph_json,
                        rel_key,
                    )
                cone_dict[as_asn].update(cone_dict[neighbor_asn])
        return cone_dict[as_asn]

    ##########################
    # Propagation rank funcs #
    ##########################

    @staticmethod
    def assign_as_propagation_rank(as_graph_json: dict[str, Any]) -> None:
        """Adds propagation rank from the leafs to the input clique"""

        for as_info in as_graph_json["ases"].values():
            # Always set this to None since you can't trust this value
            as_info["propagation_rank"] = None
        for as_info in as_graph_json["ases"].values():
            ASGraphUtils._assign_ranks_helper(as_info, 0, as_graph_json)

    @staticmethod
    def _assign_ranks_helper(
        as_info: dict[str, Any], rank: int, as_graph_json: dict[str, Any]
    ) -> None:
        """Assigns ranks to all ases in customer/provider chain recursively"""

        if (
            as_info.get("propagation_rank") is None
            or as_info["propagation_rank"] < rank
        ):
            as_info["propagation_rank"] = rank
            # Only update it's providers if it's rank becomes higher
            # This avoids a double for loop of writes
            for provider_asn in as_info.get("provider_asns", []):
                ASGraphUtils._assign_ranks_helper(
                    as_graph_json["ases"][provider_asn], rank + 1, as_graph_json
                )

    @staticmethod
    def assign_as_graph_propagation_ranks(
        as_graph_json: dict[str, Any],
    ) -> None:
        """Orders ASes by rank"""

        max_rank: int = max(
            x["propagation_rank"] for x in as_graph_json["ases"].values()
        )
        # Create a list of empty lists
        # Ignore types here for speed purposes
        ranks: list[list[int]] = [list() for _ in range(max_rank + 1)]
        # Append the ASes into their proper rank
        for asn, as_info in as_graph_json["ases"].items():
            ranks[as_info["propagation_rank"]].append(asn)

        # Create tuple ranks
        as_graph_json["propagation_rank_asns"] = [sorted(rank) for rank in ranks]

    ####################
    # ASN groups funcs #
    ####################

    @staticmethod
    def add_asn_groups(
        as_graph_json: dict[str, Any],
        additional_asn_group_filters: frozendict[
            str, Callable[[dict[int, AS]], frozenset[int]]
        ],
    ) -> None:
        """Gets ASN groups. Used for choosing attackers from stubs, adopters, etc."""

        asn_to_as: dict[int, AS] = {
            asn: AS.from_json(as_info) for asn, as_info in as_graph_json["ases"].items()
        }

        asn_group_filters: dict[str, Callable[[dict[int, AS]], frozenset[int]]] = dict(
            **ASGraphUtils.get_default_as_group_filters(),
            **additional_asn_group_filters,
        )

        asn_groups: frozendict[str, frozenset[int]] = frozendict(
            {
                asn_group_key: filter_func(asn_to_as)
                for asn_group_key, filter_func in asn_group_filters.items()
            }
        )

        as_graph_json["asn_groups"] = {
            k: list(asn_group) for k, asn_group in asn_groups.items()
        }

    @staticmethod
    def get_default_as_group_filters() -> dict[
        str, Callable[[dict[int, AS]], frozenset[int]]
    ]:
        """Returns the default filter functions for AS groups"""

        def ixp_filter(asn_to_as: dict[int, AS]) -> frozenset[int]:
            return frozenset(asn for asn, as_ in asn_to_as.items() if as_.ixp)

        def stub_no_ixp_filter(asn_to_as: dict[int, AS]) -> frozenset[int]:
            return frozenset(
                asn for asn, as_ in asn_to_as.items() if as_.stub and not as_.ixp
            )

        def multihomed_no_ixp_filter(asn_to_as: dict[int, AS]) -> frozenset[int]:
            return frozenset(
                asn for asn, as_ in asn_to_as.items() if as_.multihomed and not as_.ixp
            )

        def stubs_or_multihomed_no_ixp_filter(
            asn_to_as: dict[int, AS],
        ) -> frozenset[int]:
            return frozenset(
                asn
                for asn, as_ in asn_to_as.items()
                if (as_.stub or as_.multihomed) and not as_.ixp
            )

        def tier_1_no_ixp_filter(asn_to_as: dict[int, AS]) -> frozenset[int]:
            return frozenset(
                asn for asn, as_ in asn_to_as.items() if as_.tier_1 and not as_.ixp
            )

        def etc_no_ixp_filter(asn_to_as: dict[int, AS]) -> frozenset[int]:
            return frozenset(
                asn
                for asn, as_ in asn_to_as.items()
                if not (as_.stub or as_.multihomed or as_.tier_1 or as_.ixp)
            )

        def transit_no_ixp_filter(asn_to_as: dict[int, AS]) -> frozenset[int]:
            return frozenset(
                asn for asn, as_ in asn_to_as.items() if as_.transit and not as_.ixp
            )

        def all_no_ixp_filter(asn_to_as: dict[int, AS]) -> frozenset[int]:
            return frozenset(asn_to_as.keys())

        return {
            ASNGroups.IXPS: ixp_filter,
            ASNGroups.STUBS: stub_no_ixp_filter,
            ASNGroups.MULTIHOMED: multihomed_no_ixp_filter,
            ASNGroups.STUBS_OR_MH: stubs_or_multihomed_no_ixp_filter,
            ASNGroups.TIER_1: tier_1_no_ixp_filter,
            ASNGroups.ETC: etc_no_ixp_filter,
            ASNGroups.TRANSIT: transit_no_ixp_filter,
            ASNGroups.ALL_WOUT_IXPS: all_no_ixp_filter,
        }

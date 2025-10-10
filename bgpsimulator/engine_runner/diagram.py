from collections import defaultdict, deque
from pathlib import Path
from typing import TYPE_CHECKING

from graphviz import Digraph

from bgpsimulator.shared import Outcomes, Settings
from bgpsimulator.simulation_engine import SimulationEngine
from bgpsimulator.simulation_framework import Scenario

if TYPE_CHECKING:
    from bgpsimulator.as_graphs import AS


class Diagram:
    """Generates a diagram of the engine run"""

    def __init__(self) -> None:
        self.dot: Digraph = Digraph(format="png")

    def run(
        self,
        engine: SimulationEngine,
        scenario: Scenario,
        packet_outcomes: dict[int, Outcomes],
        name: str,
        description: str,
        diagram_ranks: list[list[int]],
        path: Path,
        view: bool = False,
        dpi: int | None = None,
    ) -> None:
        """Runs the diagram"""
        self._add_legend(packet_outcomes, scenario)
        display_full_prefix_bool = self._get_display_full_prefix_bool(scenario)
        self._add_ases(engine, packet_outcomes, scenario, display_full_prefix_bool)
        self._add_edges(engine)
        diagram_ranks = diagram_ranks or self._get_default_diagram_ranks(engine)
        self._add_diagram_ranks(diagram_ranks, engine)
        self._add_description(name, description)
        self._render(path=path, view=view, dpi=dpi)

    def _add_legend(
        self, packet_outcomes: dict[int, Outcomes], scenario: Scenario
    ) -> None:
        """Adds legend to the graph with outcome counts"""

        attacker_success_count = sum(
            1 for x in packet_outcomes.values() if x == Outcomes.ATTACKER_SUCCESS.value
        )
        victim_success_count = sum(
            1
            for x in packet_outcomes.values()
            if x == Outcomes.LEGITIMATE_ORIGIN_SUCCESS.value
        )
        disconnect_count = sum(
            1 for x in packet_outcomes.values() if x == Outcomes.DISCONNECTED.value
        )
        looping_count = sum(
            1 for x in packet_outcomes.values() if x == Outcomes.DATA_PLANE_LOOP.value
        )
        html = f"""<
              <TABLE BORDER="0" CELLBORDER="1" CELLSPACING="0" CELLPADDING="4">
              <TR>
          <TD COLSPAN="2" BORDER="0">(For Destination of {scenario.dest_ip_addr})</TD>
              </TR>
              <TR>
          <TD BGCOLOR="#ff6060:white">&#128520; ATTACKER SUCCESS &#128520;</TD>
                <TD>{attacker_success_count}</TD>
              </TR>
              <TR>
         <TD BGCOLOR="#90ee90:white">&#128519; LEGITIMATE ORIGIN SUCCESS &#128519;</TD>
                <TD>{victim_success_count}</TD>
              </TR>
        """
        if disconnect_count:
            html += f"""
            <TR>
            <TD BGCOLOR="grey:white">&#10041; DISCONNECTED &#10041;</TD>
                    <TD>{disconnect_count}</TD>
                  </TR>
            """
        if looping_count:
            html += f"""
            <TR>
            <TD BGCOLOR="yellow:white">&#8734; LOOPING &#8734;</TD>
                    <TD>{disconnect_count}</TD>
                  </TR>
            """

        # ROAs takes up the least space right underneath the legend
        # which is why we have this here instead of a separate node
        html += """
              <TR>
                <TD COLSPAN="2" BORDER="0">ROAs (prefix, origin, max_len)</TD>
              </TR>
              """
        for roa in scenario.roas:
            html += f"""
              <TR>
                <TD>{roa.prefix}</TD>
                <TD>{roa.origin}</TD>
                <TD>{roa.max_length}</TD>
              </TR>"""
        html += """</TABLE>>"""

        self.dot.node(
            "Legend",
            html,
            shape="plaintext",
            color="black",
            style="filled",
            fillcolor="white",
        )

    def _get_display_full_prefix_bool(self, scenario: Scenario) -> bool:
        """If there are multiple prefixes for the same prefixlen, display full prefix

        else just display the prefix len as an abbreviation
        """

        prefix_len_to_addr = defaultdict(set)
        for asn, anns_list in scenario.seed_asn_ann_dict.items():
            for ann in anns_list:
                prefix_len_to_addr[ann.prefix.prefixlen].add(ann.prefix.network_address)
        return any(len(v) > 1 for v in prefix_len_to_addr.values())

    def _add_ases(
        self,
        engine: SimulationEngine,
        packet_outcomes: dict[int, Outcomes],
        scenario: Scenario,
        display_full_prefix_bool: bool,
    ) -> None:
        """Adds the ASes to the graph"""

        # First add all nodes to the graph
        for as_obj in engine.as_graph:
            self._encode_as_obj_as_node(
                as_obj, engine, packet_outcomes, scenario, display_full_prefix_bool
            )

    def _encode_as_obj_as_node(
        self,
        as_obj: "AS",
        engine: SimulationEngine,
        packet_outcomes: dict[int, Outcomes],
        scenario: Scenario,
        display_full_prefix_bool: bool,
    ) -> None:
        kwargs = dict()

        html = self._get_html(
            as_obj, engine, packet_outcomes, scenario, display_full_prefix_bool
        )

        kwargs = self._get_kwargs(as_obj, engine, packet_outcomes, scenario)

        self.dot.node(str(as_obj.asn), html, **kwargs)

    def _get_html(
        self,
        as_obj: "AS",
        engine: SimulationEngine,
        packet_outcomes: dict[int, Outcomes],
        scenario: Scenario,
        display_full_prefix_bool: bool,
    ) -> str:
        colspan = 3
        asn_str = str(as_obj.asn)
        if as_obj.asn in scenario.legitimate_origin_asns:
            asn_str = "&#128519;" + asn_str + "&#128519;"
        elif as_obj.asn in scenario.attacker_asns:
            asn_str = "&#128520;" + asn_str + "&#128520;"

        used_settings = [
            setting
            for setting, value in zip(Settings, as_obj.policy.settings, strict=False)
            if value and setting != Settings.BGP_FULL
        ]

        html = f"""<
            <TABLE BORDER="0" CELLBORDER="1" CELLSPACING="0" CELLPADDING="{colspan}">
            <TR>
            <TD COLSPAN="{colspan}" BORDER="0">{asn_str}</TD>
            </TR>
            """
        for setting in used_settings:
            html += f"""
            <TR>
            <TD COLSPAN="{colspan}" BORDER="0">({setting.name})</TD>
            </TR>"""
        local_rib_anns = tuple(as_obj.policy.local_rib.values())
        local_rib_anns = tuple(
            sorted(
                local_rib_anns,
                key=lambda x: x.prefix.num_addresses,
                reverse=True,
            )
        )
        if len(local_rib_anns) > 0:
            html += f"""<TR>
                        <TD COLSPAN="{colspan}">Local RIB</TD>
                      </TR>"""

            for ann in local_rib_anns:
                if display_full_prefix_bool:
                    prefix_display = str(ann.prefix)
                else:
                    prefix_display = "/" + str(ann.prefix).split("/")[-1]
                path = "-".join(str(x) for x in ann.as_path)
                html += f"""<TR>
                            <TD COLSPAN="1">{prefix_display}</TD>
                            <TD COLSPAN="2">{path}</TD>
                            """
                html += """</TR>"""
        html += "</TABLE>>"
        return html

    def _get_kwargs(
        self,
        as_obj: "AS",
        engine: SimulationEngine,
        packet_outcomes: dict[int, Outcomes],
        scenario: Scenario,
    ) -> dict[str, str]:
        kwargs = {
            "color": "black",
            "style": "filled",
            "fillcolor": "white",
            "gradientangle": "270",
        }

        # If the as obj is the attacker
        if as_obj.asn in scenario.attacker_asns:
            kwargs.update({"fillcolor": "#ff6060", "shape": "doublecircle"})
            if any(
                v
                for k, v in zip(Settings, as_obj.policy.settings, strict=False)
                if v and k != Settings.BGP_FULL
            ):
                kwargs["shape"] = "doubleoctagon"
            # If people complain about the red being too dark lol:
            kwargs.update({"fillcolor": "#FF7F7F"})
            # kwargs.update({"fillcolor": "#ff4d4d"})
        # As obj is the victim
        elif as_obj.asn in scenario.legitimate_origin_asns:
            kwargs.update({"fillcolor": "#90ee90", "shape": "doublecircle"})
            if any(
                v
                for k, v in zip(Settings, as_obj.policy.settings, strict=False)
                if v and k != Settings.BGP_FULL
            ):
                kwargs["shape"] = "doubleoctagon"

        # As obj is not attacker or victim
        else:
            if packet_outcomes[as_obj.asn] == Outcomes.ATTACKER_SUCCESS.value:
                kwargs.update({"fillcolor": "#ff6060:yellow"})
            elif (
                packet_outcomes[as_obj.asn] == Outcomes.LEGITIMATE_ORIGIN_SUCCESS.value
            ):
                kwargs.update({"fillcolor": "#90ee90:white"})
            elif packet_outcomes[as_obj.asn] == Outcomes.DISCONNECTED.value:
                kwargs.update({"fillcolor": "grey:white"})
            elif packet_outcomes[as_obj.asn] == Outcomes.DATA_PLANE_LOOP.value:
                kwargs.update({"fillcolor": "yellow:white"})

            if any(
                v
                for k, v in zip(Settings, as_obj.policy.settings, strict=False)
                if v and k != Settings.BGP_FULL
            ):
                kwargs["shape"] = "octagon"
        return kwargs

    def _add_edges(self, engine: SimulationEngine):
        # Then add all connections to the graph
        # Starting with provider to customer
        for as_obj in engine.as_graph:
            # Add provider customer edges
            for customer_obj in as_obj.customers:
                self.dot.edge(str(as_obj.asn), str(customer_obj.asn))
            # Add peer edges
            # Only add if the largest asn is the curren as_obj to avoid dups
            for peer_obj in as_obj.peers:
                if as_obj.asn > peer_obj.asn:
                    self.dot.edge(
                        str(as_obj.asn),
                        str(peer_obj.asn),
                        dir="none",
                        style="dashed",
                        penwidth="2",
                    )

    def _get_default_diagram_ranks(self, engine) -> list[list[int]]:
        """
        Return ranks (list of ASN lists) for drawing the AS graph.

        * Peered ASNs share a rank.
        * A provider is always strictly above each customer.
        * Multihomed customers sit just below their highest provider.
        * Output ordering is deterministic.
        """
        # --------------------------------------------------------------
        # 1.  Gather raw edges (ASNs only, no AS objects)
        # --------------------------------------------------------------
        as_dict = engine.as_graph.as_dict  # dict[int, ASNode]
        peer_edges: set[tuple[int, int]] = set()
        provider_edges: set[tuple[int, int]] = set()  # (provider, customer)

        for asn, node in as_dict.items():
            # Peers (undirected) – store ints (node.peers is a set of AS-objects)
            for peer_obj in node.peers:
                peer_asn = peer_obj.asn
                if peer_asn in as_dict:  # ignore external ASNs
                    peer_edges.add(tuple(sorted((asn, peer_asn))))

            # Providers (directed) – provider ➜ customer (= asn)
            for prov_obj in node.providers:
                prov_asn = prov_obj.asn
                if prov_asn in as_dict:
                    provider_edges.add((prov_asn, asn))

        # --------------------------------------------------------------
        # 2.  Collapse peer clusters with Union–Find
        # --------------------------------------------------------------
        parent: dict[int, int] = {}

        def find(x: int) -> int:
            parent.setdefault(x, x)
            if parent[x] != x:
                parent[x] = find(parent[x])
            return parent[x]

        def union(a: int, b: int) -> None:
            pa, pb = find(a), find(b)
            if pa != pb:
                parent[pb] = pa

        for u, v in peer_edges:
            union(u, v)

        cluster_of = {asn: find(asn) for asn in as_dict}

        # --------------------------------------------------------------
        # 3.  Build provider-customer DAG between clusters
        # --------------------------------------------------------------
        children: dict[int, set[int]] = defaultdict(set)
        indeg: dict[int, int] = defaultdict(int)

        for prov_asn, cust_asn in provider_edges:
            cp, cc = cluster_of[prov_asn], cluster_of[cust_asn]
            if cp == cc:  # provider inside its own peer-cluster → ignore
                continue
            if cc not in children[cp]:
                children[cp].add(cc)
                indeg[cc] += 1

        all_clusters = set(cluster_of.values())
        rank: dict[int, int] = defaultdict(int)

        # --------------------------------------------------------------
        # 4.  Longest-path layering
        # --------------------------------------------------------------
        queue = deque(cl for cl in all_clusters if indeg[cl] == 0)

        while queue:
            cl = queue.popleft()
            for child in children.get(cl, ()):
                rank[child] = max(rank[child], rank[cl] + 1)
                indeg[child] -= 1
                if indeg[child] == 0:
                    queue.append(child)

        # Any cluster still showing indegree > 0 is in a cycle → push to top
        for cl, d in indeg.items():
            if d:  # d > 0
                rank[cl] = 0

        # --------------------------------------------------------------
        # 5.  Expand clusters back to ASNs and sort
        # --------------------------------------------------------------
        levels: dict[int, list[int]] = defaultdict(list)
        for asn, cl in cluster_of.items():
            levels[rank[cl]].append(asn)

        max_rank = max(levels) if levels else -1
        return [sorted(levels[r]) for r in range(max_rank + 1)]

    def _add_diagram_ranks(
        self, diagram_ranks: list[list[int]], engine: SimulationEngine
    ) -> None:
        # TODO: Refactor
        if diagram_ranks:
            for diagram_rank in diagram_ranks:
                with self.dot.subgraph() as s:
                    s.attr(rank="same")  # set all nodes to the same rank
                    previous_asn: str | None = None
                    for asn in diagram_rank:
                        assert isinstance(asn, int)
                        s.node(str(asn))
                        if previous_asn is not None:
                            # Add invisible edge to maintain static order
                            s.edge(str(previous_asn), str(asn), style="invis")
                        previous_asn = str(asn)
        else:
            for i, rank in enumerate(engine.as_graph.propagation_ranks):
                g = Digraph(f"Propagation_rank_{i}")
                g.attr(rank="same")
                for as_obj in rank:
                    g.node(str(as_obj.asn))
                self.dot.subgraph(g)

    def _add_description(self, name: str, description: str) -> None:
        if name or description:
            # https://stackoverflow.com/a/57461245/8903959
            self.dot.attr(label=f"{name}\n{description}")

    def _render(
        self, path: Path | None = None, view: bool = False, dpi: int | None = None
    ) -> None:
        if dpi:
            self.dot.attr(dpi=str(dpi))
        self.dot.render(path, view=view)

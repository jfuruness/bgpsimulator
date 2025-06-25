from pathlib import Path
from graphviz import Digraph

from bgpsimulator.simulation_engine import SimulationEngine
from bgpsimulator.simulation_framework import Scenario
from bgpsimulator.shared import Outcomes


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
        display_next_hop_asn = self._display_next_hop_asn(engine, scenario)
        self._add_ases(engine, packet_outcomes, scenario, display_next_hop_asn)
        self._add_edges(engine)
        self._add_diagram_ranks(diagram_ranks, engine)
        self._add_description(description, display_next_hop_asn)
        self._render(path=path, view=view, dpi=dpi)

    def _add_legend(self, packet_outcomes: dict[int, Outcomes], scenario: Scenario) -> None:
        """Adds legend to the graph with outcome counts"""

        attacker_success_count = sum(
            1 for x in packet_outcomes.values() if x == Outcomes.ATTACKER_SUCCESS.value
        )
        victim_success_count = sum(
            1 for x in packet_outcomes.values() if x == Outcomes.LEGITIMATE_ORIGIN_SUCCESS.value
        )
        disconnect_count = sum(
            1 for x in packet_outcomes.values() if x == Outcomes.DISCONNECTED.value
        )
        html = f"""<
              <TABLE BORDER="0" CELLBORDER="1" CELLSPACING="0" CELLPADDING="4">
              <TR>
          <TD COLSPAN="2" BORDER="0">(For most specific prefix only)</TD>
              </TR>
              <TR>
          <TD BGCOLOR="#ff6060:white">&#128520; ATTACKER SUCCESS &#128520;</TD>
                <TD>{attacker_success_count}</TD>
              </TR>
              <TR>
         <TD BGCOLOR="#90ee90:white">&#128519; LEGITIMATE ORIGIN SUCCESS &#128519;</TD>
                <TD>{victim_success_count}</TD>
              </TR>
              <TR>
                <TD BGCOLOR="grey:white">&#10041; DISCONNECTED &#10041;</TD>
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

        self.dot.node("Legend", html, shape="plaintext", color="black", style="filled", fillcolor="white")

    def _display_next_hop_asn(self, engine: SimulationEngine, scenario: Scenario) -> bool:
        """Displays the next hop ASN

        We want to display the next hop ASN any time it has been manipulated
        That only happens when the next_hop_asn is not equal to the as object's ASN
        (which occurs when the AS is the origin) or the next ASN in the path
        """

        for as_obj in engine.as_graph:
            for ann in as_obj.policy.local_rib.values():
                if (len(ann.as_path) == 1 and ann.as_path[0] != ann.next_hop_asn) or (
                    len(ann.as_path) > 1 and ann.as_path[1] != ann.next_hop_asn
                ):
                    return True
        return False

    def _add_ases(self, engine: SimulationEngine, packet_outcomes: dict[int, Outcomes], scenario: Scenario, display_next_hop_asn: bool) -> None:
        """Adds the ASes to the graph"""
        pass

        # First add all nodes to the graph
        for as_obj in engine.as_graph:
            self._encode_as_obj_as_node(
                as_obj, engine, packet_outcomes, scenario, display_next_hop_asn
            )

    def _encode_as_obj_as_node(
        self,
        as_obj: "AS",
        engine: SimulationEngine,
        packet_outcomes: dict[int, Outcomes],
        scenario: Scenario,
        display_next_hop_asn: bool,
    ) -> None:
        kwargs = dict()

        html = self._get_html(as_obj, engine, packet_outcomes, scenario, display_next_hop_asn)

        kwargs = self._get_kwargs(as_obj, engine, packet_outcomes, scenario)

        self.dot.node(str(as_obj.asn), html, **kwargs)

    def _get_html(
        self,
        as_obj: "AS",
        engine: SimulationEngine,
        packet_outcomes: dict[int, Outcomes],
        scenario: Scenario,
        display_next_hop_asn: bool,
    ) -> str:
        colspan = 5 if display_next_hop_asn else 4
        asn_str = str(as_obj.asn)
        if as_obj.asn in scenario.legitimate_origin_asns:
            asn_str = "&#128519;" + asn_str + "&#128519;"
        elif as_obj.asn in scenario.attacker_asns:
            asn_str = "&#128520;" + asn_str + "&#128520;"

        used_settings = [setting for setting, value in as_obj.policy.settings.items() if value]
        policy_str = "; ".join(str(x) for x in used_settings) if used_settings else "BGP"


        html = f"""<
            <TABLE BORDER="0" CELLBORDER="1" CELLSPACING="0" CELLPADDING="{colspan}">
            <TR>
            <TD COLSPAN="{colspan}" BORDER="0">{asn_str}</TD>
            </TR>
            <TR>
            <TD COLSPAN="{colspan}" BORDER="0">({policy_str})</TD>
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
                mask = "/" + str(ann.prefix).split("/")[-1]
                path = ", ".join(str(x) for x in ann.as_path)
                ann_help = ""
                if getattr(ann, "rovpp_blackhole", False):
                    ann_help = "&#10041;"
                elif getattr(ann, "preventive", False):
                    ann_help = "&#128737;"
                elif any(x in ann.as_path for x in scenario.attacker_asns):
                    ann_help = "&#128520;"
                elif any(x == ann.origin for x in scenario.legitimate_origin_asns):
                    ann_help = "&#128519;"
                else:
                    raise NotImplementedError

                html += f"""<TR>
                            <TD>{mask}</TD>
                            <TD>{path}</TD>
                            <TD>{ann_help}</TD>"""
                if display_next_hop_asn:
                    html += f"""<TD>{ann.next_hop_asn}</TD>"""
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
            if any(list(as_obj.policy.settings)):
                kwargs["shape"] = "doubleoctagon"
            # If people complain about the red being too dark lol:
            kwargs.update({"fillcolor": "#FF7F7F"})
            # kwargs.update({"fillcolor": "#ff4d4d"})
        # As obj is the victim
        elif as_obj.asn in scenario.legitimate_origin_asns:
            kwargs.update({"fillcolor": "#90ee90", "shape": "doublecircle"})
            if any(list(as_obj.policy.settings)):
                kwargs["shape"] = "doubleoctagon"

        # As obj is not attacker or victim
        else:
            if packet_outcomes[as_obj.asn] == Outcomes.ATTACKER_SUCCESS.value:
                kwargs.update({"fillcolor": "#ff6060:yellow"})
            elif packet_outcomes[as_obj.asn] == Outcomes.LEGITIMATE_ORIGIN_SUCCESS.value:
                kwargs.update({"fillcolor": "#90ee90:white"})
            elif packet_outcomes[as_obj.asn] == Outcomes.DISCONNECTED.value:
                kwargs.update({"fillcolor": "grey:white"})

            if any(list(as_obj.policy.settings)):
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

    def _add_diagram_ranks(
        self, diagram_ranks: list[list[int]], engine: SimulationEngine
    ) -> None:
        # TODO: Refactor
        if diagram_ranks:
            for rank in diagram_ranks:
                with self.dot.subgraph() as s:
                    s.attr(rank="same")  # set all nodes to the same rank
                    previous_asn: str | None = None
                    for asn in rank:
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

    def _add_description(self, description: str, display_next_hop_asn: bool) -> None:
        if display_next_hop_asn:
            description += (
                "\nLocal RIB rows displayed as: prefix, as path, origin, next_hop"
            )
        if description:
            # https://stackoverflow.com/a/57461245/8903959
            self.dot.attr(label=description)

    def _render(
        self, path: Path | None = None, view: bool = False, dpi: int | None = None
    ) -> None:
        if dpi:
            self.dot.attr(dpi=str(dpi))
        self.dot.render(path, view=view)
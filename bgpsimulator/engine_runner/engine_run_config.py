from typing import Any

from bgpsimulator.as_graphs.as_graph.as_graph import ASGraph
from bgpsimulator.simulation_framework.scenarios import ScenarioConfig


class EngineRunConfig:
    """Gemerates a JSON config for a single engine run
    
    Useful for tests and diagrams
    """

    _used_names: set[str] = set()

    def __init__(
        self,
        name: str,
        scenario_config: ScenarioConfig,
        as_graph: ASGraph,
        diagram_desc: str = "",
        text: str = "",
        diagram_ranks: tuple[tuple[int, ...], ...] = (),
    ):
        self.name = name
        if self.name in EngineRunConfig._used_names:
            raise ValueError(f"Name {self.name} already used")
        EngineRunConfig._used_names.add(self.name)
        self.diagram_desc = diagram_desc
        # Displayed in the website giant text box
        self.text = text
        self.scenario_config = scenario_config
        self.as_graph = as_graph
        self.diagram_ranks = diagram_ranks

    def to_json(self) -> dict[str, Any]:
        """Converts the engine run config to a JSON object"""

        return {
            "name": self.name,
            "diagram_desc": self.diagram_desc,
            "text": self.text,
            "scenario_config": self.scenario_config.to_json(),
            "as_graph": self.as_graph.to_json(),
            "diagram_ranks": self.diagram_ranks,
        }

    @classmethod
    def from_json(cls, json_obj: dict[str, Any]) -> "EngineRunConfig":
        """Converts a JSON object to an engine run config"""
        return cls(
            name=json_obj["name"],
            diagram_desc=json_obj["diagram_desc"],
            text=json_obj["text"],
            scenario_config=ScenarioConfig.from_json(json_obj["scenario_config"]),
            as_graph=ASGraph.from_json(json_obj["as_graph"]),
            diagram_ranks=json_obj["diagram_ranks"],
        )
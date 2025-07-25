from typing import Any, ClassVar

from bgpsimulator.as_graphs.as_graph.as_graph import ASGraph
from bgpsimulator.simulation_framework.scenarios import ScenarioConfig


class EngineRunConfig:
    """Gemerates a JSON config for a single engine run

    Useful for tests and diagrams
    """

    _used_names: ClassVar[set[str]] = set()

    def __init__(
        self,
        name: str,
        scenario_config: ScenarioConfig,
        as_graph: ASGraph,
        diagram_desc: str = "",
        text: str = "",
        lab_text: str = "",
        diagram_ranks: list[list[int]] | None = None,
        prevent_naming_duplicates: bool = True
    ):
        self.name = name
        self.prevent_naming_duplicates: bool = prevent_naming_duplicates

        # Useful for pytest, but turned off for the website
        if self.name in EngineRunConfig._used_names and prevent_naming_duplicates:
            raise ValueError(f"Name {self.name} already used")
        EngineRunConfig._used_names.add(self.name)
        self.diagram_desc = diagram_desc
        # Displayed in the website giant text box
        self.text = text
        self.lab_text = lab_text
        self.scenario_config = scenario_config
        self.as_graph = as_graph
        self.diagram_ranks = diagram_ranks or []

    def to_json(self) -> dict[str, Any]:
        """Converts the engine run config to a JSON object"""

        return {
            "name": self.name,
            "diagram_desc": self.diagram_desc,
            "text": self.text,
            "lab_text": self.lab_text,
            "scenario_config": self.scenario_config.to_json(),
            "as_graph": self.as_graph.to_json(),
            "diagram_ranks": self.diagram_ranks,
            "prevent_naming_duplicates": self.prevent_naming_duplicates,
        }

    @classmethod
    def from_json(cls, json_obj: dict[str, Any]) -> "EngineRunConfig":
        """Converts a JSON object to an engine run config"""
        return cls(
            name=json_obj["name"],
            diagram_desc=json_obj["diagram_desc"],
            text=json_obj["text"],
            lab_text=json_obj["lab_text"],
            scenario_config=ScenarioConfig.from_json(json_obj["scenario_config"]),
            as_graph=ASGraph.from_json(json_obj["as_graph"]),
            diagram_ranks=json_obj["diagram_ranks"],
            prevent_naming_duplicates=json_obj["prevent_naming_duplicates"],
        )

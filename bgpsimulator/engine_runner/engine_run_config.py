from typing import Any

from bgpsimulator.engine_runner.scenario_config import ScenarioConfig


class EngineRunConfig:
    """Gemerates a JSON config for a single engine run
    
    Useful for tests and diagrams
    """

    def __init__(
        self,
        name: str = "",
        desc: str = "",
        scenario_config: ScenarioConfig,
        as_graph_json: dict[str, Any],
        SimulationEngineCls: type[SimulationEngine],
        DataPlanePacketPropagatorCls: type[DataPlanePacketPropagator],
        DataTrackerCls: type[DataTracker],
        PolicyCls: type[Policy],
        DiagramCls: type[Diagram],
    ):
        self.name = name
        self.desc = desc
        self.scenario_config = scenario_config
        self.as_graph_json = as_graph_json
        self.SimulationEngineCls = SimulationEngineCls
        self.DataPlanePacketPropagatorCls = DataPlanePacketPropagatorCls
        self.DataTrackerCls = DataTrackerCls
        self.PolicyCls = PolicyCls
        self.DiagramCls = DiagramCls

    def to_json(self) -> dict[str, Any]:
        """Converts the engine run config to a JSON object.
        
        Only going to save the default classes here;
        Creating name to class dicts would complicate the code
        and would have almost no benefit since most will never use
        the JSON functionality offered here
        """

        return {
            "name": self.name,
            "desc": self.desc,
            "scenario_config": self.scenario_config.to_json(),
            "as_graph_json": self.as_graph_json,
        }

    @classmethod
    def from_json(cls, json_obj: dict[str, Any]) -> "EngineRunConfig":
        """Converts a JSON object to an engine run config"""
        return cls(
            name=json_obj["name"],
            desc=json_obj["desc"],
            scenario_config=ScenarioConfig.from_json(json_obj["scenario_config"]),
            as_graph_json=json_obj["as_graph_json"],
        )
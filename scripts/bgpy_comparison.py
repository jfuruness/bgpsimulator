from bgpsimulator.engine_runner import EngineRunner, EngineRunConfig
from bgpsimulator.shared import Outcomes
from bgpsimulator.simulation_framework.scenarios import ScenarioConfig, SubprefixHijack
from bgpsimulator.shared import Settings
from bgpsimulator.as_graphs import ASGraph
from bgpsimulator.simulation_engine import SimulationEngine
from pathlib import Path
import json

from bgpy.simulation.engine import SimulationEngine as BGPySimulationEngine, ROV as BGPyROV
from bgpy.utils import EngineRunner as BGPyEngineRunner, EngineRunConfig as BGPyEngineRunConfig
from bgpy.as_graphs import ASGraphInfo as BGPyASGraphInfo, CAIDAASGraphConstructor as BGPyCAIDAASGraphConstructor
from bgpy.simulation_framework import SubprefixHijack as BGPySubprefixHijack, ScenarioConfig as BGPyScenarioConfig


def get_bgpsimulator_local_ribs_and_packet_outcomes() -> tuple[dict[int, [str, tuple[int, ...]]], dict[int, Outcomes]]:
    conf = EngineRunConfig(
        name="bgpsimulator_local_ribs",
        scenario_config=ScenarioConfig(
            label="bgpsimulator_local_ribs",
            ScenarioCls=SubprefixHijack,
            default_adoption_settings={Settings.ROV: True},
            override_attacker_asns=set([666]),
            override_legitimate_origin_asns=set([777]),
            override_adopting_asns=set([174]),
        ),
        as_graph=ASGraph(),
    )
    runner = EngineRunner(conf)
    runner.run()
    with runner.engine_guess_path.open() as f:
        engine = SimulationEngine.from_json(f.read())
        local_ribs = dict()
        for as_obj in engine.as_graph:
            local_ribs[as_obj.asn] = {str(prefix): ann.as_path for prefix, ann in as_obj.policy.local_rib.items()}
    with runner.outcomes_guess_path.open() as f:
        packet_outcomes = json.loads(f.read())
    return local_ribs, packet_outcomes

def get_bgpy_local_ribs_and_packet_outcomes() -> tuple[dict[int, [str, tuple[int, ...]]], dict[int, Outcomes]]:
    conf = BGPyEngineRunConfig(
        name="bgpy_local_ribs",
        scenario_config=BGPyScenarioConfig(
            ScenarioCls=BGPySubprefixHijack,
            AdoptPolicyCls=BGPyROV,
            override_attacker_asns=frozenset([666]),
            override_legitimate_origin_asns=frozenset([777]),
            override_adopting_asns=frozenset([174]),
        ),
        as_graph_info=BGPyCAIDAASGraphConstructor().run(),
    )
    runner = BGPyEngineRunner(conf)
    engine, packet_outcomes, *_ = runner.run_engine()
    local_ribs = dict()
    for as_obj in engine.as_graph:
        local_ribs[as_obj.asn] = {str(prefix): ann.as_path for prefix, ann in as_obj.policy.local_rib.items()}
    return local_ribs, packet_outcomes

def main() -> None:
    """Compares the guesses against ground truth for engine and packet outcomes"""
    local_ribs, packet_outcomes = get_bgpsimulator_local_ribs_and_packet_outcomes()
    local_ribs_bgpy, packet_outcomes_bgpy = get_bgpy_local_ribs_and_packet_outcomes()
    assert local_ribs == local_ribs_bgpy, "Local ribs do not match"
    assert packet_outcomes == packet_outcomes_bgpy, "Packet outcomes do not match"

if __name__ == "__main__":
    main()
from bgpsimulator.engine_runner import EngineRunner, EngineRunConfig
from bgpsimulator.shared import Outcomes
from bgpsimulator.simulation_framework.scenarios import ScenarioConfig, SubprefixHijack, PassiveHijack
from bgpsimulator.shared import Settings
from bgpsimulator.as_graphs import ASGraph, CAIDAASGraphJSONConverter
from bgpsimulator.simulation_engine import SimulationEngine
from pathlib import Path
import json

from bgpy.simulation_engine import SimulationEngine as BGPySimulationEngine, ROV as BGPyROV
from bgpy.utils import EngineRunner as BGPyEngineRunner, EngineRunConfig as BGPyEngineRunConfig
from bgpy.as_graphs import ASGraphInfo as BGPyASGraphInfo, CAIDAASGraphConstructor as BGPyCAIDAASGraphConstructor
from bgpy.simulation_framework import SubprefixHijack as BGPySubprefixHijack, ScenarioConfig as BGPyScenarioConfig, VictimsPrefix as BGPyVictimsPrefix


def get_bgpsimulator_local_ribs_and_packet_outcomes() -> tuple[dict[int, [str, tuple[int, ...]]], dict[int, Outcomes]]:
    conf = EngineRunConfig(
        name="bgpsimulator_local_ribs",
        scenario_config=ScenarioConfig(
            label="bgpsimulator_local_ribs",
            ScenarioCls=SubprefixHijack,
            # ScenarioCls=PassiveHijack,
            default_adoption_settings={Settings.ROV: True},
            override_attacker_asns=set([25]),
            override_legitimate_origin_asns=set([27]),
            override_adopting_asns=set([174, 43, 68]),
        ),
        as_graph=ASGraph(CAIDAASGraphJSONConverter().run()[0]),
    )
    runner = EngineRunner(conf, write_diagrams=False)
    print("Running bgpsimulator")
    runner.run()
    print("bgpsimulator done")
    with runner.engine_guess_path.open() as f:
        engine = SimulationEngine.from_json(json.loads(f.read()))
        local_ribs = dict()
        for as_obj in engine.as_graph:
            local_ribs[as_obj.asn] = {str(prefix): ann.as_path for prefix, ann in as_obj.policy.local_rib.items()}
    with runner.outcomes_guess_path.open() as f:
        packet_outcomes = {int(asn): Outcomes(outcome) for asn, outcome in json.loads(f.read()).items()}
    print("bgpsimulator local ribs and packet outcomes done")
    return local_ribs, packet_outcomes

def get_bgpy_local_ribs_and_packet_outcomes() -> tuple[dict[int, [str, tuple[int, ...]]], dict[int, Outcomes]]:
    # Download file (for ex: from CAIDA)
    constructor = BGPyCAIDAASGraphConstructor()
    dl_path = constructor.as_graph_collector.run()
    # Get ASGraphInfo from downloaded file
    as_graph_info = constructor._get_as_graph_info(dl_path)

    conf = BGPyEngineRunConfig(
        name="bgpy_local_ribs",
        scenario_config=BGPyScenarioConfig(
            ScenarioCls=BGPySubprefixHijack,
            # ScenarioCls=BGPyVictimsPrefix,
            AdoptPolicyCls=BGPyROV,
            override_attacker_asns=frozenset([25]),
            override_victim_asns=frozenset([27]),
            override_adopting_asns=frozenset([174, 43, 68]),
        ),
        desc="",
        as_graph_info=as_graph_info,
    )
    class NoDiagramsEngineRunner(BGPyEngineRunner):
        def _generate_diagrams(self, *args, **kwargs):
            pass
        def _store_data(self, *args, **kwargs):
            pass
    runner = NoDiagramsEngineRunner(conf)
    print("Running bgpy")
    engine, packet_outcomes, *_ = runner.run_engine()
    print("bgpy done")
    local_ribs = dict()
    for as_obj in engine.as_graph:
        local_ribs[as_obj.asn] = {str(prefix): ann.as_path for prefix, ann in as_obj.policy.local_rib.items()}
    print("bgpy local ribs and packet outcomes done")
    return local_ribs, packet_outcomes

def main() -> None:
    """Compares the guesses against ground truth for engine and packet outcomes"""
    local_ribs, packet_outcomes = get_bgpsimulator_local_ribs_and_packet_outcomes()
    local_ribs_bgpy, packet_outcomes_bgpy = get_bgpy_local_ribs_and_packet_outcomes()
    for asn in local_ribs:
        if local_ribs[asn] == local_ribs_bgpy[asn]:
            print(f"Local rib for AS{asn} matches")
            continue
        if local_ribs[asn] != local_ribs_bgpy[asn]:
            print(f"Local rib for AS{asn} does not match")
            print(local_ribs[asn])
            print(local_ribs_bgpy[asn])
            input("HERE")
    for asn in local_ribs_bgpy:
        if local_ribs_bgpy[asn] != local_ribs[asn]:
            print(f"Local rib for AS{asn} does not match")
            print(local_ribs_bgpy[asn])
            print(local_ribs[asn])
            input("HERE")
    assert local_ribs == local_ribs_bgpy, "Local ribs do not match"
    for asn in packet_outcomes:
        if packet_outcomes[asn] != packet_outcomes_bgpy[asn]:
            print(f"Packet outcome for AS{asn} does not match")
            print(packet_outcomes[asn])
            print(packet_outcomes_bgpy[asn])
            input("HERE")

if __name__ == "__main__":
    main()

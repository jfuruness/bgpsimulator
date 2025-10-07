from bgpsimulator.as_graphs.as_graph import ASGraph
from bgpsimulator.engine_runner import EngineRunConfig
from bgpsimulator.shared import CommonASNs, Settings
from bgpsimulator.simulation_framework import PassiveHijack, ScenarioConfig

# Graph to test OTC from a peer
# CommonASNs.LEGITIMATE_ORIGIN - CommonASNs.ATTACKER - 1
graph_data = {
    "ases": {
        "1": {
            "asn": 1,
            "customer_asns": [CommonASNs.ATTACKER],
            "provider_asns": [
                3,
            ],
        },
        "2": {
            "asn": 2,
            "customer_asns": [CommonASNs.LEGITIMATE_ORIGIN, CommonASNs.ATTACKER],
            "provider_asns": [3],
        },
        "3": {"asn": 3, "customer_asns": [1, 2]},
        CommonASNs.ATTACKER: {
            "asn": CommonASNs.ATTACKER,
            "provider_asns": [1, 2],
        },
        CommonASNs.LEGITIMATE_ORIGIN: {
            "asn": CommonASNs.LEGITIMATE_ORIGIN,
            "provider_asns": [2],
        },
    }
}

# Create the engine run config
ex_config_033 = EngineRunConfig(
    name="ex_033_leaker",
    scenario_config=ScenarioConfig(
        label="leaker",
        ScenarioCls=PassiveHijack,
        override_attacker_asns={CommonASNs.ATTACKER},
        override_legitimate_origin_asns={CommonASNs.LEGITIMATE_ORIGIN},
        # AS 1 and VICTIM use OnlyToCustomers
        override_base_settings={
            CommonASNs.ATTACKER: {Settings.LEAKER: True},
        },
    ),
    as_graph=ASGraph(graph_data),
    diagram_desc="Accidental route leak",
)

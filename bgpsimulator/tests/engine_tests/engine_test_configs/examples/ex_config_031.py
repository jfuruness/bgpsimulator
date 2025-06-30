from bgpsimulator.as_graphs.as_graph import ASGraph
from bgpsimulator.engine_runner import EngineRunConfig
from bgpsimulator.shared import CommonASNs, Settings
from bgpsimulator.simulation_framework import AccidentalRouteLeak, ScenarioConfig

# Graph to test OTC from a peer
# 777 - 666 - 1
graph_data = {
    "ases": {
        str(CommonASNs.VICTIM): {
            "asn": CommonASNs.VICTIM,
            "customer_asns": [],
            "peer_asns": [CommonASNs.ATTACKER],
            "provider_asns": [],
        },
        str(CommonASNs.ATTACKER): {
            "asn": CommonASNs.ATTACKER,
            "customer_asns": [],
            "peer_asns": [CommonASNs.VICTIM, 1],
            "provider_asns": [],
        },
        "1": {
            "asn": 1,
            "customer_asns": [],
            "peer_asns": [CommonASNs.ATTACKER],
            "provider_asns": [],
        },
    },
}

# Create the engine run config
ex_config_031 = EngineRunConfig(
    name="ex_031_route_leak_peer_with_otc_simple",
    scenario_config=ScenarioConfig(
        label="otc",
        ScenarioCls=AccidentalRouteLeak,
        override_attacker_asns={CommonASNs.ATTACKER},
        override_legitimate_origin_asns={CommonASNs.VICTIM},
        # AS 1 and VICTIM use OnlyToCustomers
        override_base_settings={
            1: {Settings.ONLY_TO_CUSTOMERS: True},
            CommonASNs.VICTIM: {Settings.ONLY_TO_CUSTOMERS: True},
        },
    ),
    as_graph=ASGraph(graph_data),
    diagram_desc="Accidental route leak to a peer with OTC Simple",
    diagram_ranks=[
        [CommonASNs.VICTIM.value, CommonASNs.ATTACKER.value, 1],
    ],
)

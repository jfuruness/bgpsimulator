from bgpsimulator.as_graphs.as_graph import ASGraph
from bgpsimulator.engine_runner import EngineRunConfig
from bgpsimulator.shared import CommonASNs, Settings
from bgpsimulator.simulation_framework import ForgedOriginPrefixHijack, ScenarioConfig

# Custom graph for this test
graph_data = {
    "ases": {
        str(CommonASNs.LEGITIMATE_ORIGIN): {
            "asn": CommonASNs.LEGITIMATE_ORIGIN,
            "customer_asns": [],
            "peer_asns": [],
            "provider_asns": [3],
        },
        str(CommonASNs.ATTACKER): {
            "asn": CommonASNs.ATTACKER,
            "customer_asns": [],
            "peer_asns": [],
            "provider_asns": [1, 2],
        },
        "1": {
            "asn": 1,
            "customer_asns": [CommonASNs.ATTACKER],
            "peer_asns": [],
            "provider_asns": [5],
        },
        "2": {
            "asn": 2,
            "customer_asns": [CommonASNs.ATTACKER],
            "peer_asns": [],
            "provider_asns": [4],
        },
        "3": {
            "asn": 3,
            "customer_asns": [CommonASNs.LEGITIMATE_ORIGIN],
            "peer_asns": [],
            "provider_asns": [],
        },
        "4": {
            "asn": 4,
            "customer_asns": [2],
            "peer_asns": [],
            "provider_asns": [5],
        },
        "5": {
            "asn": 5,
            "customer_asns": [4, 1],
            "peer_asns": [],
            "provider_asns": [],
        },
    },
}

# Create the engine run config
ex_config_029 = EngineRunConfig(
    name="ex_029_aspa_weirdness",
    scenario_config=ScenarioConfig(
        label="aspa",
        ScenarioCls=ForgedOriginPrefixHijack,
        override_attacker_asns={CommonASNs.ATTACKER},
        override_legitimate_origin_asns={CommonASNs.LEGITIMATE_ORIGIN},
        # AS 4 and VICTIM use ASPA
        override_base_settings={
            4: {Settings.ASPA: True},
            CommonASNs.LEGITIMATE_ORIGIN: {Settings.ASPA: True},
        },
    ),
    as_graph=ASGraph(graph_data),
    diagram_desc="ASPA weirdness. rejects upstream, accepts downstream",
)

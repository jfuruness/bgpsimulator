from bgpsimulator.as_graphs.as_graph import ASGraph
from bgpsimulator.engine_runner import EngineRunConfig
from bgpsimulator.shared import CommonASNs, Settings
from bgpsimulator.simulation_framework import PrefixHijack, ScenarioConfig

# Graph to test OTC from a peer
# CommonASNs.LEGITIMATE_ORIGIN - CommonASNs.ATTACKER - 1
graph_data = {
    "ases": {
        "1": {"asn": 1, "customer_asns": [3, 5]},
        "2": {"asn": 2, "customer_asns": [4], "peer_asns": [5]},
        "3": {"asn": 3, "provider_asns": [1], "peer_asns": [4]},
        "4": {"asn": 4, "provider_asns": [2, 8], "peer_asns": [3]},
        "5": {
            "asn": 5,
            "provider_asns": [1],
            "customer_asns": [8, 9],
            "peer_asns": [2, 11],
        },
        "8": {"asn": 8, "provider_asns": [5], "customer_asns": [4], "peer_asns": [9]},
        "9": {
            "asn": 9,
            "provider_asns": [5],
            "customer_asns": [10, CommonASNs.ATTACKER, CommonASNs.LEGITIMATE_ORIGIN],
            "peer_asns": [8],
        },
        "10": {"asn": 10, "provider_asns": [9]},
        "11": {"asn": 11, "peer_asns": [5]},
        CommonASNs.ATTACKER: {"asn": CommonASNs.ATTACKER, "provider_asns": [9]},
        CommonASNs.LEGITIMATE_ORIGIN: {
            "asn": CommonASNs.LEGITIMATE_ORIGIN,
            "provider_asns": [9],
        },
    }
}

# Create the engine run config
ex_config_032 = EngineRunConfig(
    name="ex_032_graph_display_algo",
    scenario_config=ScenarioConfig(
        label="graph_display_algo",
        ScenarioCls=PrefixHijack,
        override_attacker_asns={CommonASNs.ATTACKER},
        override_legitimate_origin_asns={CommonASNs.LEGITIMATE_ORIGIN},
        # AS 1 and VICTIM use OnlyToCustomers
        override_base_settings={
            1: {Settings.ROV: True},
            CommonASNs.LEGITIMATE_ORIGIN: {Settings.ROV: True},
        },
    ),
    as_graph=ASGraph(graph_data),
    diagram_desc="Testing the graph display algorithm",
)

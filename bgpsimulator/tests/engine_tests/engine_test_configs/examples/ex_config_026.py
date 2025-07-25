from bgpsimulator.as_graphs.as_graph import ASGraph
from bgpsimulator.engine_runner import EngineRunConfig
from bgpsimulator.shared import CommonASNs, Settings
from bgpsimulator.simulation_framework import ScenarioConfig, ShortestPathPrefixHijack

graph_data = {
    "ases": {
        str(CommonASNs.LEGITIMATE_ORIGIN): {
            "asn": CommonASNs.LEGITIMATE_ORIGIN,
            "customer_asns": [],
            "peer_asns": [],
            "provider_asns": [2, 4, 10],
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
            "provider_asns": [5, 8],
        },
        "2": {
            "asn": 2,
            "customer_asns": [CommonASNs.ATTACKER, CommonASNs.LEGITIMATE_ORIGIN],
            "peer_asns": [],
            "provider_asns": [8],
        },
        "3": {
            "asn": 3,
            "customer_asns": [],
            "peer_asns": [9],
            "provider_asns": [],
        },
        "4": {
            "asn": 4,
            "customer_asns": [CommonASNs.LEGITIMATE_ORIGIN],
            "peer_asns": [],
            "provider_asns": [9],
        },
        "5": {
            "asn": 5,
            "customer_asns": [1],
            "peer_asns": [],
            "provider_asns": [],
        },
        "8": {
            "asn": 8,
            "customer_asns": [1, 2],
            "peer_asns": [9],
            "provider_asns": [11],
        },
        "9": {
            "asn": 9,
            "customer_asns": [4],
            "peer_asns": [8, 10, 3],
            "provider_asns": [11],
        },
        "10": {
            "asn": 10,
            "customer_asns": [CommonASNs.LEGITIMATE_ORIGIN],
            "peer_asns": [9],
            "provider_asns": [11, 12],
        },
        "11": {
            "asn": 11,
            "customer_asns": [8, 9, 10],
            "peer_asns": [],
            "provider_asns": [],
        },
        "12": {
            "asn": 12,
            "customer_asns": [10],
            "peer_asns": [],
            "provider_asns": [],
        },
    },
}

# Create the engine run config
ex_config_026 = EngineRunConfig(
    name="ex_026_shortest_path_export_all_aspa_simple_peer",
    scenario_config=ScenarioConfig(
        label="aspa",
        ScenarioCls=ShortestPathPrefixHijack,
        override_attacker_asns={CommonASNs.ATTACKER},
        override_legitimate_origin_asns={CommonASNs.LEGITIMATE_ORIGIN},
        # Attacker uses origin hijack to customers setting
        attacker_settings={Settings.ORIGIN_PREFIX_HIJACK_CUSTOMERS: True},
        # ASes 2, 4, 5, 8, 9, 10, 11, 12, and VICTIM use ASPA
        override_base_settings={
            2: {Settings.ASPA: True},
            4: {Settings.ASPA: True},
            5: {Settings.ASPA: True},
            8: {Settings.ASPA: True},
            9: {Settings.ASPA: True},
            10: {Settings.ASPA: True},
            11: {Settings.ASPA: True},
            12: {Settings.ASPA: True},
            CommonASNs.LEGITIMATE_ORIGIN: {Settings.ASPA: True},
        },
    ),
    as_graph=ASGraph(graph_data),
    diagram_desc=(
        "shortest path export all against ASPASimple from a peer\n"
        "AS prevents the attack, this is merely to check attack functionality"
    ),
)

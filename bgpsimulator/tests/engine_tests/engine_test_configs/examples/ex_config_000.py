from bgpsimulator.as_graphs.as_graph import ASGraph
from bgpsimulator.engine_runner import EngineRunConfig
from bgpsimulator.simulation_framework import ScenarioConfig, LegitimatePrefixOnly
from bgpsimulator.shared import CommonASNs

graph_data = {
    "ases": {
        str(CommonASNs.VICTIM): {
            "asn": CommonASNs.VICTIM,
            "provider_asns": [2, 4, 10],
        },
        str(CommonASNs.ATTACKER): {
            "asn": CommonASNs.ATTACKER,
            "provider_asns": [1, 2],
        },
        "1": {
            "asn": 1,
            "provider_asns": [5, 8],
        },
        "2": {
            "asn": 2,
            "customer_asns": [CommonASNs.ATTACKER, CommonASNs.VICTIM],
            "provider_asns": [8],
        },
        "3": {
            "asn": 3,
            "peer_asns": [9],
        },
        "4": {
            "asn": 4,
            "customer_asns": [CommonASNs.VICTIM],
            "provider_asns": [9],
        },
        "5": {
            "asn": 5,
            "customer_asns": [1],
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
            "customer_asns": [CommonASNs.VICTIM],
            "peer_asns": [9],
            "provider_asns": [11, 12],
        },
        "11": {
            "asn": 11,
            "customer_asns": [8, 9, 10],
        },
        "12": {
            "asn": 12,
            "customer_asns": [10],
        }
    },
}

# Create the engine run config
ex_config_000 = EngineRunConfig(
    name="ex_000_valid_prefix_bgp_simple",
    scenario_config=ScenarioConfig(
        label="bgp",
        ScenarioCls=LegitimatePrefixOnly,
        override_attacker_asns=set(),
        override_legitimate_origin_asns={CommonASNs.VICTIM},
    ),
    as_graph=ASGraph(graph_data),
    diagram_desc="Valid prefix with BGP Simple",
    diagram_ranks=[
        [CommonASNs.ATTACKER, CommonASNs.VICTIM],
        [1, 2, 3, 4],
        [5, 8, 9, 10],
        [11, 12],
    ],
)
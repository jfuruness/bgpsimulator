from bgpsimulator.as_graphs.as_graph import ASGraph
from bgpsimulator.engine_runner import EngineRunConfig
from bgpsimulator.shared import CommonASNs
from bgpsimulator.simulation_framework import ScenarioConfig, SubprefixHijack

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

desc = (
    "Subprefix hijack with BGP Simple "
    "Valley Free (Gao Rexford) Demonstration\n"
    "import policy\n"
    "AS 9, prefix, shows customer > peer\n"
    "AS 9, subprefix, shows peer > provider\n"
    "AS 11, prefix, shows shortest AS path\n"
    "AS 5 and AS 8, subprefix, tiebreaker by lowest ASN\n"
    "export policy\n"
    "AS 10, subprefix, shows anns from providers only export to customers\n"
    "AS 9, subprefix, shows anns from peers only export to customers\n"
    "(All ASes show exporting to customers)\n"
    "hidden hijack\n"
    "AS 12 shows a hidden hijack\n"
)

# Create the engine run config
ex_config_002 = EngineRunConfig(
    name="ex_002_subprefix_hijack_bgp_simple_gao_rexford_demo",
    scenario_config=ScenarioConfig(
        label="bgp",
        ScenarioCls=SubprefixHijack,
        override_attacker_asns={CommonASNs.ATTACKER},
        override_legitimate_origin_asns={CommonASNs.LEGITIMATE_ORIGIN},
    ),
    as_graph=ASGraph(graph_data),
    diagram_desc=desc,
)

from bgpsimulator.as_graphs.as_graph import ASGraph
from bgpsimulator.engine_runner import EngineRunConfig
from bgpsimulator.shared import CommonASNs, Settings
from bgpsimulator.simulation_framework import ScenarioConfig, ForgedOriginPrefixHijack

# Custom graph for this test (same as ex_config_023)
graph_data = {
    "ases": {
        str(CommonASNs.VICTIM): {
            "asn": CommonASNs.VICTIM,
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
            "customer_asns": [CommonASNs.ATTACKER, 2],
            "peer_asns": [],
            "provider_asns": [],
        },
        "2": {
            "asn": 2,
            "customer_asns": [CommonASNs.ATTACKER],
            "peer_asns": [],
            "provider_asns": [1],
        },
        "3": {
            "asn": 3,
            "customer_asns": [CommonASNs.VICTIM],
            "peer_asns": [],
            "provider_asns": [],
        },
    },
}

# Create the engine run config
ex_config_024 = EngineRunConfig(
    name="ex_024_origin_export_all_hijack_aspa_full_downstream_verification",
    scenario_config=ScenarioConfig(
        label="aspa",
        ScenarioCls=ForgedOriginPrefixHijack,
        default_base_settings={Settings.BGP_FULL: True},
        override_attacker_asns={CommonASNs.ATTACKER},
        override_legitimate_origin_asns={CommonASNs.VICTIM},
        # AS 2 and VICTIM use ASPA
        override_base_settings={
            2: {Settings.ASPA: True},
            CommonASNs.VICTIM: {Settings.ASPA: True},
        },
    ),
    as_graph=ASGraph(graph_data),
    diagram_desc="Origin hijack against ASPASimple\nTesting that ASPA rejects from the upstream, but accepts from downstream",
    diagram_ranks=[
        [CommonASNs.ATTACKER.value, CommonASNs.VICTIM.value],
        [1, 2, 3],
    ],
)
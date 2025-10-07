from bgpsimulator.as_graphs.as_graph import ASGraph
from bgpsimulator.engine_runner import EngineRunConfig
from bgpsimulator.shared import CommonASNs, Settings
from bgpsimulator.simulation_framework import PrefixHijack, ScenarioConfig
from bgpsimulator.shared.enums import CommonPrefixes, Relationships, Timestamps
from bgpsimulator.simulation_engine import Announcement as Ann


# Graph to test OTC from a peer
# CommonASNs.LEGITIMATE_ORIGIN - CommonASNs.ATTACKER - 1
graph_data = {
    "ases": {
        "1": {"asn": 1, "customer_asns": [CommonASNs.ATTACKER]},
        CommonASNs.ATTACKER: {
            "asn": CommonASNs.ATTACKER,
            "customer_asns": [CommonASNs.LEGITIMATE_ORIGIN],
            "provider_asns": [1],
        },
        CommonASNs.LEGITIMATE_ORIGIN: {
            "asn": CommonASNs.LEGITIMATE_ORIGIN,
            "provider_asns": [CommonASNs.ATTACKER],
        },
    }
}

# Create the engine run config
ex_config_034 = EngineRunConfig(
    name="ex_034_withdrawal_supppresion_loop",
    scenario_config=ScenarioConfig(
        label="withdrawal_suppression_loop",
        ScenarioCls=PrefixHijack,
        override_seed_asn_ann_dict={
            CommonASNs.LEGITIMATE_ORIGIN: [
                Ann(
                    prefix=CommonPrefixes.PREFIX.value,
                    as_path=(CommonASNs.LEGITIMATE_ORIGIN,),
                    next_hop_asn=CommonASNs.LEGITIMATE_ORIGIN,
                    recv_relationship=Relationships.ORIGIN,
                    timestamp=Timestamps.LEGITIMATE_ORIGIN,
                ),
            ],
            1: [
                Ann(
                    prefix=CommonPrefixes.SUBPREFIX.value,
                    as_path=(1,),
                    next_hop_asn=1,
                    recv_relationship=Relationships.ORIGIN,
                    timestamp=Timestamps.LEGITIMATE_ORIGIN,
                ),
            ],
        },
        num_attackers=0,
        override_attacker_asns=set(),  # CommonASNs.ATTACKER},
        override_legitimate_origin_asns={CommonASNs.LEGITIMATE_ORIGIN},
        # AS 1 and VICTIM use OnlyToCustomers
        override_base_settings={
            1: {Settings.ANNOUNCE_THEN_WITHDRAW: True},
            CommonASNs.ATTACKER: {
                Settings.NEVER_PROPAGATE_WITHDRAWALS: True,
                Settings.NEVER_WITHDRAW: True,
            },
        },
    ),
    as_graph=ASGraph(graph_data),
    diagram_desc="Withdrawal suppression loop",
)

from .engine_run_config import EngineRunConfig


class EngineRunner:
    """Runs a single engine run"""

    def __init__(self, engine_run_config: EngineRunConfig):
        self.conf = engine_run_config

    def run(self, dpi: int | None = None):
        """Runs the engine run"""

        engine, scenario = self._get_engine_and_scenario()

        # Run engine
        for round_ in range(self.conf.scenario_config.propagation_rounds):
            engine.run(propagation_round=round_, scenario=scenario)
            # By default, these are both no ops
            for func in (scenario.pre_aggregation_hook, scenario.post_propagation_hook):
                func(engine=engine, propagation_round=round_, trial=0, percent_ases_randomly_adopting=0)
            
            # Run diagram
            diagram = self.conf.DiagramCls(engine=engine, scenario=scenario)
            diagram.run(propagation_round=round_, trial=0, percent_adopt=0)

        data_plane_packet_propagator = self.conf.DataPlanePacketPropagatorCls()
        data_plane_outcomes = data_plane_packet_propagator.get_as_outcomes_for_data_plane_packet(
            dest_ip_addr=scenario.dest_ip_addr,
            simulation_engine=engine,
            legitimate_origin_asns=scenario.legitimate_origin_asns,
            attacker_asns=scenario.attacker_asns,
            scenario=scenario,
        )

        data_tracker = self.conf.DataTrackerCls(
            line_filters=self.conf.scenario_config.line_filters,
            scenario_labels=[self.conf.scenario_config.scenario_label],
        )
        data_tracker.store_trial_data(
            engine=engine,
            scenario=scenario,
            outcomes_dict=data_plane_outcomes,
            propagation_round=round_,
        )
        data_tracker.aggregate_data()
        self._store_data(engine=engine, outcomes_dict=data_plane_outcomes, data_tracker=data_tracker)
        self._generate_diagrams(scenario)


    def _get_engine_and_scenario(self):
        """Gets the engine and scenario"""
        engine = self._get_engine()
        scenario = self._get_scenario(engine=engine)
        scenario.setup_engine(engine)
        return engine, scenario

    def _get_engine(self):
        """Gets the engine"""
        return self.conf.SimulationEngineCls(
            as_graph=ASGraph.from_json(self.conf.as_graph_json),
        )

    def _get_scenario(self, engine: SimulationEngine):
        """Gets the scenario"""
        return self.conf.scenario_config.ScenarioCls(
            scenario_config=self.conf.scenario_config,
            engine=engine,
        )

    def _store_data(self, engine: SimulationEngine, outcomes_dict: dict[int, Outcomes], data_tracker: DataTracker):
        raise NotImplementedError("Subclass must implement this")

    def _generate_diagrams(self, scenario: Scenario):
        raise NotImplementedError("Subclass must implement this")
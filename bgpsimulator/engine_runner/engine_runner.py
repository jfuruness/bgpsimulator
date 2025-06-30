import json
from pathlib import Path

from bgpsimulator.shared import Outcomes
from bgpsimulator.simulation_engine import SimulationEngine
from bgpsimulator.simulation_framework import DataPlanePacketPropagator, Scenario

from .diagram import Diagram
from .engine_run_config import EngineRunConfig


class EngineRunner:
    """Runs a single engine run"""

    def __init__(
        self,
        engine_run_config: EngineRunConfig,
        base_dir: Path = Path.home() / "Desktop" / "bgpsimulator_engine_runs",
        overwrite: bool = False,
        compare_against_ground_truth: bool = False,
        write_diagrams: bool = True,
    ):
        self.conf: EngineRunConfig = engine_run_config
        self.base_dir: Path = base_dir
        self.overwrite: bool = overwrite
        # True when used for tests, False when used for everything else
        self.compare_against_ground_truth: bool = compare_against_ground_truth
        self.storage_dir: Path = self.base_dir / self.conf.name
        self.storage_dir.mkdir(parents=True, exist_ok=True)
        self.write_diagrams: bool = write_diagrams

    def run(self, dpi: int | None = None):
        """Runs the engine run"""

        engine, scenario = self._get_engine_and_scenario()

        # Run engine
        for round_ in range(self.conf.scenario_config.propagation_rounds):
            engine.propagate(propagation_round=round_, scenario=scenario)
            # By default, these are both no ops
            for func in (scenario.pre_aggregation_hook, scenario.post_propagation_hook):
                func(
                    engine=engine,
                    propagation_round=round_,
                    trial=0,
                    percent_ases_randomly_adopting=0,
                )
        data_plane_packet_propagator = DataPlanePacketPropagator()
        data_plane_outcomes = (
            data_plane_packet_propagator.get_as_outcomes_for_data_plane_packet(
                dest_ip_addr=scenario.dest_ip_addr,
                simulation_engine=engine,
                legitimate_origin_asns=scenario.legitimate_origin_asns,
                attacker_asns=scenario.attacker_asns,
                scenario=scenario,
            )
        )
        # NOTE: We used to include the data_tracker, but we don't now for three reasons:
        # 1. Any time the format of the metrics change, the tests break, breaking
        #    backwards compatibility
        # 2. Nobody looked at them. Like, ever. I.e. they were useless to test
        # 3. Many simulators track a very different set of metrics with no clear format
        self._store_data(engine=engine, asn_to_packet_outcome_dict=data_plane_outcomes)
        self._generate_diagrams(scenario, dpi=dpi)
        self._compare_against_ground_truth()

    def _get_engine_and_scenario(self):
        """Gets the engine and scenario"""
        engine = self._get_engine()
        scenario = self._get_scenario(engine=engine)
        scenario.setup_engine(engine)
        return engine, scenario

    def _get_engine(self):
        """Gets the engine"""
        return SimulationEngine(as_graph=self.conf.as_graph)

    def _get_scenario(self, engine: SimulationEngine):
        """Gets the scenario"""
        route_validator = next(
            iter(engine.as_graph.as_dict.values())
        ).policy.route_validator
        return self.conf.scenario_config.ScenarioCls(
            scenario_config=self.conf.scenario_config,
            engine=engine,
            route_validator=route_validator,
        )

    def _store_data(
        self, engine: SimulationEngine, asn_to_packet_outcome_dict: dict[int, Outcomes]
    ):
        """Stores the engine and outcomes.

        Always stores the guess, and optionally overwrites ground truth.
        """
        self.engine_guess_path.write_text(json.dumps(engine.to_json()))
        self.outcomes_guess_path.write_text(json.dumps(asn_to_packet_outcome_dict))
        # Only write the ground truth if we're comparing against it
        if self.compare_against_ground_truth and (
            self.overwrite or not self.engine_gt_path.exists()
        ):
            self.engine_gt_path.write_text(json.dumps(engine.to_json()))
        if self.compare_against_ground_truth and (
            self.overwrite or not self.outcomes_gt_path.exists()
        ):
            self.outcomes_gt_path.write_text(json.dumps(asn_to_packet_outcome_dict))

    def _generate_diagrams(self, scenario: Scenario, dpi: int | None = None):
        """Generates the diagrams"""

        if not self.write_diagrams:
            return

        vals = [
            (
                self.engine_guess_path,
                self.outcomes_guess_path,
                self.diagram_guess_path,
                "",
            ),
        ]
        # Only write the ground truth if we're comparing against it
        if self.compare_against_ground_truth:
            vals.append(
                (
                    self.engine_gt_path,
                    self.outcomes_gt_path,
                    self.diagram_gt_path,
                    " (ground truth) ",
                )
            )

        for engine_path, packet_outcomes_path, diagram_path, name in vals:
            Diagram().run(
                engine=SimulationEngine.from_json(json.loads(engine_path.read_text())),
                scenario=scenario,
                packet_outcomes={
                    int(asn): Outcomes(outcome)
                    for asn, outcome in json.loads(
                        packet_outcomes_path.read_text()
                    ).items()
                },
                name=self.conf.name + name,
                description=self.conf.diagram_desc,
                diagram_ranks=self.conf.diagram_ranks,
                path=diagram_path,
                dpi=dpi,
            )

    def _compare_against_ground_truth(self):
        if not self.compare_against_ground_truth:
            return

        """Compares the guesses against ground truth for engine and packet outcomes"""
        engine_guess = SimulationEngine.from_json(
            json.loads(self.engine_guess_path.read_text())
        )
        engine_gt = SimulationEngine.from_json(
            json.loads(self.engine_gt_path.read_text())
        )
        assert engine_guess == engine_gt, (
            "Engine guess does not match engine ground truth"
        )

        outcomes_guess = json.loads(self.outcomes_guess_path.read_text())
        outcomes_gt = json.loads(self.outcomes_gt_path.read_text())
        assert outcomes_guess == outcomes_gt, (
            "Outcomes guess does not match outcomes ground truth"
        )

    ###################
    # Path Properties #
    ###################

    @property
    def engine_guess_path(self) -> Path:
        return self.storage_dir / "engine_guess.json"

    @property
    def engine_gt_path(self) -> Path:
        return self.storage_dir / "engine_gt.json"

    @property
    def outcomes_guess_path(self) -> Path:
        return self.storage_dir / "outcomes_guess.json"

    @property
    def outcomes_gt_path(self) -> Path:
        return self.storage_dir / "outcomes_gt.json"

    @property
    def diagram_guess_path(self) -> Path:
        return self.storage_dir / "diagram_guess.gv"

    @property
    def diagram_gt_path(self) -> Path:
        return self.storage_dir / "diagram_gt.gv"

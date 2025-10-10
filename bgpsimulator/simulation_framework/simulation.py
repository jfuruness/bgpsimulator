import argparse
import gc
import json
import os
import random
import shutil
import time
from copy import deepcopy
from functools import cached_property
from multiprocessing import Pool, cpu_count
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import TYPE_CHECKING, Any, Iterable
from warnings import warn

import psutil
from tqdm import tqdm

from bgpsimulator.as_graphs import (
    ASGraph,
    CAIDAASGraphCollector,
    CAIDAASGraphJSONConverter,
)
from bgpsimulator.shared import (
    ASNGroups,
    InAdoptingASNs,
    Outcomes,
    Settings,
    bgpsimulator_logger,
)
from bgpsimulator.simulation_engine import Policy, SimulationEngine

from .data_plane_packet_propagator import DataPlanePacketPropagator
from .data_tracker.data_tracker import DataTracker
from .data_tracker.line_filter import LineFilter
from .line_chart_factory.line_chart_factory import LineChartFactory
from .scenarios import SubprefixHijack
from .scenarios.scenario import Scenario
from .scenarios.scenario_config import ScenarioConfig

if TYPE_CHECKING:
    from multiprocessing.pool import ApplyResult

    from bgpsimulator.simulation_framework.scenarios.scenario import Scenario

parser = argparse.ArgumentParser(description="Runs BGPy simulations")
parser.add_argument(
    "--num_trials",
    "--trials",
    dest="trials",
    type=int,
    default=10,
    help="Number of trials to run",
)
parser.add_argument(
    "--parse_cpus",
    "--cpus",
    dest="cpus",
    type=int,
    default=max(cpu_count() - 1, 1),
    help="Number of CPUs to use for parsing",
)
# parse known args to avoid crashing during pytest
args, _unknown = parser.parse_known_args()


class Simulation:
    """A simulation of a BGP routing policy"""

    ##############
    # Init Funcs #
    ##############

    def __init__(
        self,
        output_dir: Path = Path("~/Desktop/sims").expanduser() / "bgpsimulator",
        percent_ases_randomly_adopting: tuple[float, ...] = (10, 20, 50, 80, 99),
        scenario_configs: tuple[ScenarioConfig, ...] = (
            ScenarioConfig(
                label="Subprefix Hijack; ROV Adopting",
                ScenarioCls=SubprefixHijack,
                default_adoption_settings={
                    Settings.ROV: True,
                },
            ),
        ),
        num_trials: int = args.trials,
        parse_cpus: int = args.cpus,
        python_hash_seed: int | None = None,
        as_graph_data_json_path: Path | None = None,
        line_filters: tuple[LineFilter, ...] = (),
    ) -> None:
        self.output_dir: Path = output_dir
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.percent_ases_randomly_adopting: tuple[float, ...] = (
            percent_ases_randomly_adopting
        )
        self.scenario_configs: tuple[ScenarioConfig, ...] = scenario_configs
        self.num_trials: int = num_trials
        self.parse_cpus: int = parse_cpus
        self.python_hash_seed: int | None = python_hash_seed
        self._seed_random()

        if not as_graph_data_json_path:
            caida_path: Path = CAIDAASGraphCollector().run()
            _, as_graph_data_json_path = CAIDAASGraphJSONConverter().run(
                caida_as_graph_path=caida_path
            )
        self.as_graph_data_json_path: Path = as_graph_data_json_path

        self.line_filters = line_filters
        if not self.line_filters:
            max_prop_rounds = max(x.propagation_rounds for x in self.scenario_configs)
            line_filters_list: list[LineFilter] = []
            for as_group in [ASNGroups.ALL_WOUT_IXPS]:
                for in_adopting_asns in InAdoptingASNs:
                    for outcome in Outcomes:
                        if outcome == Outcomes.UNDETERMINED:
                            continue
                        line_filters_list.append(
                            LineFilter(
                                as_group=as_group,
                                in_adopting_asns=in_adopting_asns,
                                # By default, we only track the last propagation round
                                prop_round=max_prop_rounds - 1,
                                outcome=outcome,
                            )
                        )
            self.line_filters = tuple(line_filters_list)

        # Can't delete this since it gets deleted in multiprocessing for some reason
        # NOTE: Once pypy gets to 3.12, just pass delete=False to this
        with TemporaryDirectory() as tmp_dir:
            tmp_dir_str = tmp_dir
        self._tqdm_tracking_dir: Path = Path(tmp_dir_str)
        self._tqdm_tracking_dir.mkdir(parents=True)

    def _seed_random(self, seed_suffix: str = "") -> None:
        """Seeds randomness"""

        if self.python_hash_seed is not None:
            msg = (
                f"You've set the python_hash_seed to {self.python_hash_seed}, but "
                "the simulations aren't deterministic unless you also set the "
                "PYTHONHASHSEED in the env, such as with \n"
                f"export PYTHONHASHSEED={self.python_hash_seed}"
            )
            if os.environ.get("PYTHONHASHSEED") != str(self.python_hash_seed):
                raise RuntimeError(msg)
            random.seed(str(self.python_hash_seed) + seed_suffix)

    def _validate_init(self):
        """Validates inputs to __init__

        Specifically checks for:
        1. scenario config mismatch between adopting and base policies
        2. duplicate scenario labels
        3. RAM constraints
        """

        self._validate_scenario_configs()
        self._validate_ram()

    def _validate_scenario_configs(self) -> None:
        """Validates ScenarioConfigs

        prevents duplicate scenario labels and ensures no mixups using BGPFull
        """

        scenario_labels = [x.label for x in self.scenario_configs]

        if len(set(scenario_labels)) != len(scenario_labels):
            raise ValueError(
                "Each ScenarioConfig uses a scenario_label when aggregating results "
                "Since you have two ScenarioConfig's with the same label, data "
                "won't be tracked properly. Please pass in a scenario_label= with a "
                "unique label name to your config"
            )

        for scenario_config in self.scenario_configs:
            if (
                scenario_config.num_attackers == 0
                and scenario_config.num_legitimate_origins == 0
            ):
                raise ValueError(
                    "ScenarioConfig has no attackers or victims. "
                    "Set num_attackers and/or num_legitimate_origins = 1 "
                    "or more "
                )

    def _validate_ram(self) -> None:
        """Validates that the RAM will not run out of bounds

        NOTE: all these values where obtained using pypy3.10 on a lenovo laptop
        """

        # NOTE: These are for PyPy, not Python
        total_gb_ram_per_core = 1.6

        expected_total_gb_ram = self.parse_cpus * total_gb_ram_per_core
        # Gets available RAM and converts to GB
        total_gb_ram = psutil.virtual_memory().available / (1024**3)

        bgpsimulator_logger.info(f"Expected RAM usage: {expected_total_gb_ram:.2f}")
        bgpsimulator_logger.info(f"Available RAM: {total_gb_ram:.2f}")
        if expected_total_gb_ram * 1.1 > total_gb_ram:
            warn(
                f"Estimated RAM usage is {expected_total_gb_ram:.2f}GB "
                f"but your machine has only {total_gb_ram:.2f}GB available, "
                "maybe use less cores or don't store provider/customer cones?",
                stacklevel=2,
            )

    ##############
    # Run Funcs #
    ##############

    def run(
        self,
        GraphFactoryCls: type[LineChartFactory] = LineChartFactory,
        graph_factory_kwargs: dict[str, Any] | None = None,
    ):  # , GraphFactoryCls: type[GraphFactory] = GraphFactory,
        # graph_factory_kwargs: dict[str, Any] | None = None) -> None:
        """Runs the simulation and writes the data"""

        data_tracker = self._get_data()
        self._write_data(data_tracker)
        self._graph_data(GraphFactoryCls, graph_factory_kwargs)
        # This object holds a lot of memory, good to get rid of it
        del data_tracker
        gc.collect()
        shutil.rmtree(self._tqdm_tracking_dir)

    def _get_data(self) -> DataTracker:
        """Runs trials for graph and aggregates data"""

        # Single process
        if self.parse_cpus == 1:
            # Results are a list of lists of metric trackers that we then sum
            return sum(
                self._get_single_process_results(),
                start=DataTracker(
                    line_filters=self.line_filters,
                    scenario_labels=self.scenario_labels,
                    percent_ases_randomly_adopting=self.percent_ases_randomly_adopting,
                ),
            )
        # Multiprocess
        else:
            # Results are a list of lists of metric trackers that we then sum
            return sum(
                self._get_mp_results(),
                start=DataTracker(
                    line_filters=self.line_filters,
                    scenario_labels=self.scenario_labels,
                    percent_ases_randomly_adopting=self.percent_ases_randomly_adopting,
                ),
            )

    ###########################
    # Multiprocessing Methods #
    ###########################

    def _get_chunks(self, cpus: int) -> list[list[int]]:
        """Returns chunks of trial inputs based on number of CPUs running

        Not a generator since we need this for multiprocessing

        We also don't multiprocess one by one because the start up cost of
        each process is huge (since each process must generate it's own engine
        ) so we must divy up the work beforehand
        """

        trials_list = list(range(self.num_trials))
        return [trials_list[i::cpus] for i in range(cpus)]

    def _get_single_process_results(self) -> list[DataTracker]:
        """Get all results when using single processing"""

        return [self._run_chunk(i, x) for i, x in enumerate(self._get_chunks(1))]

    def _get_mp_results(self) -> list[DataTracker]:
        """Get results from multiprocessing

        Previously used starmap, but now we have tqdm
        """

        # Pool is much faster than ProcessPoolExecutor
        with Pool(self.parse_cpus) as p:
            # return p.starmap(self._run_chunk, enumerate(self._get_chunks(parse_cpus)))
            chunks = self._get_chunks(self.parse_cpus)
            desc = f"Simulating {self.output_dir.name}"
            total = (
                sum(len(x) for x in chunks)
                * len(self.percent_ases_randomly_adopting)
                * len(self.scenario_configs)
            )
            with tqdm(total=total, desc=desc) as pbar:
                tasks: list[ApplyResult[DataTracker]] = [
                    p.apply_async(self._run_chunk, x) for x in enumerate(chunks)
                ]
                completed: list[DataTracker] = []
                while tasks:
                    completed, tasks = self._get_completed_and_tasks(completed, tasks)
                    self._update_tqdm_progress_bar(pbar)
                    time.sleep(0.5)
        return completed

    def _get_completed_and_tasks(self, completed, tasks):
        """Moves completed tasks into completed"""
        new_tasks = list()
        for task in tasks:
            if task.ready():
                completed.append(task.get())
            else:
                new_tasks.append(task)
        return completed, new_tasks

    def _update_tqdm_progress_bar(self, pbar: tqdm) -> None:  # type: ignore
        """Updates tqdm progress bar"""

        total_completed = 0
        for file_path in self._tqdm_tracking_dir.iterdir():
            try:
                total_completed += int(file_path.read_text())
            # Can happen write when file is being written when it's empty
            except ValueError:
                pass
        pbar.n = total_completed
        pbar.refresh()

    ############################
    # Data Aggregation Methods #
    ############################

    def _run_chunk(self, chunk_id: int, trials: list[int]) -> DataTracker:
        """Runs a chunk of trial inputs"""

        # Must also seed randomness here since we don't want multiproc to be the same
        self._seed_random(seed_suffix=str(chunk_id))

        # ASGraph is not picklable, so we need to create it here
        engine = SimulationEngine(
            as_graph=ASGraph.from_json(
                json.loads(self.as_graph_data_json_path.read_text())
            )
        )

        data_tracker = DataTracker(
            line_filters=self.line_filters,
            scenario_labels=self.scenario_labels,
            percent_ases_randomly_adopting=self.percent_ases_randomly_adopting,
        )

        for trial_index, trial in self._get_run_chunk_iter(trials):
            # Use the same attacker victim pairs across all percent adoptions
            trial_attacker_asns = None
            trial_legitimate_origin_asns = None
            for percent_adopt_index, percent_adopt in enumerate(
                self.percent_ases_randomly_adopting
            ):
                # Use the same adopting asns across all scenarios configs
                adopting_asns = None
                for scenario_config_index, scenario_config in enumerate(
                    self.scenario_configs
                ):
                    # Create the scenario for this trial
                    scenario = scenario_config.ScenarioCls(
                        scenario_config=scenario_config,
                        percent_ases_randomly_adopting=percent_adopt,
                        engine=engine,
                        route_validator=Policy.route_validator,
                        attacker_asns=trial_attacker_asns,
                        legitimate_origin_asns=trial_legitimate_origin_asns,
                        adopting_asns=adopting_asns,
                    )

                    # Change AS Classes, seed announcements before propagation
                    scenario.setup_engine(engine)
                    # For each round of propagation run the engine
                    for propagation_round in range(scenario_config.propagation_rounds):
                        self._single_engine_run(
                            engine=engine,
                            percent_ases_randomly_adopting=percent_adopt,
                            trial=trial,
                            scenario=scenario,
                            propagation_round=propagation_round,
                            data_tracker=data_tracker,
                        )
                    # Use the same attacker victim pairs across all percent adoptions
                    if self.reuse_attacker_asns:
                        trial_attacker_asns = scenario.attacker_asns
                    if self.reuse_legitimate_origin_asns:
                        trial_legitimate_origin_asns = scenario.legitimate_origin_asns
                    # Use the same adopting ASEs across all scenarios configs
                    if self.reuse_adopting_asns:
                        adopting_asns = scenario.adopting_asns

                    # Used to track progress with tqdm - update after each
                    # scenario_config
                    total_completed = (
                        trial_index
                        * len(self.percent_ases_randomly_adopting)
                        * len(self.scenario_configs)
                        + percent_adopt_index * len(self.scenario_configs)
                        + scenario_config_index
                        + 1
                    )
                    self._write_tqdm_progress(chunk_id, total_completed)

        self._write_tqdm_progress(
            chunk_id,
            len(trials)
            * len(self.percent_ases_randomly_adopting)
            * len(self.scenario_configs),
        )

        return data_tracker

    @cached_property
    def reuse_attacker_asns(self) -> bool:
        """Reuse the same attacker ASes across all scenarios configs.

        If they're from the same ASN group.
        """
        num_attackers_set = {x.num_attackers for x in self.scenario_configs}
        attacker_asn_groups_set = {x.attacker_asn_group for x in self.scenario_configs}
        return len(num_attackers_set) == 1 and len(attacker_asn_groups_set) == 1

    @cached_property
    def reuse_legitimate_origin_asns(self) -> bool:
        """Reuse the same victim ASes across all scenarios configs.

        If they're from the same ASN group.
        """
        num_legitimate_origins_set = {
            x.num_legitimate_origins for x in self.scenario_configs
        }
        legitimate_origin_asn_groups_set = {
            x.legitimate_origin_asn_group for x in self.scenario_configs
        }
        return (
            len(num_legitimate_origins_set) == 1
            and len(legitimate_origin_asn_groups_set) == 1
        )

    @cached_property
    def reuse_adopting_asns(self) -> bool:
        adoption_asn_groups_set = {
            tuple(x.adoption_asn_groups) for x in self.scenario_configs
        }
        return len(adoption_asn_groups_set) == 1

    def _get_run_chunk_iter(self, trials: list[int]) -> Iterable[tuple[int, int]]:
        """Returns iterator for trials with or without progress bar

        If there's only 1 cpu, run the progress bar here, else we run it elsewhere
        """

        if self.parse_cpus == 1:
            return tqdm(
                enumerate(trials),
                total=len(trials),
                desc=f"Simulating {self.output_dir.name}",
            )
        else:
            return enumerate(trials)

    def _write_tqdm_progress(self, chunk_id: int, completed: int) -> None:
        """Writes total number of percent adoption trial pairs to file"""

        # If self.parse_cpus == 1, then no multiprocessing is used
        if self.parse_cpus > 1:
            with (self._tqdm_tracking_dir / f"{chunk_id}.txt").open("w") as f:
                f.write(str(completed))

    def _single_engine_run(
        self,
        *,
        engine: SimulationEngine,
        percent_ases_randomly_adopting: float,
        trial: int,
        scenario: "Scenario",
        propagation_round: int,
        data_tracker: DataTracker,
    ) -> None:
        """Single engine run"""

        # Run the engine
        engine.propagate(propagation_round=propagation_round, scenario=scenario)

        # Pre-aggregation Hook
        scenario.pre_aggregation_hook(
            engine=engine,
            percent_ases_randomly_adopting=percent_ases_randomly_adopting,
            trial=trial,
            propagation_round=propagation_round,
        )

        self._collect_engine_run_data(
            engine,
            percent_ases_randomly_adopting,
            trial,
            scenario,
            propagation_round,
            data_tracker,
        )

        # By default, this is a no op
        scenario.post_propagation_hook(
            engine=engine,
            percent_ases_randomly_adopting=percent_ases_randomly_adopting,
            trial=trial,
            propagation_round=propagation_round,
        )

    def _collect_engine_run_data(
        self,
        engine: SimulationEngine,
        percent_ases_randomly_adopting: float,
        trial: int,
        scenario: "Scenario",
        propagation_round: int,
        data_tracker: DataTracker,
    ) -> dict[int, Outcomes]:
        # Save all engine run info
        # The reason we aggregate info right now, instead of saving
        # the engine and doing it later, is because doing it all
        # in RAM is MUCH faster, and speed is important
        outcomes = DataPlanePacketPropagator().get_as_outcomes_for_data_plane_packet(
            dest_ip_addr=scenario.dest_ip_addr,
            simulation_engine=engine,
            legitimate_origin_asns=scenario.legitimate_origin_asns,
            attacker_asns=scenario.attacker_asns,
            scenario=scenario,
        )

        data_tracker.store_trial_data(
            engine=engine,
            scenario=scenario,
            propagation_round=propagation_round,
            # dict[int, int] == dict[int, outcomes] (int enum)
            asn_to_packet_outcome_dict=outcomes,
        )
        return outcomes

    #######################
    # Graph Writing Funcs #
    #######################

    def _write_data(self, data_tracker: DataTracker) -> None:
        """Writes data to file"""

        data_tracker.aggregate_data()

        with self.json_path.open("w") as f:
            json.dump(data_tracker.to_json(), f, indent=4, sort_keys=True)
        with self.csv_path.open("w") as f:
            f.write(data_tracker.to_csv())
        bgpsimulator_logger.info(f"Wrote data to {self.json_path} and {self.csv_path}")

    def _graph_data(
        self,
        GraphFactoryCls: type[LineChartFactory] | None = LineChartFactory,
        kwargs=None,
    ) -> None:
        """Generates some default graphs"""

        # This prevents problems if kwargs is reused more than once
        # outside of this file, since we modify it
        kwargs = dict() if kwargs is None else deepcopy(kwargs)
        # Set defaults for kwargs
        kwargs["json_path"] = kwargs.pop("json_path", self.json_path)
        kwargs["graph_dir"] = kwargs.pop("graph_dir", self.graph_output_dir)
        if GraphFactoryCls:
            GraphFactoryCls(**kwargs).generate_line_charts()
            bgpsimulator_logger.info(f"\nWrote graphs to {kwargs['graph_dir']}")

    ##############
    # Properties #
    ##############

    @cached_property
    def scenario_labels(self) -> tuple[str, ...]:
        return tuple([x.label for x in self.scenario_configs])

    @cached_property
    def graph_output_dir(self) -> Path:
        return self.output_dir / "graphs"

    @cached_property
    def json_path(self) -> Path:
        return self.output_dir / "data.json"

    @cached_property
    def csv_path(self) -> Path:
        return self.output_dir / "data.csv"

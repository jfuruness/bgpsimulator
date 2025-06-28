from math import sqrt
from statistics import stdev
from typing import Any

from bgpsimulator.shared import Outcomes
from bgpsimulator.simulation_engine import SimulationEngine
from bgpsimulator.simulation_framework.scenarios.scenario import Scenario

from .line_filter import LineFilter


class DataTracker:
    """Tracks data for later use in creating line charts"""

    __slots__ = (
        "line_filters",
        "scenario_labels",
        "percent_ases_randomly_adopting",
        "unaggregated_data",
        "aggregated_data",
    )

    def __init__(
        self,
        line_filters,
        scenario_labels,
        percent_ases_randomly_adopting,
        unaggregated_data=None,
        aggregated_data=None,
    ) -> None:
        """Format of the unaggregated_data below


        You have the scenario label as the outer key, representing the
        scenario config (who is attacking, defending, adopting, what routing
        policy settings they are using).
        Then for each scenario config/label, you have filters for a line
        (as the next key), using a subset of the data from the
        scenario_config.
        Within that there are the data points for each percent of ASes
        adopting, and their values.
        {
            # Name of the line from the scenario config
            scenario_label: {
                # The subset of data used from the scenario_config to create this line
                line_filter (as_group, in_adopting_asns, prop_round, outcome): {
                    # Data point in the line
                    percent_ases_randomly_adopting: [
                        {
                            # Numerator = achieved outcome of graph filter
                            # and within the filter
                            numerator: 0,
                            # Denominator = within the filter, disregarding outcome
                            denominator: 0
                        }
                    ]
                }
            }
        }

        In aggregated_data (which is the final output), a list of
        numerators and denominators -> averagevalue, yerr (90% confidence
        interval)

        This data structure has gone through many iterations.
        At first, it was a gigantic nested dictionary.
        Then it become a multi nested dictionary using Python classes,
        which were hard to convert to JSON.
        I think this will be the most usable, as it will be pure JSON, not
        a bunch of dataclasses
        and from a high level it makes sense.
        """
        self.line_filters = line_filters
        self.scenario_labels = scenario_labels
        self.percent_ases_randomly_adopting = percent_ases_randomly_adopting
        self.unaggregated_data = (
            unaggregated_data or self._create_new_unaggregated_data()
        )
        self.aggregated_data = (
            aggregated_data
            or {
                label: {line_filter: {} for line_filter in line_filters}
                for label in self.scenario_labels
            }
            or {}
        )

    def _create_new_unaggregated_data(
        self,
    ) -> dict[str, dict[LineFilter, dict[float, list[dict[str, int]]]]]:
        """Creates a new unaggregated data dictionary"""

        data: dict[str, dict[LineFilter, dict[float, list[dict[str, int]]]]] = dict()
        # This is the label of the scenario_config
        for label in self.scenario_labels:
            data[label] = dict()
            # These are the filters for the scenario_config
            # to create the line seen in the graph
            for line_filter in self.line_filters:
                data[label][line_filter] = dict()
                for percent_adopt in self.percent_ases_randomly_adopting:
                    data[label][line_filter][percent_adopt] = list()
        return data

    def __add__(self, other) -> "DataTracker":
        if isinstance(other, DataTracker):
            # Timing trials show this is the fastest way
            new_data = self._create_new_unaggregated_data()
            for label, inner_dict in self.unaggregated_data.items():
                for line_filter, trial_data in inner_dict.items():
                    for (
                        percent_ases_randomly_adopting,
                        _data_points,
                    ) in trial_data.items():
                        new_data[label][line_filter][percent_ases_randomly_adopting] = (
                            self.unaggregated_data[label][line_filter][
                                percent_ases_randomly_adopting
                            ]
                            + other.unaggregated_data[label][line_filter][
                                percent_ases_randomly_adopting
                            ]
                        )
            return DataTracker(
                self.line_filters,
                self.scenario_labels,
                self.percent_ases_randomly_adopting,
                new_data,
            )
        else:
            return NotImplemented

    def store_trial_data(
        self,
        *,
        engine: SimulationEngine,
        scenario: Scenario,
        asn_to_packet_outcome_dict: dict[int, Outcomes],
        propagation_round: int,
    ) -> None:
        """Stores the data for a trial"""

        # Initialize the trial data
        for _label, inner_dict in self.unaggregated_data.items():
            for _line_filter, trial_data in inner_dict.items():
                trial_data.setdefault(
                    scenario.percent_ases_randomly_adopting, []
                ).append({"numerator": 0, "denominator": 0})

        unaggregated_scenario_data = self.unaggregated_data[
            scenario.scenario_config.label
        ]

        for line_filter in unaggregated_scenario_data:
            # We don't need this (since this is also checked in
            # LineFilter), but it saves some time
            if line_filter.prop_round != propagation_round:
                continue
            for as_obj in engine.as_graph:
                # Don't count ASes that are preset, such as attackers, victims, etc.
                if as_obj.asn in scenario.untracked_asns:
                    continue
                outcome = asn_to_packet_outcome_dict[as_obj.asn]
                if line_filter.as_in_denominator(
                    as_obj, engine.as_graph, scenario, propagation_round, outcome
                ):
                    # The default for the numerator simply checks that the
                    # outcome is the same as the line filter
                    if line_filter.as_in_numerator(
                        as_obj, engine.as_graph, scenario, propagation_round, outcome
                    ):
                        unaggregated_scenario_data[line_filter][
                            scenario.percent_ases_randomly_adopting
                        ][-1]["numerator"] += 1
                    unaggregated_scenario_data[line_filter][
                        scenario.percent_ases_randomly_adopting
                    ][-1]["denominator"] += 1

    def aggregate_data(self) -> None:
        """Aggregates the data"""

        for label, inner_dict in self.unaggregated_data.items():
            for line_filter, trial_data in inner_dict.items():
                for percent_ases_randomly_adopting, data_points in trial_data.items():
                    decimal_vals = [
                        x["numerator"] * 100 / x["denominator"]
                        if x["denominator"] != 0
                        else 0
                        for x in data_points
                    ]
                    self.aggregated_data[label][line_filter][
                        percent_ases_randomly_adopting
                    ] = {
                        "value": sum(decimal_vals) / len(decimal_vals),  # average
                        "yerr": self._get_yerr(decimal_vals),
                    }
        # Clear the unaggregated data to save memory
        self.unaggregated_data = {}

    def _get_yerr(self, percent_list: list[float]) -> float:
        """Returns 90% confidence interval for graphing"""

        if len(percent_list) > 1:
            return 1.645 * 2 * stdev(percent_list) / sqrt(len(percent_list))
        else:
            return 0

    def to_json(self) -> dict[str, Any]:
        """Converts the data to a JSON-friendly format"""
        json_data: dict[str, dict[str, dict[str, int]]] = {}
        for label, inner_dict in self.aggregated_data.items():
            json_data[label] = {}
            for line_filter, trial_data in inner_dict.items():
                json_data[label][line_filter.to_json()] = trial_data
        return {
            "line_filters": [x.to_json() for x in self.line_filters],
            "scenario_labels": self.scenario_labels,
            "percent_ases_randomly_adopting": self.percent_ases_randomly_adopting,
            "aggregated_data": json_data,
            "schema_description": DataTracker.__init__.__doc__,
        }

    @classmethod
    def from_json(cls, json_data: dict[str, Any]) -> "DataTracker":
        """Converts the data from a JSON-friendly format"""
        aggregated_data: dict[str, dict[LineFilter, dict[str, int]]] = {}
        for label, inner_dict in json_data["aggregated_data"].items():
            aggregated_data[label] = {}
            for line_filter, trial_data in inner_dict.items():
                aggregated_data[label][LineFilter.from_json(line_filter)] = trial_data
        return cls(
            line_filters=[LineFilter.from_json(x) for x in json_data["line_filters"]],
            scenario_labels=json_data["scenario_labels"],
            percent_ases_randomly_adopting=json_data["percent_ases_randomly_adopting"],
            aggregated_data=aggregated_data,
        )

    def to_csv(self) -> str:
        """Converts the data to a CSV-friendly format"""

        csv_data = (
            "scenario_label,as_group,in_adopting_asns,prop_round,outcome,"
            "percent_ases_randomly_adopting,value,yerr,line_filter_json\n"
        )
        for label, inner_dict in self.aggregated_data.items():
            for line_filter, trial_data in inner_dict.items():
                for percent_ases_randomly_adopting, data_point in trial_data.items():
                    csv_data += (
                        f"{label},{line_filter.to_csv()},"
                        f"{percent_ases_randomly_adopting},"
                        f"{data_point['value']},{data_point['yerr']},"
                        f"{line_filter.to_json()}\n"
                    )
        return csv_data

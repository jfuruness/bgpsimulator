from pathlib import Path
import json

from bgpsimulator.simulation_framework.data_tracker.data_tracker import DataTracker
from bgpsimulator.simulation_framework.data_tracker.line_filter import LineFilter
from bgpsimulator.simulation_framework.scenarios.scenario_config import ScenarioConfig
from bgpsimulator.simulation_framework.scenarios.scenario import Scenario
from .line import Line
from .line_chart import LineChart

class LineChartFactory:
    """Factory for creating line charts"""

    def __init__(self, json_path: Path, graph_dir: Path, xlabel: str = "Percent Adoption", xlim: tuple[float, float] = (0, 100), ylim: tuple[float, float] = (0, 100), legend_loc: str = "best") -> None:
        self.data_tracker = DataTracker.from_json(json.loads(json_path.read_text()))
        self.graph_dir = graph_dir
        self.graph_json_dir.mkdir(parents=True, exist_ok=True)
        self.graph_png_dir.mkdir(parents=True, exist_ok=True)
        self.xlabel = xlabel
        self.xlim = xlim
        self.ylim = ylim
        self.legend_loc = legend_loc

    def generate_line_charts(self) -> None:
        """Generates graphs"""

        # Each line filter is a unique graph
        paths = self._generate_line_chart_jsons()
        paths = self._json_mod_hook(paths)
        self._write_pngs(paths)

    def _generate_line_chart_jsons(self) -> list[Path]:
        paths = []
        for line_filter in self.data_tracker.line_filters:
            paths.append(self._generate_line_chart_json(line_filter))
        return paths

    def _generate_line_chart_json(self, line_filter: LineFilter) -> Path:
        """Generates a graph for a given line filter and scenario label"""

        lines = []
        for scenario_label, inner_dict in self.data_tracker.aggregated_data.items():
            line = Line(scenario_label, [], [], [])
            for percent_ases_randomly_adopting, data_point in inner_dict[line_filter].items():
                line.xs.append(percent_ases_randomly_adopting)
                line.ys.append(data_point["value"])
                line.yerrs.append(data_point["yerr"])
            lines.append(line)
        
        y_label = f"Percent {line_filter.outcome.name.replace('_', ' ').title()}"
        line_chart = LineChart(line_filter, lines, title=line_filter.to_csv(), xlabel=self.xlabel, ylabel=y_label, xlim=self.xlim, ylim=self.ylim, legend_loc=self.legend_loc)
        line_chart_path = self.get_line_chart_path(line_filter, extension="json")
        line_chart_path.write_text(json.dumps(line_chart.to_json(), indent=4, sort_keys=True))
        return line_chart_path

    def _json_mod_hook(self, paths: list[Path]) -> list[Path]:
        """Modifies the json files after they are generated"""
        return paths

    def _write_pngs(self, paths: list[Path]) -> None:
        """Writes the pngs"""
        for path in paths:
            line_chart = LineChart.from_json(json.loads(path.read_text()))
            png_path = Path(str(path.with_suffix(".png")).replace("graph_jsons", "graph_pngs"))
            png_path.parent.mkdir(parents=True, exist_ok=True)
            line_chart.write_graph(png_path)

    @property
    def graph_json_dir(self) -> Path:
        return self.graph_dir / "graph_jsons"

    @property
    def graph_png_dir(self) -> Path:
        return self.graph_dir / "graph_pngs"

    def get_line_chart_path(self, line_filter: LineFilter, extension: str = "json") -> Path:
        path = self.graph_json_dir / f"{line_filter.to_csv().replace(',', '/')}.{extension}"
        path.parent.mkdir(parents=True, exist_ok=True)
        return path
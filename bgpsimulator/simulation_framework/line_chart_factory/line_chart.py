import gc
from pathlib import Path
from statistics import mean
from typing import Any

import matplotlib as mpl
import matplotlib.pyplot as plt

from bgpsimulator.simulation_framework.data_tracker import LineFilter

from .line import Line


class LineChart:
    """A line chart"""

    def __init__(
        self,
        line_filter: LineFilter,
        lines: list[Line],
        title: str,
        xlabel: str,
        ylabel: str,
        xlim: tuple[float, float],
        ylim: tuple[float, float],
        legend_loc: str = "best",
    ) -> None:
        self.line_filter = line_filter
        self.lines = lines
        self.title = title
        self.xlabel = xlabel
        self.ylabel = ylabel
        self.xlim = xlim
        self.ylim = ylim
        self.legend_loc = legend_loc

    def write_graph(self, path: Path) -> None:
        """Writes the graph to a file"""

        mpl.use("Agg")
        fig, ax = plt.subplots()
        fig.set_dpi(300)
        plt.rcParams.update({"font.size": 14, "lines.markersize": 10})

        # Set labels
        # ax.set_ylabel(self.ylabel)
        # ax.set_xlabel(self.xlabel)
        for line in self.lines:
            ax.errorbar(
                line.xs,
                line.ys,
                line.yerrs,
                label=line.label,
                marker=line.marker,
                ls=line.ls,
                color=line.color,
            )

        # Set X and Y axis size
        ax.set_xlim(*self.xlim)
        ax.set_ylim(*self.ylim)

        handles, labels = ax.get_legend_handles_labels()
        label_to_handle_dict = dict(zip(labels, handles, strict=False))

        mean_y_dict = {line.label: mean(line.ys) for line in self.lines}
        sorted_labels = sorted(
            label_to_handle_dict,
            key=lambda label: mean_y_dict[label],
            reverse=True,
        )
        sorted_handles = [label_to_handle_dict[lbl] for lbl in sorted_labels]

        ax.legend(sorted_handles, sorted_labels)
        plt.tight_layout()
        plt.savefig(path)

        # https://stackoverflow.com/a/33343289/8903959
        ax.cla()
        plt.cla()
        plt.clf()
        # If you just close the fig, on machines with many CPUs and trials,
        # there is some sort of a memory leak that occurs. See stackoverflow
        # comment above
        plt.close(fig)
        # If you are running one simulation after the other, matplotlib
        # basically leaks memory. I couldn't find the original issue, but
        # here is a note in one of their releases saying to just call the garbage
        # collector: https://matplotlib.org/stable/users/prev_whats_new/
        # whats_new_3.6.0.html#garbage-collection-is-no-longer-run-on-figure-close
        # and here is the stackoverflow post on this topic:
        # https://stackoverflow.com/a/33343289/8903959
        # Even if this works without garbage collection in 3.5.2, that will break
        # as soon as we upgrade to the latest matplotlib which no longer does
        # If you run the simulations on a machine with many cores and lots of trials,
        # this bug leaks enough memory to crash the server, so we must garbage collect
        gc.collect()

    def to_json(self) -> dict[str, Any]:
        return {
            "line_filter": self.line_filter.to_json(),
            "title": self.title,
            "xlabel": self.xlabel,
            "ylabel": self.ylabel,
            "xlim": self.xlim,
            "ylim": self.ylim,
            "legend_loc": self.legend_loc,
            "lines": [line.to_json() for line in self.lines],
        }

    @classmethod
    def from_json(cls, json_data: dict[str, Any]) -> "LineChart":
        return cls(
            line_filter=LineFilter.from_json(json_data["line_filter"]),
            title=json_data["title"],
            xlabel=json_data["xlabel"],
            ylabel=json_data["ylabel"],
            xlim=json_data["xlim"],
            ylim=json_data["ylim"],
            legend_loc=json_data["legend_loc"],
            lines=[Line.from_json(line) for line in json_data["lines"]],
        )

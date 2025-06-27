from typing import Any

from .line_properties_generator import LinePropertiesGenerator

GENERATOR = LinePropertiesGenerator()


class Line:
    """A line in a line chart"""

    def __init__(
        self,
        label: str,
        xs: list[float],
        ys: list[float],
        yerrs: list[float],
        marker: str = "",
        ls: str = "",
        color: str = "",
    ) -> None:
        self.label: str = label
        self.xs: list[float] = xs
        self.ys: list[float] = ys
        self.yerrs: list[float] = yerrs
        self.marker: str = marker
        self.ls: str = ls
        self.color: str = color

        if not self.marker:
            self.marker = GENERATOR.get_marker()
        if not self.ls:
            self.ls = GENERATOR.get_line_style()
        if not self.color:
            self.color = GENERATOR.get_color()

    def to_json(self) -> dict[str, Any]:
        return {
            "label": self.label,
            "xs": self.xs,
            "ys": self.ys,
            "yerrs": self.yerrs,
            "marker": self.marker,
            "ls": self.ls,
            "color": self.color,
        }

    @classmethod
    def from_json(cls, json_data: dict[str, Any]) -> "Line":
        return cls(
            label=json_data["label"],
            xs=[float(x) for x in json_data["xs"]],
            ys=[float(y) for y in json_data["ys"]],
            yerrs=[float(yerr) for yerr in json_data["yerrs"]],
            marker=json_data["marker"],
            ls=json_data["ls"],
            color=json_data["color"],
        )

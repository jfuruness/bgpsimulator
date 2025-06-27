import re
from pathlib import Path

from bgpsimulator.as_graphs import AS, ASGraph
from bgpsimulator.shared import ASNGroups, InAdoptingASNs, Outcomes
from bgpsimulator.simulation_framework.scenarios.scenario import Scenario


class LineFilter:
    """Filters for a line in a line chart

    Checks for each AS whether it meets the filter criteria, aside from
    the outcome

    The outcome is used only for the numerator of the data point, the
    denominator is always the total number of ASes in the group

    You can always subclass this and change your criteria for the numerator
    and denominator
    """

    __slots__ = ("asn_group", "in_adopting_asns", "prop_round", "outcome", "_hash")

    def __init__(
        self,
        as_group: ASNGroups,
        in_adopting_asns: InAdoptingASNs,
        prop_round: int,
        outcome: Outcomes,
    ) -> None:
        self.asn_group = as_group
        self.in_adopting_asns = in_adopting_asns
        self.prop_round = prop_round
        self.outcome = outcome
        self._hash = hash(self.to_json())

    def as_in_denominator(
        self,
        as_obj: AS,
        as_graph: ASGraph,
        scenario: Scenario,
        propagation_round: int,
        outcome: Outcomes,
    ) -> bool:
        """Checks if the AS meets the filter criteria, aside from the outcome

        The outcome is used only for the numerator of the data point, the
        denominator is always the total number of ASes in the group
        """
        if propagation_round != self.prop_round:
            return False
        elif as_obj.asn not in as_graph.asn_groups[self.asn_group]:
            return False
        elif (
            self.in_adopting_asns == InAdoptingASNs.TRUE
            and as_obj.asn not in scenario.adopting_asns
        ):
            return False
        elif (
            self.in_adopting_asns == InAdoptingASNs.FALSE
            and as_obj.asn in scenario.adopting_asns
        ):
            return False
        else:
            return True

    def as_in_numerator(
        self,
        as_obj: AS,
        as_graph: ASGraph,
        scenario: Scenario,
        propagation_round: int,
        outcome: Outcomes,
    ) -> bool:
        """Checks if the AS should be included in the numerator of the data point

        NOTE: as_in_denominator is already checked before this function is
        called, so we don't need to check it again
        """

        return outcome == self.outcome

    def __hash__(self) -> int:
        return self._hash

    def __repr__(self) -> str:
        return self.to_json()

    def __eq__(self, other) -> bool:
        if isinstance(other, LineFilter):
            return (
                self.asn_group == other.asn_group
                and self.in_adopting_asns == other.in_adopting_asns
                and self.prop_round == other.prop_round
                and self.outcome == other.outcome
            )
        else:
            return NotImplemented

    def to_json(self) -> str:
        """Returns a JSON-friendly string that can be used as a key"""
        return (
            f"All ASes in AS Group({self.asn_group}) "
            f"where adopting is set to ({self.in_adopting_asns}) "
            f"and propagation round is ({self.prop_round}) "
            f"and outcome is ({self.outcome})"
        )

    def to_csv(self) -> str:
        """Returns a CSV-friendly string"""
        return (
            f"{self.asn_group},{self.in_adopting_asns},"
            f"{self.prop_round},{self.outcome.name}"
        )

    @classmethod
    def from_json(cls, string: str) -> "LineFilter":
        """Converts a JSON-friendly string back to a LineFilter"""
        matches = re.findall(r"\((.*?)\)", string)
        if len(matches) != 4:
            raise ValueError(
                f"Expected 4 values in parentheses, got {len(matches)}: {matches}"
            )
        as_group, in_adopting_asns, prop_round, outcome = matches
        return cls(
            as_group=ASNGroups(as_group),
            in_adopting_asns=InAdoptingASNs(in_adopting_asns),
            prop_round=int(prop_round),
            outcome=Outcomes(int(outcome)),
        )

    def get_json_path(self, base_dir: Path) -> Path:
        path = (
            base_dir
            / "graph_jsons"
            / f"as_group_is_{self.asn_group.name}"
            / f"adopting_is_{self.in_adopting_asns.name}"
            / f"propagation_round_{self.prop_round}"
            / f"{self.outcome.name}.json"
        )
        path.parent.mkdir(exist_ok=True, parents=True)
        return path

    def get_png_path(self, base_dir: Path) -> Path:
        path = (
            base_dir
            / "graph_pngs"
            / f"as_group_is_{self.asn_group.name}"
            / f"adopting_is_{self.in_adopting_asns.name}"
            / f"propagation_round_{self.prop_round}"
            / f"{self.outcome.name}.png"
        )
        path.parent.mkdir(exist_ok=True, parents=True)
        return path

from functools import cached_property
from typing import Any

from bgpsimulator.shared import Prefix, ROARouted, ROAValidity


class ROA:
    def __init__(
        self,
        prefix: Prefix,
        origin: int,
        max_length: int | None = None,
        ta: str | None = None,
    ):
        self.prefix: Prefix = prefix
        self.origin: int = origin
        self.max_length: int = max_length or self.prefix.prefixlen
        self.ta: str | None = ta

    def __hash__(self) -> int:
        return hash((self.prefix, self.origin, self.max_length, self.ta))

    def __eq__(self, other: object) -> bool:
        if isinstance(other, ROA):
            return (
                self.prefix == other.prefix
                and self.origin == other.origin
                and self.max_length == other.max_length
                and self.ta == other.ta
            )
        return NotImplemented

    @cached_property
    def routed_status(self) -> ROARouted:
        return ROARouted.ROUTED if self.is_routed else ROARouted.NON_ROUTED

    @cached_property
    def is_routed(self) -> bool:
        return self.origin != 0

    @cached_property
    def is_non_routed(self) -> bool:
        return not self.is_routed

    def covers_prefix(self, prefix: Prefix) -> bool:
        """Returns True if the ROA covers the prefix"""

        # NOTE: subnet_of includes the original prefix (I checked lol)
        return prefix.subnet_of(self.prefix)

    def get_validity(self, prefix: Prefix, origin: int) -> ROAValidity:
        """Returns validity of prefix origin pair"""

        if self.covers_prefix(prefix):
            if prefix.prefixlen > self.max_length and origin != self.origin:
                return ROAValidity.INVALID_LENGTH_AND_ORIGIN
            elif prefix.prefixlen > self.max_length and origin == self.origin:
                return ROAValidity.INVALID_LENGTH
            elif prefix.prefixlen <= self.max_length and origin != self.origin:
                return ROAValidity.INVALID_ORIGIN
            elif prefix.prefixlen <= self.max_length and origin == self.origin:
                return ROAValidity.VALID
            else:
                raise NotImplementedError("This should never happen")
        else:
            return ROAValidity.UNKNOWN

    def get_outcome(self, prefix: Prefix, origin: int) -> tuple[ROAValidity, ROARouted]:
        """Returns outcome of prefix origin pair"""

        return self.get_validity(prefix, origin), self.routed_status

    def to_json(self) -> dict[str, Any]:
        """Converts the ROA to a JSON object"""
        return {
            "prefix": str(self.prefix),
            "origin": self.origin,
            "max_length": self.max_length,
            "ta": self.ta,
        }

    @classmethod
    def from_json(cls, json_obj: dict[str, Any]) -> "ROA":
        """Converts a JSON object to a ROA"""
        return cls(
            prefix=Prefix(json_obj["prefix"]),
            origin=int(json_obj["origin"]),
            max_length=int(json_obj["max_length"]),
            ta=json_obj.get("ta"),
        )

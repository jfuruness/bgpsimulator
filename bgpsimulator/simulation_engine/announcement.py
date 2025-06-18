from dataclasses import asdict, dataclass, replace
from typing import Any, Optional
from warnings import warn

from yamlable import YamlAble, yaml_info

from bgpy.shared.enums import Relationships


class Announcement:
    """BGP Announcement"""

    __slots__ = ("prefix", "as_path", "next_hop_asn", "recv_relationship", "timestamp", "bgpsec_next_asn", "bgpsec_as_path", "only_to_customers", "rovpp_blackhole")

    def __init__(
        self,
        prefix: str,
        as_path: tuple[int, ...],
        next_hop_asn: int | None = None,
        recv_relationship: Relationships = Relationships.ORIGIN,
        timestamp: int = 0,
        bgpsec_next_asn: int | None = None,
        bgpsec_as_path: tuple[int, ...] | None = None,
        only_to_customers: int | None = None,
        rovpp_blackhole: bool = False,
    ):
        self.prefix: str = prefix
        self.as_path: tuple[int, ...] = as_path
        # Equivalent to the next hop in a normal BGP announcement
        self.next_hop_asn: int = next_hop_asn or as_path[-1]
        self.recv_relationship: Relationships = recv_relationship
        self.timestamp: int = timestamp
        self.bgpsec_next_asn: int | None = bgpsec_next_asn
        self.bgpsec_as_path: tuple[int, ...] = bgpsec_as_path or ()
        self.only_to_customers: int | None = only_to_customers
        self.rovpp_blackhole: bool = rovpp_blackhole

        if self.next_hop_asn is None:
            # next hop defaults to None, messing up the type
            if len(self.as_path) == 1:  # type: ignore
                self.next_hop_asn = self.as_path[0]
            elif len(self.as_path) > 1:
                raise ValueError(
                    "Announcement was initialized with an AS path longer than 1 "
                    f"({self.as_path}) but the next_hop_asn is ambiguous. "
                    " next_hop_asn is where the traffic should route to next."
                    "Please add "
                    "the next_hop_asn to the initialization parameters "
                    f"for the announcement of prefix {self.prefix}"
                )
            else:
                # Path is either zero or some other case we didn't account for
                raise NotImplementedError

    def copy(
        self,
        prefix: str | None = None,
        as_path: tuple[int, ...] | None = None,
        next_hop_asn: int | None = None,
        recv_relationship: Relationships | None = None,
        timestamp: int | None = None,
        bgpsec_next_asn: int | None = None,
        bgpsec_as_path: tuple[int, ...] | None = None,
        only_to_customers: int | None = None,
        rovpp_blackhole: bool | None = None,
    ) -> "Announcement":
        """Creates a new announcement with the same attributes"""
        return Announcement(
            prefix=prefix or self.prefix,
            as_path=as_path or self.as_path,
            next_hop_asn=next_hop_asn or self.next_hop_asn,
            recv_relationship=recv_relationship or self.recv_relationship,
            timestamp=timestamp or self.timestamp,
            bgpsec_next_asn=bgpsec_next_asn or self.bgpsec_next_asn,
            bgpsec_as_path=bgpsec_as_path or self.bgpsec_as_path,
            only_to_customers=only_to_customers or self.only_to_customers,
            rovpp_blackhole=rovpp_blackhole or self.rovpp_blackhole,
        )

    def __str__(self) -> str:
        return f"{self.prefix} {self.as_path} {self.recv_relationship}"

    @property
    def origin(self) -> int:
        """Returns the origin of the announcement"""

        return self.as_path[-1]

    def to_json(self) -> dict[str, Any]:
        """Converts the announcement to a JSON object"""
        return vars(self)

    @classmethod
    def from_json(cls, json_obj: dict[str, Any]) -> "Announcement":
        return cls(
            prefix=json_obj["prefix"],
            as_path=json_obj["as_path"],
            next_hop_asn=json_obj["next_hop_asn"],
            recv_relationship=json_obj["recv_relationship"],
            timestamp=json_obj["timestamp"],
            bgpsec_next_asn=json_obj["bgpsec_next_asn"],
            bgpsec_as_path=json_obj["bgpsec_as_path"],
            only_to_customers=json_obj["only_to_customers"],
            rovpp_blackhole=json_obj["rovpp_blackhole"],
        )
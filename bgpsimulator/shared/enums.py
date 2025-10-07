from enum import Enum, IntEnum, StrEnum

from .prefix import Prefix


class Relationships(IntEnum):
    """Relationships between ASes.

    Higher numbers == higher priority for announcements
    """

    # Must start at one for the priority
    PROVIDERS = 1
    PEERS = 2
    # Customers have highest priority
    # Economic incentives first!
    CUSTOMERS = 3
    # Origin must always remain since the AS created it
    ORIGIN = 4
    # Unknown for external programs like extrapolator
    UNKNOWN = 5


class ASNGroups(StrEnum):
    """ASN groups"""

    TIER_1 = "tier_1"
    ETC = "etc"
    STUBS_OR_MH = "stubs_or_mh"
    ALL_WOUT_IXPS = "all_wout_ixps"
    STUBS = "stubs"
    MULTIHOMED = "multihomed"
    TRANSIT = "transit"
    IXPS = "ixps"


class Settings(IntEnum):
    """Routing policy settings"""

    ANNOUNCE_THEN_WITHDRAW = 0
    AS_PATH_EDGE_FILTER = 1
    ASPA = 2
    ASPA_W_N = 3
    ASPAPP = 4
    ASRA = 5
    BGPSEC = 6
    BGP_FULL = 7
    BGP_I_SEC = 8
    BGP_I_SEC_TRANSITIVE = 9
    ENFORCE_FIRST_AS = 10
    FIRST_ASN_STRIPPING_PREFIX_HIJACK_CUSTOMERS = 11
    LEAKER = 12
    NEVER_PROPAGATE_WITHDRAWALS = 13
    NEVER_WITHDRAW = 14
    ONLY_TO_CUSTOMERS = 15
    ORIGIN_PREFIX_HIJACK_CUSTOMERS = 16
    PATH_END = 17
    PEERLOCK_LITE = 18
    PEER_ROV = 19
    PROVIDER_CONE_ID = 20
    ROST = 21
    ROV = 22
    ROVPP_V1_LITE = 23
    ROVPP_V2I_LITE = 24
    ROVPP_V2_LITE = 25


class ROAValidity(IntEnum):
    """ROAValidity values

    NOTE: it's possible that you could have two ROAs for
    the same prefix, each with different reasons why they are
    invalid. In that case, the ROAChecker returns the "best"
    validity (in the order below). It doesn't really matter,
    since they are both invalid anyways, and that's the only
    case where this conflict can occur
    """

    # NOTE: These values double as "scores" for validity,
    # so do NOT change the orders
    # (used in the ROA class)
    VALID = 0
    UNKNOWN = 1
    INVALID_LENGTH = 2
    INVALID_ORIGIN = 3
    INVALID_LENGTH_AND_ORIGIN = 4

    @staticmethod
    def is_valid(roa_validity: "ROAValidity") -> bool:
        return roa_validity == ROAValidity.VALID

    @staticmethod
    def is_unknown(roa_validity: "ROAValidity") -> bool:
        return roa_validity == ROAValidity.UNKNOWN

    @staticmethod
    def is_invalid(roa_validity: "ROAValidity") -> bool:
        return roa_validity in (
            ROAValidity.INVALID_LENGTH,
            ROAValidity.INVALID_ORIGIN,
            ROAValidity.INVALID_LENGTH_AND_ORIGIN,
        )


class ROARouted(IntEnum):
    ROUTED = 0
    UNKNOWN = 1
    # A ROA is Non Routed if it is for an origin of ASN 0
    # This means that the prefix for this ROA should never be announced
    NON_ROUTED = 2


class CommonPrefixes(Enum):
    """Prefixes for attacks.

    Prefixes tend to be in reference to the legitimate origin.
    """

    SUPERPREFIX = Prefix("1.0.0.0/8")
    PREFIX = Prefix("1.2.0.0/16")
    SUBPREFIX = Prefix("1.2.3.0/24")


class Timestamps(IntEnum):
    """Timestamps for announcements. Legitimate origin is always first."""

    LEGITIMATE_ORIGIN = 0
    ATTACKER = 1


class Outcomes(IntEnum):
    ATTACKER_SUCCESS = 0
    LEGITIMATE_ORIGIN_SUCCESS = 1
    DISCONNECTED = 2
    UNDETERMINED = 3
    DATA_PLANE_LOOP = 4


class InAdoptingASNs(StrEnum):
    TRUE = "True"
    FALSE = "False"
    ANY = "Any"


class CommonASNs(IntEnum):
    """Common ASNs"""

    ATTACKER = 666
    LEGITIMATE_ORIGIN = 777

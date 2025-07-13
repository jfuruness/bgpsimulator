class CycleError(RuntimeError):
    pass


class NoCAIDAURLError(Exception):
    """Raised when no CAIDA URL is found"""

    pass


class GaoRexfordError(RuntimeError):
    """Error that occurs during gao rexford, such as failing to choose an ann"""

    pass


class AnnouncementNotFoundError(RuntimeError):
    """Exception that covers when an Announcement isn't findable

    ex: in local RIB, in AdjRIBsIn, etc
    """

    pass


class ReservedPrefixError(ValueError):
    """Exception that covers when a prefix is reserved"""

    pass


class InvalidIPAddressError(ValueError):
    """Exception that covers when an IP address is invalid"""

    pass

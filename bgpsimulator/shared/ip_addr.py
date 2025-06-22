from .prefix import Prefix
from .exceptions import InvalidIPAddressError


class IPAddr(Prefix):
    """
    IPAddress class that wraps both IPv4 and IPv6 addresses,
    storing them internally as IPv6Network using IPv4-mapped format
    for IPv4 addresses (::ffff:a.b.c.d). Reserved addresses are disallowed.
    """

    __slots__ = ()

    def __init__(self, address: str):
        super().__init__(address)
        if self.prefixlen != 32 and self.prefixlen != 128:
            raise InvalidIPAddressError(f"Invalid IP address: {address}")

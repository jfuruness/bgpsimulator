from .exceptions import InvalidIPAddressError
from .prefix import Prefix


class IPAddr(Prefix):
    """
    IPAddress class that wraps both IPv4 and IPv6 addresses,
    storing them internally as IPv6Network using IPv4-mapped format
    for IPv4 addresses (::ffff:a.b.c.d). Reserved addresses are disallowed.
    """

    __slots__ = ()

    def __init__(self, address: str):
        super().__init__(address)
        if self.prefixlen not in {32, 128}:
            raise InvalidIPAddressError(f"Invalid IP address: {address}")

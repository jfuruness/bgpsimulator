from ipaddress import IPv6Network, ip_network

from .exceptions import ReservedPrefixError


class Prefix(IPv6Network):
    """Prefix class that is faster than ipaddress.ip_network

    All prefixes (IPv4 and IPv6) are internally stored as IPv6 addresses
    using IPv4-mapped IPv6 format (::ffff:a.b.c.d) for IPv4 addresses.
    """

    __slots__ = ("_hash",)

    def __init__(self, prefix: str, *args, **kwargs):
        """Create a fast Prefix from a string."""

        prefix = str(prefix)
        self._og_str_prefix = prefix
        temp_prefix = ip_network(prefix)
        if temp_prefix.is_reserved:
            raise ReservedPrefixError(
                f"Prefix {prefix} is reserved. Reserved prefixes can't be used "
                "since we map IPv4 prefixes to IPv6 prefixes."
            )
        if temp_prefix.version == 4:
            prefix = (
                f"::ffff:{temp_prefix.network_address}/{96 + temp_prefix.prefixlen}"
            )

        # Prefix is used as a key in dicts, so hash it in advance as it gets
        # called millions of times. We multiply the network address by 1000 to
        # avoid collisions with IPv6 prefix lengths (max 128)
        self._hash: int = hash(
            int(ip_network(prefix).network_address) * 1000 + temp_prefix.prefixlen
        )

        super().__init__(prefix, *args, **kwargs)

    def __hash__(self) -> int:
        return self._hash

    def __eq__(self, other) -> bool:
        if isinstance(other, Prefix):
            return self._hash == other._hash
        else:
            return NotImplemented

    def __str__(self) -> str:
        return self._og_str_prefix

    def __repr__(self) -> str:
        return self._og_str_prefix

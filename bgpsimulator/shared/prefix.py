"""High-performance immutable Prefix class for BGP simulations.

This module provides a Prefix class that:
- Maps both IPv4 and IPv6 to IPv6 for unified representation
- Is immutable with slots for performance
- Provides all functionality needed by BGPy, ROAChecker, and lib_cidr_trie
- Optimizes copying and comparison operations
"""

from __future__ import annotations

import ipaddress
from functools import lru_cache
from typing import Union, TypeVar, Generic, Dict, WeakValueDictionary
import weakref

__all__ = ['Prefix', 'ip_prefix']

PrefixType = TypeVar('PrefixType', bound='Prefix')

# Memory pool for common prefixes to reduce memory usage
_prefix_pool: Dict[str, 'Prefix'] = {}
_prefix_weak_pool: WeakValueDictionary[str, 'Prefix'] = WeakValueDictionary()

# Fast paths for common prefix patterns
_IPV4_MAPPED_BASE = 0xffff00000000


def _fast_ipv4_to_ipv6_int(ipv4_int: int) -> int:
    """Fast conversion of IPv4 integer to IPv6-mapped integer."""
    return _IPV4_MAPPED_BASE | ipv4_int


@lru_cache(maxsize=2048)
def _parse_prefix_cached(prefix_str: str) -> tuple[ipaddress.IPv6Network, bool, str]:
    """Parse prefix string and return (IPv6Network, is_ipv4_mapped, original_str).
    
    Cached for performance since string parsing is expensive.
    """
    try:
        # Try IPv4 first (more common in BGP)
        ipv4_net = ipaddress.IPv4Network(prefix_str, strict=False)
        # Map IPv4 to IPv6 using RFC 3493 IPv4-mapped IPv6 addresses
        # IPv4 a.b.c.d/n becomes ::ffff:a.b.c.d/(96+n)
        ipv4_int = int(ipv4_net.network_address)
        ipv6_int = _fast_ipv4_to_ipv6_int(ipv4_int)
        ipv6_addr = ipaddress.IPv6Address(ipv6_int)
        ipv6_net = ipaddress.IPv6Network(f"{ipv6_addr}/{96 + ipv4_net.prefixlen}")
        return ipv6_net, True, prefix_str
    except (ipaddress.AddressValueError, ipaddress.NetmaskValueError):
        # Must be IPv6
        try:
            ipv6_net = ipaddress.IPv6Network(prefix_str, strict=False)
            return ipv6_net, False, prefix_str
        except (ipaddress.AddressValueError, ipaddress.NetmaskValueError) as e:
            raise ValueError(f"Invalid prefix: {prefix_str}") from e


def _get_pooled_prefix(prefix_str: str) -> 'Prefix':
    """Get a prefix from the memory pool or create a new one."""
    # Check strong pool first (for very common prefixes)
    if prefix_str in _prefix_pool:
        return _prefix_pool[prefix_str]
    
    # Check weak pool 
    if prefix_str in _prefix_weak_pool:
        return _prefix_weak_pool[prefix_str]
    
    # Create new prefix
    network, is_ipv4_mapped, original_str = _parse_prefix_cached(prefix_str)
    prefix = object.__new__(Prefix)
    object.__setattr__(prefix, '_network', network)
    object.__setattr__(prefix, '_is_ipv4_mapped', is_ipv4_mapped)
    object.__setattr__(prefix, '_original_str', original_str)
    object.__setattr__(prefix, '_hash', None)
    
    # Add to weak pool
    _prefix_weak_pool[prefix_str] = prefix
    
    # Add common prefixes to strong pool
    if _is_common_prefix(prefix_str):
        _prefix_pool[prefix_str] = prefix
    
    return prefix


def _is_common_prefix(prefix_str: str) -> bool:
    """Check if a prefix is common enough to keep in strong pool."""
    # Keep default routes and very common prefixes in strong pool
    return prefix_str in {
        '0.0.0.0/0', '::/0',  # Default routes
        '192.168.0.0/16', '10.0.0.0/8', '172.16.0.0/12',  # RFC 1918
        '1.2.0.0/16', '1.2.3.0/24', '1.2.3.4/32',  # Common test prefixes
    }


class Prefix:
    """High-performance immutable prefix class with IPv4->IPv6 mapping.
    
    All IPv4 prefixes are internally represented as IPv6 using RFC 3493
    IPv4-mapped addresses (::ffff:0:0/96 prefix).
    
    This provides:
    - Unified representation for both IPv4 and IPv6
    - Immutability for safe sharing and hashing
    - Performance optimization through slots and caching
    - All functionality needed by BGPy, ROAChecker, and lib_cidr_trie
    """
    
    __slots__ = ('_network', '_is_ipv4_mapped', '_original_str', '_hash')
    
    def __init__(self, prefix: Union[str, ipaddress.IPv4Network, ipaddress.IPv6Network, Prefix]):
        """Create a Prefix from various input types.
        
        Args:
            prefix: String like "192.168.1.0/24", ipaddress object, or another Prefix
        """
        if isinstance(prefix, Prefix):
            # Fast copy constructor
            object.__setattr__(self, '_network', prefix._network)
            object.__setattr__(self, '_is_ipv4_mapped', prefix._is_ipv4_mapped)
            object.__setattr__(self, '_original_str', prefix._original_str)
            object.__setattr__(self, '_hash', prefix._hash)
        elif isinstance(prefix, str):
            network, is_ipv4_mapped, original_str = _parse_prefix_cached(prefix)
            object.__setattr__(self, '_network', network)
            object.__setattr__(self, '_is_ipv4_mapped', is_ipv4_mapped)
            object.__setattr__(self, '_original_str', original_str)
            object.__setattr__(self, '_hash', None)
        elif isinstance(prefix, ipaddress.IPv4Network):
            # Convert IPv4 to IPv6 representation using fast path
            ipv4_int = int(prefix.network_address)
            ipv6_int = _fast_ipv4_to_ipv6_int(ipv4_int)
            ipv6_addr = ipaddress.IPv6Address(ipv6_int)
            ipv6_net = ipaddress.IPv6Network(f"{ipv6_addr}/{96 + prefix.prefixlen}")
            object.__setattr__(self, '_network', ipv6_net)
            object.__setattr__(self, '_is_ipv4_mapped', True)
            object.__setattr__(self, '_original_str', str(prefix))
            object.__setattr__(self, '_hash', None)
        elif isinstance(prefix, ipaddress.IPv6Network):
            object.__setattr__(self, '_network', prefix)
            object.__setattr__(self, '_is_ipv4_mapped', False)
            object.__setattr__(self, '_original_str', str(prefix))
            object.__setattr__(self, '_hash', None)
        else:
            raise TypeError(f"Cannot create Prefix from {type(prefix)}")
    
    def __setattr__(self, name: str, value) -> None:
        """Prevent modification after creation."""
        raise AttributeError("Prefix objects are immutable")
    
    def __delattr__(self, name: str) -> None:
        """Prevent deletion after creation."""
        raise AttributeError("Prefix objects are immutable")
    
    # String representation
    def __str__(self) -> str:
        """Return string representation, preserving original format when possible."""
        if self._is_ipv4_mapped:
            # Convert back to IPv4 representation
            ipv6_int = int(self._network.network_address)
            ipv4_int = ipv6_int & 0xffffffff
            ipv4_addr = ipaddress.IPv4Address(ipv4_int)
            ipv4_prefixlen = self._network.prefixlen - 96
            return f"{ipv4_addr}/{ipv4_prefixlen}"
        else:
            return str(self._network)
    
    def __repr__(self) -> str:
        """Return detailed representation."""
        return f"Prefix('{self}')"
    
    # Equality and hashing
    def __eq__(self, other) -> bool:
        """Check equality based on network representation."""
        if not isinstance(other, Prefix):
            return NotImplemented
        return self._network == other._network
    
    def __ne__(self, other) -> bool:
        """Check inequality."""
        result = self.__eq__(other)
        if result is NotImplemented:
            return result
        return not result
    
    def __hash__(self) -> int:
        """Hash based on network representation."""
        if self._hash is None:
            object.__setattr__(self, '_hash', hash(self._network))
        return self._hash
    
    # Comparison operators for sorting
    def __lt__(self, other) -> bool:
        """Less than comparison for sorting."""
        if not isinstance(other, Prefix):
            return NotImplemented
        return self._network < other._network
    
    def __le__(self, other) -> bool:
        """Less than or equal comparison."""
        if not isinstance(other, Prefix):
            return NotImplemented
        return self._network <= other._network
    
    def __gt__(self, other) -> bool:
        """Greater than comparison."""
        if not isinstance(other, Prefix):
            return NotImplemented
        return self._network > other._network
    
    def __ge__(self, other) -> bool:
        """Greater than or equal comparison."""
        if not isinstance(other, Prefix):
            return NotImplemented
        return self._network >= other._network
    
    # Network properties and methods
    @property
    def version(self) -> int:
        """Return IP version (4 for IPv4-mapped, 6 for native IPv6)."""
        return 4 if self._is_ipv4_mapped else 6
    
    @property
    def prefixlen(self) -> int:
        """Return prefix length in original address family."""
        if self._is_ipv4_mapped:
            return self._network.prefixlen - 96
        return self._network.prefixlen
    
    @property
    def num_addresses(self) -> int:
        """Return number of addresses in this prefix."""
        if self._is_ipv4_mapped:
            # Calculate for IPv4 space
            return 2 ** (32 - self.prefixlen)
        return self._network.num_addresses
    
    def subnet_of(self, other: Prefix) -> bool:
        """Check if this prefix is a subnet of another prefix."""
        if not isinstance(other, Prefix):
            raise TypeError("subnet_of requires another Prefix")
        return self._network.subnet_of(other._network)
    
    def supernet_of(self, other: Prefix) -> bool:
        """Check if this prefix is a supernet of another prefix."""
        if not isinstance(other, Prefix):
            raise TypeError("supernet_of requires another Prefix")
        return self._network.supernet_of(other._network)
    
    def overlaps(self, other: Prefix) -> bool:
        """Check if this prefix overlaps with another prefix."""
        if not isinstance(other, Prefix):
            raise TypeError("overlaps requires another Prefix")
        return self._network.overlaps(other._network)
    
    def __contains__(self, other) -> bool:
        """Check if an address or prefix is contained in this prefix."""
        if isinstance(other, str):
            other = Prefix(other)
        elif isinstance(other, (ipaddress.IPv4Address, ipaddress.IPv6Address, 
                               ipaddress.IPv4Network, ipaddress.IPv6Network)):
            other = Prefix(other)
        
        if isinstance(other, Prefix):
            return other._network.subnet_of(self._network) or other._network == self._network
        
        return NotImplemented
    
    # Compatibility methods for type checking
    def __instancecheck__(self, cls):
        """Support isinstance checks for IPv4Network/IPv6Network."""
        if cls in (ipaddress.IPv4Network, ipaddress.IPv6Network):
            if self._is_ipv4_mapped:
                return cls == ipaddress.IPv4Network
            else:
                return cls == ipaddress.IPv6Network
        return isinstance(self, cls)


def ip_prefix(prefix: Union[str, ipaddress.IPv4Network, ipaddress.IPv6Network, Prefix]) -> Prefix:
    """Create a Prefix object, similar to ipaddress.ip_network().
    
    This is the main factory function for creating Prefix objects.
    Uses memory pooling for string inputs to improve performance.
    
    Args:
        prefix: String, ipaddress object, or existing Prefix
        
    Returns:
        Prefix object
        
    Examples:
        >>> ip_prefix("192.168.1.0/24")
        Prefix('192.168.1.0/24')
        >>> ip_prefix("2001:db8::/32")
        Prefix('2001:db8::/32')
    """
    if isinstance(prefix, Prefix):
        return prefix
    elif isinstance(prefix, str):
        # Use memory pool for string inputs
        return _get_pooled_prefix(prefix)
    else:
        # Create new instance for ipaddress objects
        return Prefix(prefix)
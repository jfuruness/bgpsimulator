from enum import IntEnum


class Relationships(IntEnum):
    """Relationships between ASes. Higher numbers == higher priority for announcements"""
    
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
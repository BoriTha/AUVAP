"""
Utility functions for the APFA Agent.
"""

from .connectivity import (
    check_host_connectivity,
    check_multiple_ports,
    verify_target_before_attack,
    clear_connectivity_cache,
    get_connectivity_cache_stats
)

__all__ = [
    'check_host_connectivity',
    'check_multiple_ports',
    'verify_target_before_attack',
    'clear_connectivity_cache',
    'get_connectivity_cache_stats'
]

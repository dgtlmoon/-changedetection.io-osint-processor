"""
Step Registry - Automatically discovers and registers all scan steps
"""

from typing import List, Type
from .base import ScanStep
from loguru import logger


# Registry of all scan step classes
_STEPS: List[Type[ScanStep]] = []


def register_step(step_class: Type[ScanStep]):
    """
    Register a scan step class.

    Args:
        step_class: ScanStep subclass to register
    """
    _STEPS.append(step_class)
    logger.debug(f"Registered OSINT scan step: {step_class.name} (order: {step_class.order})")
    return step_class


def get_all_steps() -> List[Type[ScanStep]]:
    """
    Get all registered scan steps, sorted by order.

    Returns:
        List of ScanStep classes sorted by their order attribute
    """
    return sorted(_STEPS, key=lambda s: s.order)


def discover_steps():
    """
    Auto-discover and import all step modules.

    This function imports all step modules which triggers their @register_step decorators.
    """
    # Import all step modules to trigger registration
    from . import dns_scan
    from . import whois_scan
    from . import http_scan
    from . import tls_scan
    from . import port_scan
    from . import traceroute_scan
    from . import bgp_scan

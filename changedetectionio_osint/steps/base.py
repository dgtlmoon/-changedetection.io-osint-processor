"""
Base class and interface for OSINT scan steps

All scan steps should inherit from ScanStep and implement:
- scan() method: Performs the actual scanning
- format_results() method: Formats results for output
"""

from abc import ABC, abstractmethod
from typing import Any, Optional


class ScanStep(ABC):
    """
    Base class for OSINT reconnaissance scan steps.

    Each step represents an independent scan operation that can be
    run serially or in parallel with other steps.
    """

    # Step name (used for section header in output)
    # Override in subclass
    name: str = "Unknown Step"

    # Step order/priority (lower numbers run first in serial mode)
    # Override in subclass
    order: int = 100

    @abstractmethod
    async def scan(self, context: dict) -> Any:
        """
        Perform the scan operation.

        Args:
            context: Dictionary containing scan context:
                - hostname: Target hostname
                - ip_address: Resolved IP address
                - url: Full target URL
                - parsed_url: Parsed URL object
                - dns_resolver: Configured DNS resolver
                - proxy_url: Optional proxy URL
                - watch_uuid: Watch UUID for status updates
                - update_signal: Blinker signal for status updates

        Returns:
            Scan results (format depends on scan type)
        """
        pass

    @abstractmethod
    def format_results(self, results: Any) -> str:
        """
        Format scan results for output.

        Args:
            results: Results from scan() method

        Returns:
            Formatted string with section header and content
        """
        pass

    def should_run(self, context: dict) -> bool:
        """
        Determine if this step should run based on context.

        Override this method if the step should only run under certain conditions
        (e.g., TLS scan only for HTTPS URLs).

        Args:
            context: Scan context dictionary

        Returns:
            True if step should run, False otherwise
        """
        return True

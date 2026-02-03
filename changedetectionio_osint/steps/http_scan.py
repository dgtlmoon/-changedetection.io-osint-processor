"""
HTTP Fingerprinting Step
"""

from .base import ScanStep
from .registry import register_step
from . import http_fingerprint


@register_step
class HTTPScanStep(ScanStep):
    """HTTP response fingerprinting, CDN/WAF detection, redirect chains"""

    name = "HTTP Response Fingerprint"
    order = 30

    async def scan(self, context: dict):
        """Perform HTTP fingerprinting"""
        return await http_fingerprint.scan_http(
            context['url'],
            context['dns_resolver'],
            context.get('proxy_url'),
            context.get('watch_uuid'),
            context.get('update_signal')
        )

    def format_results(self, results):
        """Format HTTP results"""
        if results and not isinstance(results, Exception):
            return http_fingerprint.format_http_results(results, context['parsed_url'])
        return "=== HTTP Response Fingerprint ===\nNo data available\n"

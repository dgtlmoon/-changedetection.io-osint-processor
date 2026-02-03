"""
WHOIS Lookup Step
"""

import asyncio
from loguru import logger
from .base import ScanStep
from .registry import register_step


@register_step
class WHOISScanStep(ScanStep):
    """WHOIS domain registration information"""

    name = "WHOIS Information"
    order = 20

    async def scan(self, context: dict):
        """Perform WHOIS lookup"""
        hostname = context['hostname']
        watch_uuid = context.get('watch_uuid')
        update_signal = context.get('update_signal')

        if update_signal and watch_uuid:
            update_signal.send(watch_uuid=watch_uuid, status="WHOIS")

        try:
            import whois
            return await asyncio.to_thread(whois.whois, hostname)
        except Exception as e:
            logger.error(f"WHOIS lookup failed: {e}")
            return None

    def format_results(self, whois_data):
        """Format WHOIS results"""
        lines = []
        lines.append("=== WHOIS Information ===")

        if whois_data and not isinstance(whois_data, Exception):
            field_map = {
                'domain_name': 'Domain Name',
                'registrar': 'Registrar',
                'whois_server': 'WHOIS Server',
                'creation_date': 'Creation Date',
                'expiration_date': 'Expiration Date',
                'updated_date': 'Updated Date',
                'name_servers': 'Name Servers',
                'status': 'Status',
                'dnssec': 'DNSSEC',
                'org': 'Organization',
                'country': 'Country',
            }

            for key, label in field_map.items():
                value = getattr(whois_data, key, None)
                if value:
                    if isinstance(value, list):
                        if key in ['creation_date', 'expiration_date', 'updated_date']:
                            value = value[0] if value else None
                            if value:
                                lines.append(f"{label}: {value}")
                        else:
                            lines.append(f"{label}:")
                            for item in value[:10]:
                                lines.append(f"  - {item}")
                    else:
                        lines.append(f"{label}: {value}")
        else:
            lines.append("No WHOIS data available")

        lines.append("")
        return '\n'.join(lines)

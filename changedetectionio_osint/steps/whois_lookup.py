"""
WHOIS Lookup Step
Performs WHOIS queries using python-whois library
"""

import asyncio
from loguru import logger


async def scan_whois(hostname, watch_uuid=None, update_signal=None):
    """
    Perform WHOIS lookup on hostname

    Args:
        hostname: Target hostname
        watch_uuid: Optional watch UUID for status updates
        update_signal: Optional blinker signal for status updates

    Returns:
        whois.WhoisEntry or None: WHOIS data
    """
    if update_signal and watch_uuid:
        update_signal.send(watch_uuid=watch_uuid, status="WHOIS")

    try:
        import whois
        return await asyncio.to_thread(whois.whois, hostname)
    except Exception as e:
        logger.error(f"WHOIS lookup failed: {e}")
        return None


def format_whois_results(whois_data):
    """Format WHOIS results for output"""
    lines = []
    lines.append("=== WHOIS Information ===")

    if whois_data:
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
                    # Take first item for dates, show all for name servers
                    if key in ['creation_date', 'expiration_date', 'updated_date']:
                        value = value[0] if value else None
                        if value:
                            lines.append(f"{label}: {value}")
                    else:
                        lines.append(f"{label}:")
                        for item in value[:10]:  # Limit to 10 items
                            lines.append(f"  - {item}")
                else:
                    lines.append(f"{label}: {value}")
    else:
        lines.append("No WHOIS data available")

    lines.append("")
    return '\n'.join(lines)

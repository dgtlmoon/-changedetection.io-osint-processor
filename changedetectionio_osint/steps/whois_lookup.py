"""
WHOIS Lookup Step
Performs WHOIS queries using python-whois library
"""

import asyncio
from datetime import datetime, timezone
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


def format_whois_results(whois_data, expire_warning_days=3):
    """Format WHOIS results for output

    Args:
        whois_data: WHOIS data object
        expire_warning_days: Number of days before expiration to show warning (default: 3)
    """
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

        expiration_date = None
        for key, label in field_map.items():
            value = getattr(whois_data, key, None)
            if value:
                if isinstance(value, list):
                    # Take first item for dates, show all for name servers
                    if key in ['creation_date', 'expiration_date', 'updated_date']:
                        value = value[0] if value else None
                        if value:
                            lines.append(f"{label}: {value}")
                            # Track expiration date for countdown calculation
                            if key == 'expiration_date':
                                expiration_date = value
                    else:
                        lines.append(f"{label}:")
                        for item in value[:10]:  # Limit to 10 items
                            lines.append(f"  - {item}")
                else:
                    lines.append(f"{label}: {value}")
                    # Track expiration date for countdown calculation
                    if key == 'expiration_date':
                        expiration_date = value

        # Add expiration countdown if within configured warning days
        if expiration_date and expire_warning_days > 0:
            try:
                # Ensure expiration_date is a datetime object
                if not isinstance(expiration_date, datetime):
                    date_str = str(expiration_date)
                    # Try multiple parsing strategies
                    try:
                        # Try ISO format with Z replacement
                        expiration_date = datetime.fromisoformat(date_str.replace('Z', '+00:00'))
                    except (ValueError, AttributeError):
                        # Try parsing without timezone
                        from dateutil import parser
                        expiration_date = parser.parse(date_str)

                # Make timezone-aware if needed
                if expiration_date.tzinfo is None:
                    expiration_date = expiration_date.replace(tzinfo=timezone.utc)
                # Convert to UTC if it's in a different timezone
                elif expiration_date.tzinfo != timezone.utc:
                    expiration_date = expiration_date.astimezone(timezone.utc)

                now = datetime.now(timezone.utc)
                days_to_expire = (expiration_date - now).days

                if days_to_expire <= expire_warning_days and days_to_expire >= 0:
                    if days_to_expire == 0:
                        lines.append("⚠️  WARNING: Domain expires TODAY!")
                    elif days_to_expire == 1:
                        lines.append("⚠️  WARNING: Domain expires in 1 day")
                    else:
                        lines.append(f"⚠️  WARNING: Domain expires in {days_to_expire} days")
                elif days_to_expire < 0:
                    lines.append("⚠️  WARNING: Domain has EXPIRED!")
            except Exception as e:
                logger.error(f"Could not parse expiration date for countdown: {e}")
                lines.append(f"⚠️  ERROR: Could not parse expiration date format: {e}")
    else:
        lines.append("No WHOIS data available")

    lines.append("")
    return '\n'.join(lines)

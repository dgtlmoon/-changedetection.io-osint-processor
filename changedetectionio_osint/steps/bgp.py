"""
BGP Information Step
Retrieves BGP/ASN information about the target IP
"""

import asyncio
from loguru import logger


async def scan_bgp(ip_address, watch_uuid=None, update_signal=None):
    """
    Retrieve BGP/ASN information for target IP

    Args:
        ip_address: Target IP address
        watch_uuid: Optional watch UUID for status updates
        update_signal: Optional blinker signal for status updates

    Returns:
        dict: BGP/ASN information
    """
    if update_signal and watch_uuid:
        update_signal.send(watch_uuid=watch_uuid, status="BGP")

    def fetch_bgp_info():
        import requests

        bgp_data = {}

        try:
            # Use ip-api.com for basic ASN/ISP info (free, no key needed)
            resp = requests.get(
                f"http://ip-api.com/json/{ip_address}?fields=as,asname,isp,org,hosting",
                timeout=3
            )

            if resp.status_code == 200:
                data = resp.json()
                if data.get('as'):
                    bgp_data['asn'] = data['as']
                if data.get('asname'):
                    bgp_data['as_name'] = data['asname']
                if data.get('isp'):
                    bgp_data['isp'] = data['isp']
                if data.get('org'):
                    bgp_data['organization'] = data['org']
                if data.get('hosting'):
                    bgp_data['hosting'] = 'Yes' if data['hosting'] else 'No'

        except Exception as e:
            logger.error(f"BGP info lookup failed: {e}")

        # Try to get more detailed BGP info from other sources
        # Note: Most BGP APIs require authentication or have rate limits
        # We'll add basic info here and can expand later

        return bgp_data

    try:
        return await asyncio.to_thread(fetch_bgp_info)
    except Exception as e:
        logger.error(f"BGP scan failed: {e}")
        return {}


def format_bgp_results(bgp_data):
    """Format BGP/ASN results for output"""
    lines = []
    lines.append("=== BGP / ASN Information ===")

    if bgp_data:
        if bgp_data.get('asn'):
            lines.append(f"ASN: {bgp_data['asn']}")
        if bgp_data.get('as_name'):
            lines.append(f"AS Name: {bgp_data['as_name']}")
        if bgp_data.get('isp'):
            lines.append(f"ISP: {bgp_data['isp']}")
        if bgp_data.get('organization'):
            lines.append(f"Organization: {bgp_data['organization']}")
        if bgp_data.get('hosting'):
            lines.append(f"Hosting/Datacenter: {bgp_data['hosting']}")
    else:
        lines.append("BGP information not available")

    lines.append("")
    return '\n'.join(lines)

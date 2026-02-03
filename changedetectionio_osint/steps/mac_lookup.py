"""
MAC Address Lookup Step
Gets MAC address from ARP cache for local network targets
"""

import asyncio
import re
import subprocess
from loguru import logger


async def scan_mac(ip_address, watch_uuid=None, update_signal=None):
    """
    Lookup MAC address from ARP cache

    Args:
        ip_address: Target IP address
        watch_uuid: Optional watch UUID for status updates
        update_signal: Optional blinker signal for status updates

    Returns:
        dict: MAC address and vendor info
    """
    if update_signal and watch_uuid:
        update_signal.send(watch_uuid=watch_uuid, status="MAC")

    def get_mac_from_arp():
        """Try to get MAC address from ARP cache"""
        result = {
            'mac_address': None,
            'vendor': None,
            'method': None
        }

        try:
            # Try reading /proc/net/arp on Linux (no root needed)
            try:
                with open('/proc/net/arp', 'r') as f:
                    arp_data = f.read()

                for line in arp_data.split('\n')[1:]:  # Skip header
                    if ip_address in line:
                        parts = line.split()
                        if len(parts) >= 4:
                            mac = parts[3]
                            if mac != '00:00:00:00:00:00' and mac != '<incomplete>':
                                result['mac_address'] = mac.upper()
                                result['method'] = '/proc/net/arp'
                                logger.debug(f"Found MAC {mac} for {ip_address} in /proc/net/arp")
                                break
            except (FileNotFoundError, PermissionError):
                logger.debug("/proc/net/arp not available, trying arp command")

            # Fallback: Try 'ip neigh' command (Linux)
            if not result['mac_address']:
                try:
                    output = subprocess.check_output(
                        ['ip', 'neigh', 'show', ip_address],
                        stderr=subprocess.DEVNULL,
                        timeout=2
                    ).decode('utf-8')

                    # Parse: 192.168.1.1 dev eth0 lladdr aa:bb:cc:dd:ee:ff REACHABLE
                    mac_match = re.search(r'lladdr\s+([0-9a-fA-F:]{17})', output)
                    if mac_match:
                        result['mac_address'] = mac_match.group(1).upper()
                        result['method'] = 'ip neigh'
                        logger.debug(f"Found MAC via 'ip neigh': {result['mac_address']}")
                except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
                    logger.debug("'ip neigh' command failed")

            # Fallback: Try 'arp' command (Linux/Mac)
            if not result['mac_address']:
                try:
                    output = subprocess.check_output(
                        ['arp', '-n', ip_address],
                        stderr=subprocess.DEVNULL,
                        timeout=2
                    ).decode('utf-8')

                    # Parse: 192.168.1.1 ether aa:bb:cc:dd:ee:ff C eth0
                    mac_match = re.search(r'([0-9a-fA-F:]{17})', output)
                    if mac_match:
                        result['mac_address'] = mac_match.group(1).upper()
                        result['method'] = 'arp command'
                        logger.debug(f"Found MAC via 'arp': {result['mac_address']}")
                except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
                    logger.debug("'arp' command failed")

            # Lookup vendor if we found a MAC
            if result['mac_address']:
                result['vendor'] = lookup_mac_vendor(result['mac_address'])

        except Exception as e:
            logger.debug(f"MAC lookup failed: {e}")

        return result

    return await asyncio.to_thread(get_mac_from_arp)


def lookup_mac_vendor(mac_address):
    """
    Lookup MAC vendor from OUI (Organizationally Unique Identifier)

    Args:
        mac_address: MAC address in format AA:BB:CC:DD:EE:FF

    Returns:
        str: Vendor name or None
    """
    try:
        # Try using mac-vendor-lookup library if available
        try:
            from mac_vendor_lookup import MacLookup
            mac = MacLookup()
            vendor = mac.lookup(mac_address)
            return vendor
        except ImportError:
            logger.debug("mac-vendor-lookup not installed, using fallback")
        except Exception as e:
            logger.debug(f"mac-vendor-lookup failed: {e}")

        # Fallback: Basic OUI lookup using common vendors
        # Just first 3 bytes (OUI)
        oui = mac_address[:8].replace(':', '').upper()

        # Common vendor OUIs (just a small sample - full database has 40k+ entries)
        common_ouis = {
            '00005E': 'IANA/ICANN',
            '00000C': 'Cisco Systems',
            '000D3A': 'Cisco Systems',
            '001A2B': 'Cisco Systems',
            '00503E': 'Cisco Systems',
            '001B0D': 'D-Link',
            '0018E7': 'TP-Link',
            '0C8268': 'TP-Link',
            'F4EC38': 'TP-Link',
            '001C7F': 'NETGEAR',
            '002275': 'NETGEAR',
            'A0CCEC': 'NETGEAR',
            'C83A35': 'NETGEAR',
            '000C29': 'VMware',
            '005056': 'VMware',
            '000569': 'VMware',
            '001C14': 'VMware',
            '080027': 'Oracle VirtualBox',
            '525400': 'QEMU Virtual NIC',
            '000000': 'Xerox Corporation',
            '001D7E': 'Raspberry Pi Foundation',
            'B827EB': 'Raspberry Pi Foundation',
            'DC4A3E': 'Raspberry Pi Foundation',
            'E45F01': 'Raspberry Pi Foundation',
            '000A27': 'Apple',
            '000D93': 'Apple',
            '001124': 'Apple',
            '0016CB': 'Apple',
            '001E52': 'Apple',
            '002332': 'Apple',
            '002436': 'Apple',
            '002500': 'Apple',
            '0026BB': 'Apple',
            '00DB70': 'Apple',
            '00E091': 'Microsoft',
            '000BDB': 'Microsoft',
            '001DD8': 'Microsoft',
            '00155D': 'Microsoft Hyper-V',
            '74D435': 'Google',
            'F4F5D8': 'Google',
            '3C5A37': 'Google',
            '000C76': 'Intel',
            '001E67': 'Intel',
            '0024D7': 'Intel',
            '7085C2': 'Intel',
            '001B21': 'Intel',
            '002170': 'Dell',
            '0026B9': 'Dell',
            'D4AE52': 'Dell',
            'F04DA2': 'Dell',
            '002564': 'Dell',
        }

        return common_ouis.get(oui[:6], 'Unknown Vendor')

    except Exception as e:
        logger.debug(f"Vendor lookup failed: {e}")
        return None


def format_mac_results(mac_data):
    """Format MAC address results for output"""
    lines = []
    lines.append("=== MAC Address (Local Network) ===")

    if mac_data and mac_data.get('mac_address'):
        lines.append(f"MAC Address: {mac_data['mac_address']}")
        if mac_data.get('vendor'):
            lines.append(f"Vendor: {mac_data['vendor']}")
        lines.append(f"Detection Method: {mac_data.get('method', 'unknown')}")
        lines.append("")
        lines.append("Note: MAC address only available for local network devices")
    else:
        lines.append("Not available (target not in ARP cache)")
        lines.append("Note: MAC addresses only visible for devices on the same local network")

    lines.append("")
    return '\n'.join(lines)

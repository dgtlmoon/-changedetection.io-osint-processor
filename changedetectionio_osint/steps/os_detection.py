"""
OS Detection Step
Performs operating system fingerprinting when raw socket permissions available
"""

import asyncio
import socket
import struct
from loguru import logger


def check_raw_socket_permission():
    """
    Check if we have raw socket permissions (requires root or CAP_NET_RAW)

    Returns:
        bool: True if raw sockets are available
    """
    try:
        # Try to create a raw ICMP socket
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        s.close()
        return True
    except PermissionError:
        return False
    except OSError as e:
        # Other errors (e.g., protocol not supported)
        logger.debug(f"Raw socket check failed: {e}")
        return False


async def scan_os(ip_address, watch_uuid=None, update_signal=None):
    """
    Perform OS detection/fingerprinting

    Args:
        ip_address: Target IP address
        watch_uuid: Optional watch UUID for status updates
        update_signal: Optional blinker signal for status updates

    Returns:
        dict: OS detection results
    """
    if update_signal and watch_uuid:
        update_signal.send(watch_uuid=watch_uuid, status="OS Detection")

    def detect_os():
        result = {
            'has_raw_socket': False,
            'os_guess': None,
            'confidence': None,
            'ttl': None,
            'method': 'passive'
        }

        # Check for raw socket permissions
        result['has_raw_socket'] = check_raw_socket_permission()

        if result['has_raw_socket']:
            logger.info("Raw socket access available - attempting active OS fingerprinting")
            result['method'] = 'active'

            # Active fingerprinting with raw sockets
            try:
                # Send ICMP ping and analyze TTL
                ttl = get_ttl_via_ping(ip_address)
                if ttl:
                    result['ttl'] = ttl
                    result['os_guess'], result['confidence'] = guess_os_from_ttl(ttl)
            except Exception as e:
                logger.debug(f"Active OS detection failed: {e}")
                result['method'] = 'passive'
        else:
            logger.debug("No raw socket access - OS detection limited to passive methods")

        return result

    return await asyncio.to_thread(detect_os)


def get_ttl_via_ping(ip_address, timeout=2):
    """
    Send ICMP ping and extract TTL from response

    Args:
        ip_address: Target IP
        timeout: Socket timeout in seconds

    Returns:
        int: TTL value or None
    """
    try:
        # Create raw ICMP socket
        icmp = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        icmp.settimeout(timeout)

        # ICMP Echo Request packet
        # Type=8 (Echo Request), Code=0, Checksum=0 (will calculate), ID=0, Seq=0
        packet_id = 12345
        packet_seq = 1

        # Build ICMP header (type, code, checksum, id, sequence)
        header = struct.pack('!BBHHH', 8, 0, 0, packet_id, packet_seq)
        data = b'OSINT' * 10  # 50 bytes of data

        # Calculate checksum
        checksum = calculate_checksum(header + data)
        header = struct.pack('!BBHHH', 8, 0, checksum, packet_id, packet_seq)

        packet = header + data

        # Send packet
        icmp.sendto(packet, (ip_address, 0))

        # Receive response
        try:
            reply, addr = icmp.recvfrom(1024)

            # Extract TTL from IP header (9th byte)
            ttl = reply[8]

            icmp.close()
            logger.debug(f"Received ICMP reply from {ip_address} with TTL={ttl}")
            return ttl

        except socket.timeout:
            logger.debug(f"ICMP ping timeout for {ip_address}")
            icmp.close()
            return None

    except Exception as e:
        logger.debug(f"ICMP ping failed: {e}")
        return None


def calculate_checksum(data):
    """Calculate ICMP checksum"""
    if len(data) % 2 == 1:
        data += b'\x00'

    s = sum(struct.unpack('!%dH' % (len(data) // 2), data))
    s = (s >> 16) + (s & 0xffff)
    s += s >> 16
    s = ~s & 0xffff

    return s


def guess_os_from_ttl(ttl):
    """
    Guess OS based on TTL value

    Common initial TTL values:
    - Linux/Unix: 64
    - Windows: 128
    - Cisco/Network devices: 255
    - Some BSD: 255

    Args:
        ttl: TTL value from packet

    Returns:
        tuple: (os_guess, confidence)
    """
    # Calculate likely initial TTL (common values: 32, 64, 128, 255)
    possible_initial_ttls = [32, 64, 128, 255]

    # Find the smallest initial TTL that's >= observed TTL
    initial_ttl = None
    for value in possible_initial_ttls:
        if ttl <= value:
            initial_ttl = value
            break

    if not initial_ttl:
        return ("Unknown (TTL too high)", "low")

    hop_count = initial_ttl - ttl

    # Make educated guesses based on initial TTL
    if initial_ttl == 64:
        # Most likely Linux/Unix
        if hop_count <= 5:
            return ("Linux/Unix", "high")
        else:
            return ("Linux/Unix", "medium")

    elif initial_ttl == 128:
        # Most likely Windows
        if hop_count <= 5:
            return ("Windows", "high")
        else:
            return ("Windows", "medium")

    elif initial_ttl == 255:
        # Could be Cisco, BSD, or other network device
        if hop_count <= 5:
            return ("Cisco/Network Device/BSD", "medium")
        else:
            return ("Cisco/Network Device/BSD", "low")

    elif initial_ttl == 32:
        # Less common, older Windows or some embedded systems
        return ("Windows 95/98 or Embedded Device", "low")

    return ("Unknown", "low")


def format_os_results(os_data):
    """Format OS detection results for output"""
    lines = []
    lines.append("=== Operating System Detection ===")

    if not os_data:
        lines.append("OS detection unavailable")
        lines.append("")
        return '\n'.join(lines)

    if os_data.get('has_raw_socket'):
        lines.append("Method: Active fingerprinting (raw sockets available)")
    else:
        lines.append("Method: Passive analysis (no raw socket permissions)")
        lines.append("Note: Run as root or grant CAP_NET_RAW for active OS fingerprinting")

    lines.append("")

    if os_data.get('ttl'):
        lines.append(f"TTL: {os_data['ttl']}")

    if os_data.get('os_guess'):
        confidence = os_data.get('confidence', 'unknown')
        lines.append(f"OS Guess: {os_data['os_guess']} (confidence: {confidence})")
    else:
        lines.append("OS: Unable to determine")

    if not os_data.get('has_raw_socket'):
        lines.append("")
        lines.append("💡 Tip: For more accurate OS detection, run changedetection.io with:")
        lines.append("   • Root privileges, or")
        lines.append("   • CAP_NET_RAW capability: sudo setcap cap_net_raw+ep /path/to/python")

    lines.append("")
    return '\n'.join(lines)

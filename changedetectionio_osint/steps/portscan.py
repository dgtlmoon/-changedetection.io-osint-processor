"""
Port Scanning Step
Fast asyncio-based TCP connect port scanning
"""

import asyncio
from loguru import logger

# ============================================================================
# CONFIGURATION
# ============================================================================

# Port list extracted from /etc/services (TCP ports 1-10000)
# This hardcoded list works on all platforms (Windows, Linux, etc.)
COMMON_PORTS = [
    1, 7, 9, 11, 13, 15, 17, 19, 20, 21, 22, 23, 25, 37, 43, 49, 53, 70, 79, 80,
    88, 102, 104, 106, 110, 111, 113, 119, 135, 139, 143, 161, 162, 163, 164, 174,
    179, 199, 209, 210, 345, 346, 369, 370, 389, 427, 443, 444, 445, 464, 465, 487,
    512, 513, 514, 515, 538, 540, 543, 544, 548, 554, 563, 587, 607, 628, 631, 636,
    646, 655, 706, 749, 750, 751, 754, 775, 777, 783, 853, 871, 873, 989, 990, 992,
    993, 995, 1080, 1093, 1094, 1099, 1127, 1178, 1194, 1236, 1313, 1314, 1352, 1433,
    1524, 1645, 1646, 1649, 1677, 1812, 1813, 2000, 2049, 2086, 2101, 2119, 2121, 2135,
    2401, 2430, 2431, 2432, 2433, 2583, 2600, 2601
]

# Service name mapping for common ports (extracted from /etc/services)
PORT_SERVICES = {
    1: 'tcpmux', 7: 'echo', 9: 'discard', 11: 'systat', 13: 'daytime', 15: 'netstat',
    17: 'qotd', 19: 'chargen', 20: 'ftp-data', 21: 'ftp', 22: 'ssh', 23: 'telnet',
    25: 'smtp', 37: 'time', 43: 'whois', 49: 'tacacs', 53: 'domain', 70: 'gopher',
    79: 'finger', 80: 'http', 88: 'kerberos', 102: 'iso-tsap', 104: 'acr-nema',
    106: 'poppassd', 110: 'pop3', 111: 'sunrpc', 113: 'auth', 119: 'nntp', 135: 'epmap',
    139: 'netbios-ssn', 143: 'imap2', 161: 'snmp', 162: 'snmp-trap', 163: 'cmip-man',
    164: 'cmip-agent', 174: 'mailq', 179: 'bgp', 199: 'smux', 209: 'qmtp', 210: 'z3950',
    345: 'pawserv', 346: 'zserv', 369: 'rpc2portmap', 370: 'codaauth2', 389: 'ldap',
    427: 'svrloc', 443: 'https', 444: 'snpp', 445: 'microsoft-ds', 464: 'kpasswd',
    465: 'submissions', 487: 'saft', 512: 'exec', 513: 'login', 514: 'shell', 515: 'printer',
    538: 'gdomap', 540: 'uucp', 543: 'klogin', 544: 'kshell', 548: 'afpovertcp', 554: 'rtsp',
    563: 'nntps', 587: 'submission', 607: 'nqs', 628: 'qmqp', 631: 'ipp', 636: 'ldaps',
    646: 'ldp', 655: 'tinc', 706: 'silc', 749: 'kerberos-adm', 750: 'kerberos4',
    751: 'kerberos-master', 754: 'krb-prop', 775: 'moira-db', 777: 'moira-update',
    783: 'spamd', 853: 'domain-s', 871: 'supfilesrv', 873: 'rsync', 989: 'ftps-data',
    990: 'ftps', 992: 'telnets', 993: 'imaps', 995: 'pop3s', 1080: 'socks', 1093: 'proofd',
    1094: 'rootd', 1099: 'rmiregistry', 1127: 'supfiledbg', 1178: 'skkserv', 1194: 'openvpn',
    1236: 'rmtcfg', 1313: 'xtel', 1314: 'xtelw', 1352: 'lotusnote', 1433: 'ms-sql-s',
    1524: 'ingreslock', 1645: 'datametrics', 1646: 'sa-msg-port', 1649: 'kermit',
    1677: 'groupwise', 1812: 'radius', 1813: 'radius-acct', 2000: 'cisco-sccp', 2049: 'nfs',
    2086: 'gnunet', 2101: 'rtcm-sc104', 2119: 'gsigatekeeper', 2121: 'iprop', 2135: 'gris',
    2401: 'cvspserver', 2430: 'venus', 2431: 'venus-se', 2432: 'codasrv', 2433: 'codasrv-se',
    2583: 'mon', 2600: 'zebrasrv', 2601: 'zebra',
    3306: 'mysql', 3389: 'ms-wbt-server', 5432: 'postgresql', 5900: 'vnc',
    8080: 'http-alt', 8443: 'https-alt'
}


async def scan_ports(ip_address, ports=None, watch_uuid=None, update_signal=None):
    """
    Perform fast TCP connect port scan

    Args:
        ip_address: Target IP address
        ports: List of ports to scan (default: common service ports)
        watch_uuid: Optional watch UUID for status updates
        update_signal: Optional blinker signal for status updates

    Returns:
        list: List of open ports
    """
    if update_signal and watch_uuid:
        update_signal.send(watch_uuid=watch_uuid, status="Ports")

    if ports is None:
        # Use ports from /etc/services
        ports = COMMON_PORTS

    async def check_port(host, port, timeout=0.5):
        """Fast TCP connect scan for a single port"""
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=timeout
            )
            writer.close()
            await writer.wait_closed()
            return port
        except:
            return None

    # Scan all ports in parallel
    scan_tasks = [check_port(ip_address, port) for port in ports]
    scan_results = await asyncio.gather(*scan_tasks)
    open_ports = sorted([p for p in scan_results if p is not None])

    return open_ports


def format_portscan_results(open_ports):
    """Format port scan results for output"""
    lines = []
    lines.append("=== Port Scan ===")

    if open_ports:
        lines.append(f"Open Ports ({len(open_ports)} found):")
        for port in open_ports:
            service = PORT_SERVICES.get(port, 'unknown')
            lines.append(f"  {port}: {service}")
    else:
        lines.append("No open ports found (or filtered)")

    lines.append("")
    return '\n'.join(lines)

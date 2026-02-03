"""
Traceroute Step
Performs traceroute and displays last N hops to target
"""

import asyncio
import socket
import struct
from loguru import logger

# Configuration: Number of last hops to display
TRACEROUTE_LAST_HOPS = 3

# Maximum TTL to try
MAX_TTL = 30


async def scan_traceroute(ip_address, dns_resolver, last_n_hops=TRACEROUTE_LAST_HOPS, watch_uuid=None, update_signal=None):
    """
    Perform traceroute and return last N hops

    Args:
        ip_address: Target IP address
        dns_resolver: DNS resolver for reverse lookups
        last_n_hops: Number of last hops to return (default: 3)
        watch_uuid: Optional watch UUID for status updates
        update_signal: Optional blinker signal for status updates

    Returns:
        list: List of last N hops with hop number, IP, and hostname
    """
    if update_signal and watch_uuid:
        update_signal.send(watch_uuid=watch_uuid, status="Trace")

    def run_traceroute():
        """Perform traceroute using ICMP (requires raw sockets) or UDP fallback"""
        import subprocess
        import re

        try:
            # Use system traceroute command (works without root for UDP)
            # -n: no DNS resolution (we'll do it ourselves)
            # -m: max hops
            # -w: timeout per hop
            # -q: queries per hop
            result = subprocess.run(
                ['traceroute', '-n', '-m', str(MAX_TTL), '-w', '1', '-q', '1', ip_address],
                capture_output=True,
                text=True,
                timeout=15
            )

            if result.returncode != 0:
                logger.warning(f"Traceroute command failed: {result.stderr}")
                return []

            # Parse traceroute output
            hops = []
            lines = result.stdout.strip().split('\n')

            for line in lines[1:]:  # Skip header line
                # Parse line like: " 1  192.168.1.1  1.234 ms"
                match = re.search(r'^\s*(\d+)\s+([\d\.]+|[\da-f:]+)\s+', line)
                if match:
                    hop_num = int(match.group(1))
                    hop_ip = match.group(2)

                    # Skip if it's a timeout (* * *)
                    if '*' in line and hop_ip not in line:
                        continue

                    # Reverse DNS lookup for this hop
                    try:
                        import dns.reversename
                        rev_name = dns.reversename.from_address(hop_ip)
                        answers = dns_resolver.resolve(rev_name, 'PTR')
                        hostname = str(answers[0])
                    except:
                        hostname = ""

                    hops.append({
                        'hop': hop_num,
                        'ip': hop_ip,
                        'hostname': hostname
                    })

            # Return only last N hops
            if hops:
                return hops[-last_n_hops:]
            return []

        except subprocess.TimeoutExpired:
            logger.warning("Traceroute timed out")
            return []
        except FileNotFoundError:
            logger.warning("traceroute command not found, skipping traceroute")
            return []
        except Exception as e:
            logger.error(f"Traceroute failed: {e}")
            return []

    try:
        return await asyncio.to_thread(run_traceroute)
    except Exception as e:
        logger.error(f"Traceroute scan failed: {e}")
        return []


def format_traceroute_results(hops):
    """Format traceroute results for output"""
    lines = []
    lines.append(f"=== Traceroute (Last {TRACEROUTE_LAST_HOPS} Hops) ===")

    if hops:
        for hop in hops:
            if hop['hostname']:
                lines.append(f"  {hop['hop']:2d}. {hop['ip']:15s} ({hop['hostname']})")
            else:
                lines.append(f"  {hop['hop']:2d}. {hop['ip']:15s}")
    else:
        lines.append("Traceroute data not available")
        lines.append("(requires traceroute command or may be blocked by firewall)")

    lines.append("")
    return '\n'.join(lines)

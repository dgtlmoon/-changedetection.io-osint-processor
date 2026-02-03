"""
OSINT Reconnaissance Processor - Configurable Execution Mode

Extends text_json_diff for comprehensive reconnaissance using:
- dnspython: Fast DNS queries
- python-whois: WHOIS lookups
- requests: HTTP response fingerprinting
- SSLyze: SSL/TLS certificate analysis
- asyncio: Fast parallel port scanning
- Traceroute: Network path analysis
- BGP: AS/routing information

Execution mode is configurable via MODE setting ("serial" or "parallel").
All DNS operations use the configured DNS_SERVER.
"""

import asyncio
import ipaddress
import socket
from loguru import logger
from urllib.parse import urlparse
from requests.structures import CaseInsensitiveDict
from blinker import signal

# Import all scan step modules (alias to avoid conflicts with dnspython)
from .steps import dns as dns_step
from .steps import whois_lookup
from .steps import http_fingerprint
from .steps import tls_analysis
from .steps import portscan
from .steps import traceroute
from .steps import bgp as bgp_step
from .steps import mac_lookup
from .steps import os_detection

# ============================================================================
# CONFIGURATION
# ============================================================================

# Execution Mode: "serial" or "parallel"
# serial: Steps run one after another (safer, easier to debug, default)
# parallel: All steps run simultaneously (faster, 4-5x speedup)
MODE = "serial"

# DNS Server Configuration
# This DNS server will be used for ALL DNS lookups
# TODO: Make this a user setting in the future
DNS_SERVER = "8.8.8.8"

# Import the text_json_diff processor to extend it
from changedetectionio.processors.text_json_diff.processor import perform_site_check as text_json_diff_processor

# Translation marker for extraction
def _(x): return x
name = _('OSINT Reconnaissance')
description = _('Comprehensive reconnaissance: DNS, WHOIS, HTTP, TLS, Ports, Traceroute, BGP')
del _
processor_weight = -50
list_badge_text = "OSINT"


class perform_site_check(text_json_diff_processor):
    """
    OSINT Reconnaissance processor that extends text_json_diff.

    Reconnaissance steps (configurable MODE: serial or parallel):
    - DNS queries (A, AAAA, MX, NS, TXT, SOA, CAA)
    - WHOIS lookups
    - HTTP response fingerprinting (CDN/WAF detection, redirect chains)
    - SSL/TLS certificate analysis
    - Port scanning
    - Traceroute (last N hops)
    - BGP/ASN information

    All DNS operations use the configured DNS_SERVER for consistent resolution.

    Configuration:
    - MODE = "serial" (default) or "parallel" (4-5x faster)
    - DNS_SERVER = "8.8.8.8" (used for all DNS operations)
    """

    async def call_browser(self, preferred_proxy_id=None):
        """
        Override the browser call to perform OSINT reconnaissance.

        Runs scan steps in serial (default) or parallel mode based on MODE setting.
        Serial: Steps run sequentially, safer and easier to debug
        Parallel: Steps run concurrently, 4-5x faster
        """
        url = self.watch.link
        watch_uuid = self.watch.get('uuid')

        # Signal for status updates to UI
        update_signal = signal('watch_small_status_comment')

        # Load processor-specific configuration from watch data directory
        processor_config = self.get_extra_watch_config('osint_recon.json')

        # Get configuration values (with defaults)
        scan_mode = processor_config.get('scan_mode', MODE)
        dns_server = processor_config.get('dns_server', DNS_SERVER) or DNS_SERVER

        # Get enabled/disabled scan steps (all enabled by default)
        enable_dns = processor_config.get('enable_dns', True)
        enable_whois = processor_config.get('enable_whois', True)
        enable_http = processor_config.get('enable_http', True)
        enable_tls = processor_config.get('enable_tls', True)
        tls_vulnerability_scan = processor_config.get('tls_vulnerability_scan', False)
        enable_portscan = processor_config.get('enable_portscan', False)
        enable_traceroute = processor_config.get('enable_traceroute', True)
        enable_bgp = processor_config.get('enable_bgp', True)
        enable_os_detection = processor_config.get('enable_os_detection', True)

        logger.info(f"Running OSINT reconnaissance on {url} (mode: {scan_mode}, DNS: {dns_server})")
        update_signal.send(watch_uuid=watch_uuid, status="Starting")

        # Validate URL
        if not url or not url.startswith(('http://', 'https://')):
            raise ValueError(f"Invalid URL for OSINT: {url}")

        # Parse URL to get hostname
        parsed = urlparse(url)
        hostname = parsed.netloc or parsed.hostname
        if not hostname:
            raise ValueError(f"Could not extract hostname from URL: {url}")

        port = parsed.port or (443 if parsed.scheme == 'https' else 80)

        # Get proxy configuration if available
        proxy_url = None
        if preferred_proxy_id:
            proxy_url = self.datastore.proxy_list.get(preferred_proxy_id).get('url')
            logger.debug(f"Using proxy '{proxy_url}' for OSINT reconnaissance")

        try:
            import dns.resolver
            import dns.reversename

            # Create DNS resolver with configured DNS server
            dns_resolver = dns.resolver.Resolver()
            dns_resolver.nameservers = [dns_server]
            logger.debug(f"Using DNS server: {dns_server} for all operations")

            # Resolve IP address first (needed by several steps)
            # Check if hostname is already an IP address
            try:
                ipaddress.ip_address(hostname)
                # It's already an IP address, no DNS resolution needed
                ip_address = hostname
                logger.debug(f"Input is already an IP address: {ip_address}")
            except ValueError:
                # Not an IP address, needs DNS resolution
                try:
                    answers = dns_resolver.resolve(hostname, 'A')
                    ip_address = str(answers[0])
                except:
                    # Fallback to AAAA if no A record
                    try:
                        answers = dns_resolver.resolve(hostname, 'AAAA')
                        ip_address = str(answers[0])
                    except:
                        raise ValueError(f"Could not resolve hostname: {hostname}")

            logger.debug(f"Resolved {hostname} to {ip_address}")

            # Reverse DNS lookup
            try:
                rev_name = dns.reversename.from_address(ip_address)
                answers = dns_resolver.resolve(rev_name, 'PTR')
                reverse_dns = str(answers[0])
            except:
                reverse_dns = "No PTR record"

            # =================================================================
            # RUN SCAN STEPS (SERIAL OR PARALLEL BASED ON MODE)
            # =================================================================

            if scan_mode == "parallel":
                logger.info("Starting PARALLEL reconnaissance scans...")

                # Build list of enabled scans
                scans = []
                if enable_dns:
                    scans.append(dns_step.scan_dns(hostname, dns_resolver, watch_uuid, update_signal))
                if enable_whois:
                    scans.append(whois_lookup.scan_whois(hostname, watch_uuid, update_signal))
                if enable_http:
                    scans.append(http_fingerprint.scan_http(url, dns_resolver, proxy_url, watch_uuid, update_signal))
                if enable_tls and parsed.scheme == 'https':
                    scans.append(tls_analysis.scan_tls(hostname, port, watch_uuid, update_signal, tls_vulnerability_scan))
                elif enable_tls:
                    scans.append(asyncio.sleep(0))  # Placeholder for TLS when not HTTPS
                if enable_portscan:
                    scans.append(portscan.scan_ports(ip_address, None, watch_uuid, update_signal))
                if enable_traceroute:
                    scans.append(traceroute.scan_traceroute(ip_address, dns_resolver, traceroute.TRACEROUTE_LAST_HOPS, watch_uuid, update_signal))
                if enable_bgp:
                    scans.append(bgp_step.scan_bgp(ip_address, watch_uuid, update_signal))
                if enable_os_detection:
                    scans.append(os_detection.scan_os(ip_address, watch_uuid, update_signal))

                # MAC address lookup (always enabled for local network detection)
                scans.append(mac_lookup.scan_mac(ip_address, watch_uuid, update_signal))

                # Launch all enabled scans concurrently
                if scans:
                    results = await asyncio.gather(*scans, return_exceptions=True)

                    # Unpack results based on which scans were enabled
                    idx = 0
                    dns_results = results[idx] if enable_dns else None
                    idx += 1 if enable_dns else 0
                    whois_data = results[idx] if enable_whois else None
                    idx += 1 if enable_whois else 0
                    http_fingerprint_data = results[idx] if enable_http else None
                    idx += 1 if enable_http else 0
                    tls_results = results[idx] if enable_tls else None
                    idx += 1 if enable_tls else 0
                    open_ports = results[idx] if enable_portscan else None
                    idx += 1 if enable_portscan else 0
                    traceroute_hops = results[idx] if enable_traceroute else None
                    idx += 1 if enable_traceroute else 0
                    bgp_data = results[idx] if enable_bgp else None
                    idx += 1 if enable_bgp else 0
                    os_data = results[idx] if enable_os_detection else None
                    idx += 1 if enable_os_detection else 0
                    mac_data = results[idx]  # Always runs
                else:
                    # No scans enabled
                    dns_results = whois_data = http_fingerprint_data = tls_results = None
                    open_ports = traceroute_hops = bgp_data = os_data = mac_data = None

            else:  # scan_mode == "serial"
                logger.info("Starting SERIAL reconnaissance scans...")

                # Run each enabled step sequentially
                dns_results = await dns_step.scan_dns(hostname, dns_resolver, watch_uuid, update_signal) if enable_dns else None

                whois_data = await whois_lookup.scan_whois(hostname, watch_uuid, update_signal) if enable_whois else None

                http_fingerprint_data = await http_fingerprint.scan_http(url, dns_resolver, proxy_url, watch_uuid, update_signal) if enable_http else None

                if enable_tls and parsed.scheme == 'https':
                    tls_results = await tls_analysis.scan_tls(hostname, port, watch_uuid, update_signal, tls_vulnerability_scan)
                else:
                    tls_results = None

                open_ports = await portscan.scan_ports(ip_address, None, watch_uuid, update_signal) if enable_portscan else None

                traceroute_hops = await traceroute.scan_traceroute(ip_address, dns_resolver, traceroute.TRACEROUTE_LAST_HOPS, watch_uuid, update_signal) if enable_traceroute else None

                bgp_data = await bgp_step.scan_bgp(ip_address, watch_uuid, update_signal) if enable_bgp else None

                os_data = await os_detection.scan_os(ip_address, watch_uuid, update_signal) if enable_os_detection else None

                # MAC address lookup (always enabled for local network detection)
                mac_data = await mac_lookup.scan_mac(ip_address, watch_uuid, update_signal)

            logger.info(f"All scans completed ({scan_mode} mode), formatting output...")

            # =================================================================
            # FORMAT ALL RESULTS
            # =================================================================

            # Build header
            header_lines = []
            header_lines.append(f"Target: {url}")
            header_lines.append(f"Hostname: {hostname}")
            header_lines.append(f"IP Address: {ip_address}")
            header_lines.append(f"Reverse DNS: {reverse_dns}")

            # Add MAC address if available (local network only)
            if mac_data and not isinstance(mac_data, Exception) and mac_data.get('mac_address'):
                header_lines.append(f"MAC Address: {mac_data['mac_address']}")
                if mac_data.get('vendor'):
                    header_lines.append(f"MAC Vendor: {mac_data['vendor']}")

            header_lines.append("")

            # Format all sections
            sections = {}

            # BGP/ASN section (shows first since it's network-level info)
            if bgp_data and not isinstance(bgp_data, Exception):
                sections["BGP / ASN Information"] = bgp_step.format_bgp_results(bgp_data)

            # DNS section
            if dns_results and not isinstance(dns_results, Exception):
                sections["DNS Records"] = dns_step.format_dns_results(dns_results)

            # WHOIS section
            if whois_data and not isinstance(whois_data, Exception):
                sections["WHOIS Information"] = whois_lookup.format_whois_results(whois_data)

            # HTTP fingerprint section
            if http_fingerprint_data and not isinstance(http_fingerprint_data, Exception):
                sections["HTTP Response Fingerprint"] = http_fingerprint.format_http_results(http_fingerprint_data, parsed)

            # TLS/SSL section (only for HTTPS)
            if parsed.scheme == 'https' and tls_results and not isinstance(tls_results, Exception) and tls_results:
                sections["SSL/TLS Analysis (SSLyze)"] = tls_analysis.format_tls_results(tls_results, watch_uuid, update_signal)

            # Traceroute section
            if traceroute_hops and not isinstance(traceroute_hops, Exception):
                sections["Traceroute (Last N Hops)"] = traceroute.format_traceroute_results(traceroute_hops)

            # Port scan section
            if open_ports is not None and not isinstance(open_ports, Exception):
                sections["Port Scan (Common Ports)"] = portscan.format_portscan_results(open_ports)

            # OS detection section
            if os_data and not isinstance(os_data, Exception):
                sections["Operating System Detection"] = os_detection.format_os_results(os_data)

            # Combine header and sorted sections
            output_parts = header_lines.copy()

            # Sort sections alphabetically and append
            for section_name in sorted(sections.keys()):
                output_parts.append(sections[section_name])

            output = '\n'.join(output_parts)

            # Format output for better readability
            output = self._format_output_for_diff(output, url)

            # Set the content in our fetcher
            self.fetcher.content = output

            # Set some basic headers
            if not hasattr(self.fetcher, 'headers') or self.fetcher.headers is None or not isinstance(self.fetcher.headers, dict):
                self.fetcher.headers = CaseInsensitiveDict()
            elif not isinstance(self.fetcher.headers, CaseInsensitiveDict):
                self.fetcher.headers = CaseInsensitiveDict(self.fetcher.headers)

            self.fetcher.headers['content-type'] = 'text/plain; charset=utf-8'

            # Mark as successful fetch
            if not hasattr(self.fetcher, 'status_code') or self.fetcher.status_code is None:
                self.fetcher.status_code = 200

            update_signal.send(watch_uuid=watch_uuid, status="Done")
            logger.info(f"OSINT reconnaissance completed successfully, captured {len(output)} bytes")

        except ImportError as e:
            error_msg = (
                f"Required packages not found. Please install them:\n"
                f"  pip install dnspython python-whois sslyze\n"
                f"Error: {str(e)}"
            )
            logger.error(error_msg)
            raise Exception(error_msg)

        except Exception as e:
            import traceback
            logger.error(f"OSINT reconnaissance error: {str(e)}")
            logger.error(f"Traceback: {traceback.format_exc()}")
            raise

    @staticmethod
    def _format_output_for_diff(text, url):
        """
        Format OSINT output for better readability in diff view.
        """
        lines = []

        # Add header
        lines.append("=" * 70)
        lines.append(f"OSINT Reconnaissance Report ({MODE.capitalize()} Mode)")
        lines.append("=" * 70)
        lines.append(f"Target URL: {url}")
        lines.append("=" * 70)
        lines.append("")

        # Process the output
        for line in text.split('\n'):
            if line.startswith('==='):
                # Section headers
                lines.append("")
                lines.append("-" * 70)
                lines.append(line.replace('===', '##'))
                lines.append("-" * 70)
            else:
                # Indent content for readability
                if line and not line.startswith(('Target:', 'Hostname:', 'IP Address:')):
                    lines.append(f"  {line}")
                else:
                    lines.append(line)

        # Add footer
        lines.append("")
        lines.append("=" * 70)
        lines.append("End of Report")
        lines.append("=" * 70)

        return '\n'.join(lines)

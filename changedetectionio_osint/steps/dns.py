"""
DNS Reconnaissance Step
Performs comprehensive DNS queries using configured DNS server
"""

import asyncio
from loguru import logger

# SOCKS5 proxy support
# DNS can use TCP on port 53, which works through SOCKS5
# We force TCP mode when proxy is configured
supports_socks5 = True


async def scan_dns(hostname, dns_resolver, proxy_url=None, watch_uuid=None, update_signal=None):
    """
    Perform DNS reconnaissance on hostname

    Args:
        hostname: Target hostname to query
        dns_resolver: Configured dns.resolver.Resolver instance
        proxy_url: Optional SOCKS5 proxy URL (forces DNS-over-TCP)
        watch_uuid: Optional watch UUID for status updates
        update_signal: Optional blinker signal for status updates

    Returns:
        dict: DNS results with record types as keys
    """
    if update_signal and watch_uuid:
        update_signal.send(watch_uuid=watch_uuid, status="DNS")

    def query_dns():
        import dns.query
        import dns.message
        import dns.rdatatype

        results = {}
        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA', 'CAA']

        # Get DNS server from resolver
        dns_server = dns_resolver.nameservers[0] if dns_resolver.nameservers else '8.8.8.8'

        for rtype in record_types:
            try:
                # Create DNS query message
                query = dns.message.make_query(hostname, rtype)

                # If proxy is configured, use TCP (works through SOCKS5)
                # Otherwise, use UDP (faster)
                if proxy_url and proxy_url.strip():
                    try:
                        # DNS-over-TCP through SOCKS5 proxy
                        from python_socks.sync import Proxy
                        from urllib.parse import urlparse
                        import socket as sock_module

                        # Parse proxy URL
                        proxy = Proxy.from_url(proxy_url)

                        # Create SOCKS5 connection to DNS server
                        socks_socket = proxy.connect(dest_host=dns_server, dest_port=53)

                        # Send DNS query over TCP through SOCKS5
                        response = dns.query.tcp(query, dns_server, sock=socks_socket, timeout=5)

                        # Close socket
                        socks_socket.close()

                    except ImportError:
                        # CRITICAL: Do NOT fallback to direct connection - would leak real IP!
                        logger.error("SOCKS5 proxy configured but 'python-socks' not installed - DNS query BLOCKED to prevent IP leak")
                        raise Exception("DNS-over-SOCKS5 requires 'python-socks' package. Install with: pip install 'python-socks[asyncio]'")
                    except Exception as e:
                        # CRITICAL: Do NOT fallback to direct connection - would leak real IP!
                        logger.error(f"DNS-over-TCP via SOCKS5 failed for {rtype}: {e} - query BLOCKED to prevent IP leak")
                        raise
                else:
                    # Direct UDP query (no proxy)
                    response = dns.query.udp(query, dns_server, timeout=5)

                # Parse response
                results[rtype] = []
                for rrset in response.answer:
                    for rdata in rrset:
                        if rtype == 'MX':
                            results[rtype].append(f"{rdata.preference} {rdata.exchange}")
                        elif rtype == 'SOA':
                            results[rtype].append(f"{rdata.mname} {rdata.rname}")
                        elif rtype == 'CAA':
                            results[rtype].append(f"{rdata.flags} {rdata.tag} {rdata.value}")
                        else:
                            results[rtype].append(str(rdata))

            except Exception as e:
                logger.debug(f"DNS query for {rtype} failed: {e}")
                pass

        return results

    return await asyncio.to_thread(query_dns)


def format_dns_results(dns_results):
    """Format DNS results for output"""
    lines = []
    lines.append("=== DNS Records ===")

    if dns_results:
        for rtype, records in sorted(dns_results.items()):
            if records:
                lines.append(f"{rtype} Records:")

                # Sort records based on type
                if rtype == 'MX':
                    # MX records: sort by priority (numeric), then alphabetically
                    # Format: "10 mail.example.com."
                    def mx_sort_key(mx_record):
                        try:
                            parts = mx_record.split(' ', 1)
                            priority = int(parts[0])
                            server = parts[1] if len(parts) > 1 else ''
                            return (priority, server)
                        except:
                            return (999999, mx_record)

                    sorted_records = sorted(records, key=mx_sort_key)

                elif rtype == 'TXT':
                    # TXT records: sort alphabetically
                    sorted_records = sorted(records)

                elif rtype == 'NS':
                    # NS records: sort alphabetically for consistent ordering
                    sorted_records = sorted(records)

                else:
                    # Other records: keep original order
                    sorted_records = records

                # Output sorted records
                for record in sorted_records:
                    lines.append(f"  {record}")
    else:
        lines.append("No DNS records found")

    lines.append("")
    return '\n'.join(lines)

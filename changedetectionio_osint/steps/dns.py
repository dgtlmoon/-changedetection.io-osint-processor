"""
DNS Reconnaissance Step
Performs comprehensive DNS queries using configured DNS server
"""

import asyncio
from loguru import logger


async def scan_dns(hostname, dns_resolver, watch_uuid=None, update_signal=None):
    """
    Perform DNS reconnaissance on hostname

    Args:
        hostname: Target hostname to query
        dns_resolver: Configured dns.resolver.Resolver instance
        watch_uuid: Optional watch UUID for status updates
        update_signal: Optional blinker signal for status updates

    Returns:
        dict: DNS results with record types as keys
    """
    if update_signal and watch_uuid:
        update_signal.send(watch_uuid=watch_uuid, status="DNS")

    def query_dns():
        results = {}
        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA', 'CAA']

        for rtype in record_types:
            try:
                answers = dns_resolver.resolve(hostname, rtype)
                results[rtype] = []
                for rdata in answers:
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

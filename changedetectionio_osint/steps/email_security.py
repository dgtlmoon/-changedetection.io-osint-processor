"""
Email Security Reconnaissance Step
Analyzes SPF, DMARC, and DKIM records for email authentication and anti-spoofing
"""

import asyncio
# SOCKS5 proxy support: Requires DNS-over-TCP implementation (TODO: use dns.query.tcp with SOCKS5 socket)
supports_socks5 = False
import re
from loguru import logger


async def scan_email_security(hostname, dns_resolver, watch_uuid=None, update_signal=None):
    """
    Perform email security reconnaissance (SPF, DMARC, DKIM)

    Args:
        hostname: Target hostname to query
        dns_resolver: Configured dns.resolver.Resolver instance
        watch_uuid: Optional watch UUID for status updates
        update_signal: Optional blinker signal for status updates

    Returns:
        dict: Email security results with SPF, DMARC, DKIM data
    """
    if update_signal and watch_uuid:
        update_signal.send(watch_uuid=watch_uuid, status="Email Security")

    def query_email_security():
        results = {
            'spf': None,
            'dmarc': None,
            'dkim': [],
            'spf_valid': False,
            'dmarc_valid': False,
            'spf_policy': None,
            'dmarc_policy': None,
            'dmarc_pct': None,
            'dmarc_rua': [],
            'dmarc_ruf': [],
        }

        # === SPF (Sender Policy Framework) ===
        # SPF records are TXT records on the domain itself
        try:
            answers = dns_resolver.resolve(hostname, 'TXT')
            for rdata in answers:
                txt_value = str(rdata).strip('"')
                if txt_value.startswith('v=spf1'):
                    results['spf'] = txt_value
                    results['spf_valid'] = True

                    # Parse SPF policy (last mechanism: all)
                    # Common endings: -all (fail), ~all (softfail), +all (pass), ?all (neutral)
                    if '-all' in txt_value:
                        results['spf_policy'] = 'strict (-all)'
                    elif '~all' in txt_value:
                        results['spf_policy'] = 'softfail (~all)'
                    elif '+all' in txt_value:
                        results['spf_policy'] = 'permissive (+all)'
                    elif '?all' in txt_value:
                        results['spf_policy'] = 'neutral (?all)'
                    else:
                        results['spf_policy'] = 'unknown'
                    break
        except Exception as e:
            logger.debug(f"SPF query failed: {e}")

        # === DMARC (Domain-based Message Authentication) ===
        # DMARC records are TXT records on _dmarc.domain.com
        try:
            dmarc_domain = f"_dmarc.{hostname}"
            answers = dns_resolver.resolve(dmarc_domain, 'TXT')
            for rdata in answers:
                txt_value = str(rdata).strip('"')
                if txt_value.startswith('v=DMARC1'):
                    results['dmarc'] = txt_value
                    results['dmarc_valid'] = True

                    # Parse DMARC policy (p=none/quarantine/reject)
                    policy_match = re.search(r'p=(\w+)', txt_value)
                    if policy_match:
                        results['dmarc_policy'] = policy_match.group(1)

                    # Parse DMARC percentage (pct=0-100)
                    pct_match = re.search(r'pct=(\d+)', txt_value)
                    if pct_match:
                        results['dmarc_pct'] = int(pct_match.group(1))
                    else:
                        results['dmarc_pct'] = 100  # Default is 100%

                    # Parse aggregate reporting URIs (rua)
                    rua_match = re.search(r'rua=([^;]+)', txt_value)
                    if rua_match:
                        results['dmarc_rua'] = [uri.strip() for uri in rua_match.group(1).split(',')]

                    # Parse forensic reporting URIs (ruf)
                    ruf_match = re.search(r'ruf=([^;]+)', txt_value)
                    if ruf_match:
                        results['dmarc_ruf'] = [uri.strip() for uri in ruf_match.group(1).split(',')]

                    break
        except Exception as e:
            logger.debug(f"DMARC query failed: {e}")

        # === DKIM (DomainKeys Identified Mail) ===
        # DKIM records are TXT records on <selector>._domainkey.domain.com
        # Common selectors to check (brute force approach since selector is arbitrary)
        common_selectors = [
            'default', 'google', 'k1', 'k2', 'k3', 'dkim', 'selector1', 'selector2',
            's1', 's2', 'mail', 'email', 'mx', 'smtp', 'mta', 'key1', 'key2'
        ]

        for selector in common_selectors:
            try:
                dkim_domain = f"{selector}._domainkey.{hostname}"
                answers = dns_resolver.resolve(dkim_domain, 'TXT')
                for rdata in answers:
                    txt_value = str(rdata).strip('"')
                    if 'v=DKIM1' in txt_value or 'p=' in txt_value:
                        # Extract key type if present
                        key_type = 'RSA'  # Default
                        k_match = re.search(r'k=(\w+)', txt_value)
                        if k_match:
                            key_type = k_match.group(1).upper()

                        results['dkim'].append({
                            'selector': selector,
                            'record': txt_value[:100] + '...' if len(txt_value) > 100 else txt_value,
                            'key_type': key_type
                        })
                        break
            except Exception:
                continue

        return results

    return await asyncio.to_thread(query_email_security)


def format_email_security_results(email_results):
    """Format email security results for output"""
    lines = []
    lines.append("=== Email Security (SPF/DMARC/DKIM) ===")

    if not email_results:
        lines.append("No email security records found")
        lines.append("")
        return '\n'.join(lines)

    # SPF Section
    lines.append("")
    lines.append("SPF (Sender Policy Framework):")
    if email_results.get('spf_valid'):
        lines.append(f"  Status: ✓ SPF record found")
        lines.append(f"  Policy: {email_results.get('spf_policy', 'unknown')}")
        lines.append(f"  Record: {email_results.get('spf')}")

        # Security assessment
        policy = email_results.get('spf_policy', '')
        if 'strict' in policy:
            lines.append("  Security: ✓ Strong (rejects unauthorized senders)")
        elif 'softfail' in policy:
            lines.append("  Security: ⚠ Moderate (marks unauthorized senders as suspicious)")
        elif 'permissive' in policy:
            lines.append("  Security: ✗ Weak (allows all senders)")
        else:
            lines.append("  Security: ? Unknown policy")
    else:
        lines.append("  Status: ✗ No SPF record found")
        lines.append("  Security: ✗ Domain is vulnerable to email spoofing")

    # DMARC Section
    lines.append("")
    lines.append("DMARC (Domain-based Message Authentication):")
    if email_results.get('dmarc_valid'):
        lines.append(f"  Status: ✓ DMARC record found")
        lines.append(f"  Policy: {email_results.get('dmarc_policy', 'unknown')}")
        lines.append(f"  Enforcement: {email_results.get('dmarc_pct', 100)}% of messages")

        if email_results.get('dmarc_rua'):
            lines.append(f"  Aggregate Reports: {', '.join(email_results['dmarc_rua'])}")
        if email_results.get('dmarc_ruf'):
            lines.append(f"  Forensic Reports: {', '.join(email_results['dmarc_ruf'])}")

        lines.append(f"  Record: {email_results.get('dmarc')}")

        # Security assessment
        policy = email_results.get('dmarc_policy', '')
        pct = email_results.get('dmarc_pct', 100)
        if policy == 'reject' and pct == 100:
            lines.append("  Security: ✓ Strong (rejects failed authentication)")
        elif policy == 'quarantine':
            lines.append("  Security: ⚠ Moderate (quarantines failed authentication)")
        elif policy == 'none':
            lines.append("  Security: ⚠ Monitor-only (no enforcement)")
        else:
            lines.append("  Security: ? Unknown policy")
    else:
        lines.append("  Status: ✗ No DMARC record found")
        lines.append("  Security: ⚠ No DMARC policy enforcement")

    # DKIM Section
    lines.append("")
    lines.append("DKIM (DomainKeys Identified Mail):")
    if email_results.get('dkim'):
        lines.append(f"  Status: ✓ Found {len(email_results['dkim'])} DKIM selector(s)")
        for dkim_entry in email_results['dkim']:
            lines.append(f"  Selector: {dkim_entry['selector']}")
            lines.append(f"    Key Type: {dkim_entry['key_type']}")
            lines.append(f"    Record: {dkim_entry['record']}")
        lines.append("  Security: ✓ Email signing enabled")
    else:
        lines.append("  Status: ⚠ No DKIM records found (checked common selectors)")
        lines.append("  Note: DKIM may be present with a custom selector")

    # Overall Security Summary
    lines.append("")
    lines.append("Overall Email Security Posture:")
    spf_ok = email_results.get('spf_valid', False)
    dmarc_ok = email_results.get('dmarc_valid', False)
    dkim_ok = len(email_results.get('dkim', [])) > 0

    score = sum([spf_ok, dmarc_ok, dkim_ok])
    if score == 3:
        lines.append("  ✓ Excellent: SPF, DMARC, and DKIM all configured")
    elif score == 2:
        lines.append("  ⚠ Good: 2 out of 3 email security standards configured")
    elif score == 1:
        lines.append("  ⚠ Weak: Only 1 out of 3 email security standards configured")
    else:
        lines.append("  ✗ Poor: No email security standards configured")
        lines.append("  Recommendation: Configure SPF, DMARC, and DKIM to prevent email spoofing")

    lines.append("")
    return '\n'.join(lines)

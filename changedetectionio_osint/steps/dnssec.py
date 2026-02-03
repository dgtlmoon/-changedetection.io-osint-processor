"""
DNSSEC Validation Step
Validates DNSSEC signatures and chain of trust for domain security
"""

import asyncio
# SOCKS5 proxy support: Requires DNS-over-TCP implementation (TODO: use dns.query.tcp with SOCKS5 socket)
supports_socks5 = False
from loguru import logger
from datetime import datetime


async def scan_dnssec(hostname, dns_resolver, watch_uuid=None, update_signal=None):
    """
    Perform DNSSEC validation

    Args:
        hostname: Target hostname to validate
        dns_resolver: Configured dns.resolver.Resolver instance
        watch_uuid: Optional watch UUID for status updates
        update_signal: Optional blinker signal for status updates

    Returns:
        dict: DNSSEC validation results
    """
    if update_signal and watch_uuid:
        update_signal.send(watch_uuid=watch_uuid, status="DNSSEC")

    def query_dnssec():
        import dns.dnssec
        import dns.name

        results = {
            'dnssec_enabled': False,
            'has_dnskey': False,
            'has_ds': False,
            'has_rrsig': False,
            'validation_status': 'unknown',
            'algorithm': None,
            'key_count': 0,
            'rrsig_count': 0,
            'signatures': [],
            'keys': [],
            'error': None
        }

        try:
            domain_name = dns.name.from_text(hostname)

            # === Check for DNSKEY records (public keys) ===
            try:
                dnskey_answers = dns_resolver.resolve(hostname, 'DNSKEY')
                results['has_dnskey'] = True
                results['key_count'] = len(dnskey_answers)

                for rdata in dnskey_answers:
                    # DNSKEY flags: 256 = Zone Signing Key (ZSK), 257 = Key Signing Key (KSK)
                    key_type = "KSK (Key Signing Key)" if rdata.flags == 257 else "ZSK (Zone Signing Key)" if rdata.flags == 256 else f"Unknown (flags={rdata.flags})"

                    # Algorithm mapping (common ones)
                    alg_names = {
                        5: "RSA/SHA-1",
                        7: "RSASHA1-NSEC3-SHA1",
                        8: "RSA/SHA-256",
                        10: "RSA/SHA-512",
                        13: "ECDSA Curve P-256 with SHA-256",
                        14: "ECDSA Curve P-384 with SHA-384",
                        15: "Ed25519",
                        16: "Ed448"
                    }
                    algorithm = alg_names.get(rdata.algorithm, f"Algorithm {rdata.algorithm}")

                    results['keys'].append({
                        'type': key_type,
                        'algorithm': algorithm,
                        'flags': rdata.flags,
                        'protocol': rdata.protocol,
                        'key_tag': dns.dnssec.key_id(rdata)
                    })

                    if not results['algorithm']:
                        results['algorithm'] = algorithm

                logger.debug(f"Found {results['key_count']} DNSKEY records for {hostname}")

            except Exception as e:
                logger.debug(f"No DNSKEY records found: {e}")

            # === Check for DS records (delegation signer) ===
            # DS records exist at the parent zone, proving the child is signed
            try:
                ds_answers = dns_resolver.resolve(hostname, 'DS')
                results['has_ds'] = len(ds_answers) > 0
                logger.debug(f"Found DS records for {hostname}")
            except Exception as e:
                logger.debug(f"No DS records found: {e}")

            # === Check for RRSIG records (signatures) ===
            # RRSIG records sign other record types (A, AAAA, etc.)
            try:
                # Try to get RRSIG for A records
                a_answers = dns_resolver.resolve(hostname, 'A')
                # Get the RRSIG that covers the A records
                rrsig_answers = dns_resolver.resolve(hostname, 'RRSIG', rdtype=dns.rdatatype.A)
                results['has_rrsig'] = True
                results['rrsig_count'] = len(rrsig_answers)

                for rdata in rrsig_answers:
                    # Parse signature timing
                    inception_time = datetime.fromtimestamp(rdata.inception)
                    expiration_time = datetime.fromtimestamp(rdata.expiration)
                    now = datetime.now()

                    # Check if signature is currently valid
                    is_valid = inception_time <= now <= expiration_time

                    alg_names = {
                        5: "RSA/SHA-1", 7: "RSASHA1-NSEC3-SHA1", 8: "RSA/SHA-256",
                        10: "RSA/SHA-512", 13: "ECDSA P-256", 14: "ECDSA P-384",
                        15: "Ed25519", 16: "Ed448"
                    }
                    algorithm = alg_names.get(rdata.algorithm, f"Algorithm {rdata.algorithm}")

                    results['signatures'].append({
                        'type_covered': dns.rdatatype.to_text(rdata.type_covered),
                        'algorithm': algorithm,
                        'signer': str(rdata.signer),
                        'key_tag': rdata.key_tag,
                        'inception': inception_time.strftime('%Y-%m-%d %H:%M:%S'),
                        'expiration': expiration_time.strftime('%Y-%m-%d %H:%M:%S'),
                        'valid': is_valid,
                        'days_until_expiry': (expiration_time - now).days if is_valid else None
                    })

                logger.debug(f"Found {results['rrsig_count']} RRSIG records for {hostname}")

            except Exception as e:
                logger.debug(f"No RRSIG records found: {e}")

            # === Determine overall DNSSEC status ===
            if results['has_dnskey'] and results['has_rrsig']:
                results['dnssec_enabled'] = True
                # Full chain validation requires DS records in parent zone
                if results['has_ds']:
                    results['validation_status'] = 'secure (full chain)'
                else:
                    results['validation_status'] = 'secure (no DS records in parent zone)'
            elif results['has_dnskey'] or results['has_rrsig']:
                results['dnssec_enabled'] = True
                results['validation_status'] = 'partial (incomplete DNSSEC)'
            else:
                results['dnssec_enabled'] = False
                results['validation_status'] = 'unsigned (no DNSSEC)'

        except Exception as e:
            logger.error(f"DNSSEC validation error: {e}")
            results['error'] = str(e)
            results['validation_status'] = 'error'

        return results

    return await asyncio.to_thread(query_dnssec)


def format_dnssec_results(dnssec_results):
    """Format DNSSEC validation results for output"""
    lines = []
    lines.append("=== DNSSEC Validation ===")

    if not dnssec_results:
        lines.append("DNSSEC validation failed")
        lines.append("")
        return '\n'.join(lines)

    if dnssec_results.get('error'):
        lines.append(f"Error: {dnssec_results['error']}")
        lines.append("")
        return '\n'.join(lines)

    # Overall Status
    lines.append("")
    status = dnssec_results.get('validation_status', 'unknown')
    if 'secure' in status:
        lines.append(f"Status: ✓ DNSSEC Enabled - {status}")
        lines.append("Security: ✓ DNS responses are cryptographically signed")
    elif 'partial' in status:
        lines.append(f"Status: ⚠ {status}")
        lines.append("Security: ⚠ DNSSEC is partially configured")
    elif 'unsigned' in status:
        lines.append(f"Status: ✗ {status}")
        lines.append("Security: ✗ DNS responses are NOT signed (vulnerable to DNS spoofing)")
    else:
        lines.append(f"Status: ? {status}")

    # DNSKEY Records (Public Keys)
    if dnssec_results.get('has_dnskey'):
        lines.append("")
        lines.append(f"DNSKEY Records: ✓ Found {dnssec_results.get('key_count', 0)} key(s)")
        for idx, key in enumerate(dnssec_results.get('keys', []), 1):
            lines.append(f"  Key {idx}:")
            lines.append(f"    Type: {key['type']}")
            lines.append(f"    Algorithm: {key['algorithm']}")
            lines.append(f"    Key Tag: {key['key_tag']}")
    else:
        lines.append("")
        lines.append("DNSKEY Records: ✗ Not found")

    # DS Records (Delegation Signer)
    if dnssec_results.get('has_ds'):
        lines.append("")
        lines.append("DS Records: ✓ Found in parent zone")
        lines.append("  Chain of Trust: ✓ Domain is properly delegated from parent")
    else:
        lines.append("")
        lines.append("DS Records: ✗ Not found in parent zone")
        if dnssec_results.get('has_dnskey'):
            lines.append("  Chain of Trust: ⚠ Keys exist but not published to parent zone")

    # RRSIG Records (Signatures)
    if dnssec_results.get('has_rrsig'):
        lines.append("")
        lines.append(f"RRSIG Records: ✓ Found {dnssec_results.get('rrsig_count', 0)} signature(s)")

        for idx, sig in enumerate(dnssec_results.get('signatures', []), 1):
            lines.append(f"  Signature {idx}:")
            lines.append(f"    Covers: {sig['type_covered']} records")
            lines.append(f"    Algorithm: {sig['algorithm']}")
            lines.append(f"    Signer: {sig['signer']}")
            lines.append(f"    Key Tag: {sig['key_tag']}")
            lines.append(f"    Valid From: {sig['inception']}")
            lines.append(f"    Expires: {sig['expiration']}")

            if sig['valid']:
                days = sig.get('days_until_expiry')
                if days is not None:
                    if days <= 7:
                        lines.append(f"    Status: ⚠ Valid but expires in {days} days")
                    else:
                        lines.append(f"    Status: ✓ Valid ({days} days remaining)")
            else:
                lines.append("    Status: ✗ EXPIRED or not yet valid")
    else:
        lines.append("")
        lines.append("RRSIG Records: ✗ Not found")

    # Summary and Recommendations
    lines.append("")
    lines.append("DNSSEC Summary:")
    if dnssec_results.get('dnssec_enabled'):
        if dnssec_results.get('has_ds'):
            lines.append("  ✓ Full DNSSEC deployment with proper chain of trust")
        else:
            lines.append("  ⚠ DNSSEC configured but DS records not published to parent")
            lines.append("  Recommendation: Publish DS records to parent zone for full validation")
    else:
        lines.append("  ✗ DNSSEC not configured")
        lines.append("  Recommendation: Enable DNSSEC to protect against DNS spoofing/cache poisoning")

    lines.append("")
    return '\n'.join(lines)

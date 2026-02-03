"""
TLS/SSL Analysis Step
Deep SSL/TLS certificate and cipher analysis using SSLyze
"""

import asyncio
from loguru import logger


async def scan_tls(hostname, port=443, watch_uuid=None, update_signal=None, vulnerability_scan=False):
    """
    Perform comprehensive TLS/SSL analysis

    Args:
        hostname: Target hostname
        port: Port number (default 443)
        watch_uuid: Optional watch UUID for status updates
        update_signal: Optional blinker signal for status updates
        vulnerability_scan: Enable vulnerability scanning (Heartbleed, ROBOT, etc.)

    Returns:
        list: SSL scan results from SSLyze
    """
    if update_signal and watch_uuid:
        update_signal.send(watch_uuid=watch_uuid, status="TLS")

    def run_sslyze_scan():
        from sslyze import (
            Scanner,
            ServerNetworkLocation,
            ServerScanRequest,
            ScanCommand
        )

        # Create server location
        server_location = ServerNetworkLocation(hostname=hostname, port=port)

        # Define scan commands - always include certificate and cipher suites
        scan_commands = {
            ScanCommand.CERTIFICATE_INFO,
            ScanCommand.SSL_2_0_CIPHER_SUITES,
            ScanCommand.SSL_3_0_CIPHER_SUITES,
            ScanCommand.TLS_1_0_CIPHER_SUITES,
            ScanCommand.TLS_1_1_CIPHER_SUITES,
            ScanCommand.TLS_1_2_CIPHER_SUITES,
            ScanCommand.TLS_1_3_CIPHER_SUITES,
        }

        # Add vulnerability scans if enabled - AUTOMATICALLY discover all security checks
        if vulnerability_scan:
            # Get all available scan commands from sslyze
            all_commands = [cmd for cmd in dir(ScanCommand) if not cmd.startswith('_') and cmd.isupper()]

            # Filter out cipher suites and certificate commands we already have
            cipher_protocol_commands = {
                'SSL_2_0_CIPHER_SUITES', 'SSL_3_0_CIPHER_SUITES',
                'TLS_1_0_CIPHER_SUITES', 'TLS_1_1_CIPHER_SUITES',
                'TLS_1_2_CIPHER_SUITES', 'TLS_1_3_CIPHER_SUITES',
                'CERTIFICATE_INFO'
            }

            # Add all other security/vulnerability check commands
            security_commands = [
                getattr(ScanCommand, cmd)
                for cmd in all_commands
                if cmd not in cipher_protocol_commands
            ]
            scan_commands.update(security_commands)

            logger.debug(f"TLS vulnerability scanning enabled for {hostname}:{port} - {len(security_commands)} additional checks")

        scan_request = ServerScanRequest(
            server_location=server_location,
            scan_commands=scan_commands
        )

        # Run scan
        scanner = Scanner()
        scanner.queue_scans([scan_request])

        # Get results
        ssl_results = []
        for result in scanner.get_results():
            ssl_results.append(result)

        return ssl_results

    try:
        return await asyncio.to_thread(run_sslyze_scan)
    except Exception as e:
        logger.error(f"TLS analysis failed: {e}")
        return []


def format_tls_results(ssl_results, watch_uuid=None, update_signal=None):
    """Format TLS/SSL results for output"""
    lines = []
    lines.append("=== SSL/TLS Analysis (SSLyze) ===")
    lines.append("SERVER TLS Fingerprint - Full capabilities for JA3S analysis")
    lines.append("")

    if ssl_results:
        scan_result = ssl_results[0]

        # Check if scan was successful
        if not scan_result.scan_result:
            lines.append("TLS scan failed - target may not support TLS/SSL on this port")
            lines.append("")
            return '\n'.join(lines)

        # Certificate info
        if scan_result.scan_result.certificate_info and scan_result.scan_result.certificate_info.result:
            cert_scan_result = scan_result.scan_result.certificate_info.result
            lines.append("Certificate Information:")

            for cert_deployment in cert_scan_result.certificate_deployments:
                cert = cert_deployment.received_certificate_chain[0]
                lines.append(f"  Subject: {cert.subject.rfc4514_string()}")
                lines.append(f"  Issuer: {cert.issuer.rfc4514_string()}")

                # Certificate validity dates
                valid_from = cert.not_valid_before_utc
                valid_until = cert.not_valid_after_utc

                # Get current time in UTC (timezone-aware)
                from datetime import datetime, timezone
                now_utc = datetime.now(timezone.utc)

                # Check if certificate is currently valid
                is_valid = valid_from <= now_utc <= valid_until

                # Calculate days until expiry
                days_until_expiry = (valid_until - now_utc).days

                lines.append(f"  Valid From: {valid_from}")
                lines.append(f"  Valid Until: {valid_until}")

                # Add validity status
                if is_valid:
                    if days_until_expiry < 0:
                        lines.append(f"  Status: ✗ EXPIRED")
                    elif days_until_expiry <= 7:
                        lines.append(f"  Status: ⚠ EXPIRING SOON")
                    elif days_until_expiry <= 30:
                        lines.append(f"  Status: ✓ Valid")
                    else:
                        lines.append(f"  Status: ✓ Valid")
                elif now_utc < valid_from:
                    lines.append(f"  Status: ✗ NOT YET VALID")
                else:
                    lines.append(f"  Status: ✗ EXPIRED")

                lines.append(f"  Serial Number: {cert.serial_number}")

                # Subject Alternative Names
                try:
                    from cryptography.x509.oid import ExtensionOID
                    san_ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
                    san_names = [name.value for name in san_ext.value]
                    lines.append(f"  SANs: {', '.join(san_names)}")
                except:
                    pass

        # Cipher suites
        lines.append("")
        lines.append("Supported TLS Versions & Cipher Suites:")

        for tls_version in ['TLS_1_3', 'TLS_1_2', 'TLS_1_1', 'TLS_1_0', 'SSL_3_0', 'SSL_2_0']:
            cipher_attr = tls_version.lower() + '_cipher_suites'
            cipher_scan_attempt = getattr(scan_result.scan_result, cipher_attr, None)

            if cipher_scan_attempt and cipher_scan_attempt.result:
                cipher_result = cipher_scan_attempt.result
                if cipher_result.accepted_cipher_suites:
                    lines.append(f"  {tls_version.replace('_', ' ')}:")
                    for cipher in cipher_result.accepted_cipher_suites:
                        lines.append(f"    - {cipher.cipher_suite.name}")

        # Vulnerability Scan Results (if enabled) - GENERIC PARSER
        vulnerabilities = []

        # Map of known vulnerability names to display strings (for prettier output)
        vuln_display_names = {
            'heartbleed': 'Heartbleed (CVE-2014-0160)',
            'robot': 'ROBOT Attack',
            'openssl_ccs_injection': 'OpenSSL CCS Injection (CVE-2014-0224)',
            'tls_compression': 'TLS Compression (CRIME)',
            'session_renegotiation': 'Insecure Renegotiation',
            'tls_fallback_scsv': 'TLS Downgrade Protection',
            'tls_1_3_early_data': 'TLS 1.3 0-RTT',
            'elliptic_curves': 'Elliptic Curves Support',
            'session_resumption': 'Session Resumption',
            'tls_extended_master_secret': 'Extended Master Secret',
        }

        # Generic vulnerability checker - works for ANY sslyze vulnerability scan
        for attr_name in dir(scan_result.scan_result):
            if attr_name.startswith('_'):
                continue

            # Skip cipher suite and certificate scans
            if 'cipher' in attr_name.lower() or attr_name == 'certificate_info':
                continue

            scan_attempt = getattr(scan_result.scan_result, attr_name, None)
            if not scan_attempt or not hasattr(scan_attempt, 'result'):
                continue

            result_obj = scan_attempt.result
            if not result_obj:
                continue

            # Send status update for this vulnerability check
            if update_signal and watch_uuid:
                check_name = vuln_display_names.get(attr_name, attr_name.replace('_', ' ').title())
                update_signal.send(watch_uuid=watch_uuid, status=f"TLS: {check_name}")

            try:
                # Try to determine if this is a vulnerability
                is_vulnerable = False
                vuln_detected = False

                # Common vulnerability indicator patterns
                result_dict = vars(result_obj) if hasattr(result_obj, '__dict__') else {}

                # Check for "is_vulnerable_to_*" patterns
                for key, value in result_dict.items():
                    if 'vulnerable' in key.lower() and value is True:
                        is_vulnerable = True
                        vuln_detected = True
                        break
                    # Check for "supports_" patterns where support might be bad
                    if attr_name == 'tls_compression' and key == 'supports_compression' and value:
                        is_vulnerable = True
                        vuln_detected = True
                    # Check for ROBOT result enum
                    if 'robot' in key.lower() and 'VULNERABLE' in str(value).upper():
                        is_vulnerable = True
                        vuln_detected = True
                    # Check for insecure renegotiation
                    if attr_name == 'session_renegotiation':
                        is_secure = getattr(result_obj, 'is_secure_renegotiation_supported', True)
                        accepts_client = getattr(result_obj, 'accepts_client_renegotiation', False)
                        if not is_secure or accepts_client:
                            is_vulnerable = True
                            vuln_detected = True
                    # Check for missing downgrade protection
                    if attr_name == 'tls_fallback_scsv':
                        supports = getattr(result_obj, 'supports_fallback_scsv', True)
                        if not supports:
                            is_vulnerable = True
                            vuln_detected = True

                # If we detected this vulnerability check, add it to results
                if vuln_detected or attr_name in vuln_display_names:
                    display_name = vuln_display_names.get(attr_name, attr_name.replace('_', ' ').title())
                    vulnerabilities.append((display_name, is_vulnerable))

            except Exception as e:
                logger.debug(f"Could not parse {attr_name} result: {e}")

        # Display vulnerability scan report - show all checks
        if vulnerabilities:
            lines.append("")
            lines.append("=== TLS Security Vulnerability Report ===")

            # Count vulnerable issues
            vulnerable_count = sum(1 for _, is_vuln in vulnerabilities if is_vuln)

            if vulnerable_count > 0:
                lines.append(f"Status: ⚠️  {vulnerable_count} issue(s) found")
            else:
                lines.append("Status: ✓ All checks passed")

            lines.append("")
            for vuln_name, is_vulnerable in vulnerabilities:
                status = "✗ VULNERABLE" if is_vulnerable else "✓ Secure"
                lines.append(f"  {status}: {vuln_name}")

        # HTTP Security Headers (if scanned)
        if hasattr(scan_result.scan_result, 'http_headers') and scan_result.scan_result.http_headers:
            if scan_result.scan_result.http_headers.result:
                lines.append("")
                lines.append("HTTP Security Headers:")
                headers = scan_result.scan_result.http_headers.result
                if hasattr(headers, 'strict_transport_security_header') and headers.strict_transport_security_header:
                    lines.append(f"  ✓ HSTS: {headers.strict_transport_security_header.max_age} seconds")
                else:
                    lines.append("  ✗ HSTS: Not set")

    lines.append("")
    return '\n'.join(lines)

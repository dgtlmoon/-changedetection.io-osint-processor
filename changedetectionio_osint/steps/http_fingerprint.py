"""
HTTP Fingerprinting Step
Captures server-side HTTP/HTTPS fingerprints including redirect chains and CDN detection
"""

import asyncio
import socket
import time
import hashlib
from urllib.parse import urlparse, urljoin, urlunparse
from loguru import logger


async def scan_http(url, dns_resolver, proxy_url=None, watch_uuid=None, update_signal=None):
    """
    Perform HTTP fingerprinting on target URL

    Args:
        url: Target URL
        dns_resolver: Configured dns.resolver.Resolver instance
        proxy_url: Optional proxy URL
        watch_uuid: Optional watch UUID for status updates
        update_signal: Optional blinker signal for status updates

    Returns:
        dict: HTTP fingerprint data
    """
    if update_signal and watch_uuid:
        update_signal.send(watch_uuid=watch_uuid, status="HTTP")

    def fetch_http_fingerprint():
        """Synchronous HTTP fingerprinting - captures server TLS configuration"""
        import requests

        # Monkey-patch socket.getaddrinfo to use our custom DNS server
        original_getaddrinfo = socket.getaddrinfo

        def custom_getaddrinfo(host, port, family=0, type=0, proto=0, flags=0):
            """Custom getaddrinfo that uses our DNS_SERVER"""
            try:
                # Use our dns_resolver to resolve the hostname
                try:
                    answers = dns_resolver.resolve(host, 'A')
                    resolved_ip = str(answers[0])
                except:
                    # Fallback to AAAA
                    try:
                        answers = dns_resolver.resolve(host, 'AAAA')
                        resolved_ip = str(answers[0])
                    except:
                        # If our DNS fails, fall back to original
                        return original_getaddrinfo(host, port, family, type, proto, flags)

                # Return address info with our resolved IP
                if ':' in resolved_ip:
                    # IPv6
                    return [(socket.AF_INET6, socket.SOCK_STREAM, proto, '', (resolved_ip, port, 0, 0))]
                else:
                    # IPv4
                    return [(socket.AF_INET, socket.SOCK_STREAM, proto, '', (resolved_ip, port))]
            except:
                return original_getaddrinfo(host, port, family, type, proto, flags)

        # Apply the monkey-patch
        socket.getaddrinfo = custom_getaddrinfo

        parsed = urlparse(url)
        session = requests.Session()

        # Configure proxy if provided
        proxies = None
        if proxy_url:
            proxies = {'http': proxy_url, 'https': proxy_url}

        # Set realistic headers
        headers = {
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
        }

        fingerprint = {}
        start_time = time.time()

        # Track redirect chain
        redirect_chain = []

        # CDN/WAF detection patterns
        cdn_waf_indicators = {
            'Cloudflare': ['CF-Ray', 'cf-request-id', '__cfduid', 'cloudflare'],
            'Akamai': ['X-Akamai-', 'akamai'],
            'AWS CloudFront': ['X-Amz-Cf-', 'cloudfront'],
            'Fastly': ['Fastly-', 'X-Fastly-'],
            'Incapsula': ['X-CDN: Incapsula', 'incap_ses', 'visid_incap'],
            'Sucuri': ['X-Sucuri-', 'sucuri'],
            'StackPath': ['X-Stackpath-'],
            'KeyCDN': ['X-Edge-', 'Server: keycdn'],
            'Imperva': ['X-Iinfo', 'imperva'],
            'F5 BIG-IP': ['BigIP', 'F5-', 'X-WA-Info'],
            'Nginx': ['Server: nginx', 'X-Nginx-'],
            'Varnish': ['Via: varnish', 'X-Varnish'],
            'Squid': ['Via: squid', 'X-Squid-'],
        }

        try:
            # Follow redirects manually to capture chain
            current_url = url
            max_redirects = 5
            redirect_count = 0

            while redirect_count < max_redirects:
                response = session.get(
                    current_url,
                    headers=headers,
                    proxies=proxies,
                    timeout=10,
                    allow_redirects=False,
                    verify=True
                )

                # Record this hop in redirect chain
                redirect_chain.append({
                    'url': current_url,
                    'status': response.status_code,
                    'location': response.headers.get('Location', '')
                })

                # Check if it's a redirect
                if response.status_code in [301, 302, 303, 307, 308]:
                    location = response.headers.get('Location')
                    if not location:
                        break

                    # Handle relative URLs
                    if location.startswith('/'):
                        parsed_current = urlparse(current_url)
                        location = urlunparse((
                            parsed_current.scheme,
                            parsed_current.netloc,
                            location,
                            '', '', ''
                        ))
                    elif not location.startswith(('http://', 'https://')):
                        location = urljoin(current_url, location)

                    current_url = location
                    redirect_count += 1
                else:
                    # Final response
                    break

            elapsed_time = time.time() - start_time

            # Basic response info
            fingerprint['status_code'] = response.status_code
            fingerprint['reason'] = response.reason
            fingerprint['elapsed_ms'] = int(elapsed_time * 1000)
            fingerprint['content_length'] = len(response.content)
            fingerprint['http_version'] = f"HTTP/{response.raw.version // 10}.{response.raw.version % 10}"

            # All response headers
            fingerprint['headers'] = dict(response.headers)

            # Server fingerprinting
            fingerprint['server'] = response.headers.get('Server', 'Not disclosed')
            fingerprint['powered_by'] = response.headers.get('X-Powered-By', 'Not disclosed')

            # Security headers
            security_headers = {
                'Strict-Transport-Security': response.headers.get('Strict-Transport-Security'),
                'Content-Security-Policy': response.headers.get('Content-Security-Policy'),
                'X-Frame-Options': response.headers.get('X-Frame-Options'),
                'X-Content-Type-Options': response.headers.get('X-Content-Type-Options'),
                'X-XSS-Protection': response.headers.get('X-XSS-Protection'),
                'Referrer-Policy': response.headers.get('Referrer-Policy'),
                'Permissions-Policy': response.headers.get('Permissions-Policy'),
            }
            fingerprint['security_headers'] = {k: v for k, v in security_headers.items() if v}

            # SERVER TLS Configuration (what the server chose/prefers)
            if parsed.scheme == 'https':
                try:
                    # Get what the SERVER negotiated/chose
                    if hasattr(response.raw, 'connection') and response.raw.connection:
                        sock = getattr(response.raw.connection, 'sock', None)
                        if sock:
                            # Server's certificate info
                            if hasattr(sock, 'getpeercert'):
                                cert = sock.getpeercert()
                                if cert:
                                    fingerprint['server_cert_subject'] = dict(x[0] for x in cert.get('subject', []))
                                    fingerprint['server_cert_issuer'] = dict(x[0] for x in cert.get('issuer', []))

                            # What the SERVER chose/negotiated with us
                            if hasattr(sock, 'version'):
                                fingerprint['server_tls_version'] = sock.version()
                            if hasattr(sock, 'cipher'):
                                cipher_info = sock.cipher()
                                fingerprint['server_cipher'] = cipher_info
                                # JA3S-like: The server's preferred cipher tells us about the server
                                if cipher_info:
                                    # Create simple server fingerprint from what it chose
                                    server_fp_string = f"{cipher_info[0]}:{cipher_info[1]}:{cipher_info[2]}"
                                    fingerprint['server_cipher_fingerprint'] = hashlib.md5(server_fp_string.encode()).hexdigest()
                except Exception as e:
                    fingerprint['ssl_error'] = str(e)

            # Cookies
            if response.cookies:
                fingerprint['cookies'] = [
                    f"{cookie.name}={'[HttpOnly]' if cookie.has_nonstandard_attr('HttpOnly') else ''}"
                    f"{'[Secure]' if cookie.secure else ''}"
                    for cookie in response.cookies
                ]

            # CDN/WAF Detection
            detected_cdns = []
            all_headers_lower = {k.lower(): v.lower() for k, v in response.headers.items()}
            all_cookies_lower = ' '.join([c.name.lower() for c in response.cookies])

            for cdn_name, indicators in cdn_waf_indicators.items():
                for indicator in indicators:
                    indicator_lower = indicator.lower()
                    # Check headers (both key and value)
                    header_match = any(
                        indicator_lower in header_key or indicator_lower in header_value
                        for header_key, header_value in all_headers_lower.items()
                    )
                    # Check cookies
                    cookie_match = indicator_lower in all_cookies_lower

                    if header_match or cookie_match:
                        if cdn_name not in detected_cdns:
                            detected_cdns.append(cdn_name)
                        break

            if detected_cdns:
                fingerprint['cdn_waf'] = detected_cdns

            # Store redirect chain in fingerprint
            fingerprint['redirect_chain'] = redirect_chain

        except Exception as e:
            fingerprint['error'] = str(e)
            logger.error(f"HTTP fingerprinting failed: {e}")
        finally:
            # Restore original getaddrinfo
            socket.getaddrinfo = original_getaddrinfo

        return fingerprint

    return await asyncio.to_thread(fetch_http_fingerprint)


def format_http_results(http_fingerprint, parsed_url):
    """Format HTTP results for output"""
    lines = []
    lines.append("=== HTTP Response Fingerprint ===")

    if 'error' in http_fingerprint:
        lines.append(f"Error: {http_fingerprint['error']}")
    else:
        # Response basics
        lines.append(f"Status: {http_fingerprint.get('status_code')} {http_fingerprint.get('reason')}")
        lines.append(f"HTTP Version: {http_fingerprint.get('http_version')}")
        lines.append(f"Content Length: {http_fingerprint.get('content_length')} bytes")
        lines.append("")

        # Server identification
        lines.append("Server Identification:")
        lines.append(f"  Server: {http_fingerprint.get('server')}")
        lines.append(f"  X-Powered-By: {http_fingerprint.get('powered_by')}")
        lines.append("")

        # Security headers
        if http_fingerprint.get('security_headers'):
            lines.append("Security Headers:")
            for header, value in http_fingerprint['security_headers'].items():
                # Truncate long CSP headers
                if len(str(value)) > 100:
                    value = str(value)[:100] + "..."
                lines.append(f"  {header}: {value}")
            lines.append("")

        # SERVER TLS Configuration (what the server chose)
        if http_fingerprint.get('server_tls_version'):
            lines.append("Server TLS Configuration:")
            lines.append(f"  TLS Version: {http_fingerprint.get('server_tls_version')}")

            if http_fingerprint.get('server_cipher'):
                cipher = http_fingerprint['server_cipher']
                lines.append(f"  Server Chose Cipher: {cipher[0]}")
                lines.append(f"  Cipher Protocol: {cipher[1]}")
                lines.append(f"  Cipher Bits: {cipher[2]}")

            # Server cipher fingerprint (JA3S-like)
            if http_fingerprint.get('server_cipher_fingerprint'):
                lines.append(f"  Server Cipher Fingerprint: {http_fingerprint['server_cipher_fingerprint']}")

            lines.append("")
            lines.append("  Note: The cipher the server chose can indicate")
            lines.append("  server software (nginx, Apache, IIS, Cloudflare, etc.)")
            lines.append("  See 'SSL/TLS Analysis' section for full server capabilities.")
            lines.append("")

        # CDN/WAF Detection
        if http_fingerprint.get('cdn_waf'):
            lines.append("CDN/WAF/Proxy Detection:")
            for cdn in http_fingerprint['cdn_waf']:
                lines.append(f"  - {cdn}")
            lines.append("")

        # Redirect Chain
        redirect_chain = http_fingerprint.get('redirect_chain', [])
        if redirect_chain and len(redirect_chain) > 1:
            lines.append("Redirect Chain:")
            for i, hop in enumerate(redirect_chain, 1):
                lines.append(f"  {i}. [{hop['status']}] {hop['url']}")
                if hop.get('location'):
                    lines.append(f"     → {hop['location']}")
            lines.append("")

        # Interesting headers
        headers = http_fingerprint.get('headers', {})
        interesting_headers = [
            'Content-Type', 'Content-Encoding', 'Transfer-Encoding',
            'Cache-Control', 'Pragma', 'Expires', 'ETag', 'Last-Modified',
            'Access-Control-Allow-Origin', 'Vary', 'X-Request-ID', 'X-Runtime'
        ]

        found_headers = {h: headers[h] for h in interesting_headers if h in headers}
        if found_headers:
            lines.append("Notable Headers:")
            for header, value in found_headers.items():
                if len(str(value)) > 100:
                    value = str(value)[:100] + "..."
                lines.append(f"  {header}: {value}")
            lines.append("")

        # Cookies
        if http_fingerprint.get('cookies'):
            lines.append("Cookies Set:")
            for cookie in http_fingerprint['cookies']:
                lines.append(f"  {cookie}")

    lines.append("")
    return '\n'.join(lines)

"""
SSH Fingerprinting Step
Connects to SSH service to extract server banner, version, and host key fingerprints
"""

import asyncio
# SOCKS5 proxy support: SSH fingerprinting supports SOCKS5 via python-socks
supports_socks5 = True
import socket
import hashlib
import base64
from loguru import logger


async def scan_ssh(hostname, port=22, timeout=5, proxy_url=None, watch_uuid=None, update_signal=None):
    """
    Perform SSH server fingerprinting

    Args:
        hostname: Target hostname or IP address
        port: SSH port (default 22)
        timeout: Connection timeout in seconds
        proxy_url: Optional SOCKS5 proxy URL (socks5://user:pass@host:port)
        watch_uuid: Optional watch UUID for status updates
        update_signal: Optional blinker signal for status updates

    Returns:
        dict: SSH fingerprint data
    """
    if update_signal and watch_uuid:
        update_signal.send(watch_uuid=watch_uuid, status="SSH")

    async def ssh_fingerprint():
        results = {
            'port_open': False,
            'banner': None,
            'version': None,
            'software': None,
            'host_keys': [],
            'key_exchange_algorithms': [],
            'encryption_algorithms': [],
            'mac_algorithms': [],
            'compression_algorithms': [],
            'error': None
        }

        try:
            # Connect to SSH port (with optional SOCKS5 proxy support)
            if proxy_url and proxy_url.strip():
                # Use SOCKS5 proxy for connection
                try:
                    from python_socks.async_.asyncio import Proxy
                    from urllib.parse import urlparse

                    # Parse SOCKS5 proxy URL
                    parsed = urlparse(proxy_url)
                    proxy = Proxy.from_url(proxy_url)

                    # Connect through SOCKS5 proxy
                    sock = await asyncio.wait_for(
                        proxy.connect(dest_host=hostname, dest_port=port, timeout=timeout),
                        timeout=timeout
                    )

                    # Create reader/writer from the socket
                    reader, writer = await asyncio.open_connection(sock=sock)

                except ImportError:
                    logger.error("SOCKS5 proxy requested but 'python-socks[asyncio]' is not installed")
                    results['error'] = "SOCKS5 proxy support requires 'python-socks[asyncio]' package"
                    return results
            else:
                # Direct connection (no proxy)
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(hostname, port),
                    timeout=timeout
                )

            results['port_open'] = True

            try:
                # Read SSH banner (SSH-2.0-...)
                banner_line = await asyncio.wait_for(reader.readline(), timeout=timeout)
                banner = banner_line.decode('utf-8', errors='ignore').strip()
                results['banner'] = banner

                # Parse SSH version and software
                # Format: SSH-protoversion-softwareversion [SP comments]
                if banner.startswith('SSH-'):
                    parts = banner.split('-', 2)
                    if len(parts) >= 3:
                        results['version'] = parts[1]  # e.g., "2.0"
                        software_parts = parts[2].split(' ', 1)
                        results['software'] = software_parts[0]  # e.g., "OpenSSH_8.2p1"

                logger.debug(f"SSH banner: {banner}")

                # Send our banner (minimal SSH client identification)
                writer.write(b'SSH-2.0-ChangeDetectionIO_OSINT_Scanner\r\n')
                await writer.drain()

                # Try to read key exchange init (this contains algorithm lists)
                # SSH packet format: packet_length (4 bytes) + padding_length (1 byte) + payload + padding + MAC
                try:
                    # Read packet length (first 4 bytes after banner exchange)
                    packet_length_bytes = await asyncio.wait_for(reader.readexactly(4), timeout=timeout)
                    packet_length = int.from_bytes(packet_length_bytes, byteorder='big')

                    # SSH packets are typically < 35000 bytes for key exchange
                    if 0 < packet_length < 35000:
                        # Read the rest of the packet
                        packet_data = await asyncio.wait_for(reader.readexactly(packet_length), timeout=timeout)

                        # Parse SSH_MSG_KEXINIT (message type 20)
                        if len(packet_data) > 1 and packet_data[0] == 20:
                            # Skip: padding_length(1) + message_type(1) + cookie(16)
                            offset = 1 + 16

                            # Helper to read name-list (4-byte length + comma-separated names)
                            def read_name_list(data, start_offset):
                                if start_offset + 4 > len(data):
                                    return [], start_offset
                                list_len = int.from_bytes(data[start_offset:start_offset+4], byteorder='big')
                                start_offset += 4
                                if start_offset + list_len > len(data):
                                    return [], start_offset
                                names_bytes = data[start_offset:start_offset+list_len]
                                names = names_bytes.decode('utf-8', errors='ignore').split(',')
                                return names, start_offset + list_len

                            # Read algorithm name-lists in order
                            results['key_exchange_algorithms'], offset = read_name_list(packet_data, offset)
                            server_host_key_algorithms, offset = read_name_list(packet_data, offset)
                            results['encryption_algorithms'], offset = read_name_list(packet_data, offset)
                            offset = read_name_list(packet_data, offset)[1]  # Skip encryption_algorithms_server_to_client
                            results['mac_algorithms'], offset = read_name_list(packet_data, offset)
                            offset = read_name_list(packet_data, offset)[1]  # Skip mac_algorithms_server_to_client
                            results['compression_algorithms'], offset = read_name_list(packet_data, offset)

                            # Store host key algorithms
                            if server_host_key_algorithms:
                                for alg in server_host_key_algorithms:
                                    results['host_keys'].append({
                                        'algorithm': alg,
                                        'fingerprint': None  # Would need full key exchange to get actual keys
                                    })

                            logger.debug(f"SSH algorithms parsed successfully")

                except asyncio.TimeoutError:
                    logger.debug("Timeout reading SSH key exchange packet")
                except Exception as e:
                    logger.debug(f"Could not parse SSH key exchange: {e}")

            finally:
                writer.close()
                await writer.wait_closed()

        except asyncio.TimeoutError:
            results['error'] = f"Connection timeout (port {port})"
            logger.debug(f"SSH connection timeout: {hostname}:{port}")
        except ConnectionRefusedError:
            results['error'] = f"Connection refused (port {port} closed or filtered)"
        except socket.gaierror as e:
            results['error'] = f"DNS resolution failed: {e}"
        except Exception as e:
            results['error'] = f"Connection error: {str(e)}"
            logger.debug(f"SSH fingerprint error: {e}")

        return results

    return await ssh_fingerprint()


def format_ssh_results(ssh_results, port=22):
    """Format SSH fingerprint results for output"""
    lines = []
    lines.append(f"=== SSH Server Fingerprint (Port {port}) ===")

    if not ssh_results:
        lines.append("No SSH scan results")
        lines.append("")
        return '\n'.join(lines)

    if ssh_results.get('error') and not ssh_results.get('port_open'):
        lines.append(f"Status: ✗ {ssh_results['error']}")
        lines.append("")
        return '\n'.join(lines)

    if not ssh_results.get('port_open'):
        lines.append(f"Status: ✗ Port {port} closed or filtered")
        lines.append("")
        return '\n'.join(lines)

    # Port is open
    lines.append(f"Status: ✓ SSH service detected on port {port}")
    lines.append("")

    # Banner and version
    if ssh_results.get('banner'):
        lines.append(f"Banner: {ssh_results['banner']}")
    if ssh_results.get('version'):
        lines.append(f"Protocol Version: SSH-{ssh_results['version']}")
    if ssh_results.get('software'):
        lines.append(f"Server Software: {ssh_results['software']}")

        # Identify SSH server type
        software = ssh_results['software'].lower()
        if 'openssh' in software:
            lines.append("  Server Type: OpenSSH (most common, widely audited)")
        elif 'dropbear' in software:
            lines.append("  Server Type: Dropbear (lightweight SSH server)")
        elif 'libssh' in software:
            lines.append("  Server Type: libssh (SSH library implementation)")
        elif 'cisco' in software:
            lines.append("  Server Type: Cisco SSH (network device)")
        elif 'rosssh' in software:
            lines.append("  Server Type: ROS SSH (MikroTik RouterOS)")
        else:
            lines.append("  Server Type: Unknown or custom implementation")

    # Host key algorithms
    if ssh_results.get('host_keys'):
        lines.append("")
        lines.append("Supported Host Key Algorithms:")
        for key in ssh_results['host_keys']:
            alg = key['algorithm']
            lines.append(f"  • {alg}")

            # Security assessment of algorithm
            if 'ed25519' in alg:
                lines.append("    Security: ✓ Excellent (Ed25519 - modern, fast, secure)")
            elif 'ecdsa' in alg:
                lines.append("    Security: ✓ Good (ECDSA - modern elliptic curve)")
            elif 'rsa' in alg and 'sha256' in alg:
                lines.append("    Security: ✓ Good (RSA with SHA-256)")
            elif 'rsa' in alg and 'sha512' in alg:
                lines.append("    Security: ✓ Good (RSA with SHA-512)")
            elif 'rsa' in alg:
                lines.append("    Security: ⚠ Acceptable (RSA - ensure >= 2048 bits)")
            elif 'dsa' in alg or 'dss' in alg:
                lines.append("    Security: ✗ Weak (DSA - deprecated, insecure)")
            elif 'ssh-rsa' == alg:
                lines.append("    Security: ⚠ Legacy (ssh-rsa - being phased out)")

    # Key exchange algorithms
    if ssh_results.get('key_exchange_algorithms'):
        lines.append("")
        lines.append("Key Exchange Algorithms:")
        # Show only first 5 to avoid clutter
        for alg in ssh_results['key_exchange_algorithms'][:5]:
            lines.append(f"  • {alg}")
        if len(ssh_results['key_exchange_algorithms']) > 5:
            lines.append(f"  ... and {len(ssh_results['key_exchange_algorithms']) - 5} more")

    # Encryption algorithms
    if ssh_results.get('encryption_algorithms'):
        lines.append("")
        lines.append("Encryption Algorithms (Ciphers):")
        for alg in ssh_results['encryption_algorithms'][:5]:
            lines.append(f"  • {alg}")
            # Flag weak ciphers
            if 'cbc' in alg.lower():
                lines.append("    ⚠ CBC mode (vulnerable to certain attacks)")
            elif 'arcfour' in alg.lower() or 'rc4' in alg.lower():
                lines.append("    ✗ RC4 (broken, should be disabled)")
            elif '3des' in alg.lower():
                lines.append("    ⚠ 3DES (outdated, slow)")
            elif 'chacha20' in alg.lower() or 'aes.*gcm' in alg.lower():
                lines.append("    ✓ Modern authenticated encryption")
        if len(ssh_results['encryption_algorithms']) > 5:
            lines.append(f"  ... and {len(ssh_results['encryption_algorithms']) - 5} more")

    # MAC algorithms
    if ssh_results.get('mac_algorithms'):
        lines.append("")
        lines.append("MAC (Message Authentication) Algorithms:")
        for alg in ssh_results['mac_algorithms'][:5]:
            lines.append(f"  • {alg}")
        if len(ssh_results['mac_algorithms']) > 5:
            lines.append(f"  ... and {len(ssh_results['mac_algorithms']) - 5} more")

    # Compression
    if ssh_results.get('compression_algorithms'):
        lines.append("")
        compression = ', '.join(ssh_results['compression_algorithms'])
        lines.append(f"Compression: {compression}")

    # Security recommendations
    lines.append("")
    lines.append("Security Recommendations:")
    has_issues = False

    if ssh_results.get('host_keys'):
        weak_keys = [k for k in ssh_results['host_keys'] if 'dsa' in k['algorithm'].lower() or 'dss' in k['algorithm'].lower()]
        if weak_keys:
            lines.append("  ⚠ Disable weak DSA host keys")
            has_issues = True

    if ssh_results.get('encryption_algorithms'):
        weak_ciphers = [c for c in ssh_results['encryption_algorithms'] if 'cbc' in c.lower() or 'arcfour' in c.lower() or '3des' in c.lower()]
        if weak_ciphers:
            lines.append("  ⚠ Disable weak/legacy ciphers (CBC mode, 3DES, RC4)")
            has_issues = True

    if not has_issues:
        lines.append("  ✓ No obvious security issues detected")

    lines.append("")
    return '\n'.join(lines)

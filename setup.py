#!/usr/bin/env python
"""
Setup for OSINT Reconnaissance Processor Plugin for changedetection.io

This processor provides comprehensive OSINT reconnaissance capabilities including
DNS queries, WHOIS lookups, HTTP fingerprinting, SSL/TLS analysis, port scanning,
traceroute, and BGP/ASN information.
"""

from setuptools import setup, find_packages

setup(
    name='changedetection-osint-processor',
    version='0.0.2',
    description='OSINT Reconnaissance Processor for changedetection.io with Email Security, DNSSEC, SSH & SMTP',
    long_description=open('README.md').read(),
    long_description_content_type='text/markdown',
    author='changedetection.io contributors',
    url='https://github.com/dgtlmoon/changedetection.io',
    packages=find_packages(),
    include_package_data=True,
    install_requires=[
        # Note: changedetection.io not listed as it's the parent package
        'dnspython>=2.0.0',             # DNS queries (A, AAAA, MX, NS, TXT, SOA, CAA)
        'python-whois>=0.8.0',          # WHOIS lookups for domain reconnaissance
        'sslyze>=6.0.0',                # Deep SSL/TLS certificate and cipher analysis
        'requests>=2.26.0',             # HTTP fingerprinting (already in changedetection.io)
        'mac-vendor-lookup>=0.1.12',    # MAC address vendor lookup from IEEE OUI database
        'cryptography>=43,<45',         # Compatibility constraint: sslyze requires <45
        'python-socks[asyncio]>=2.0.0', # SOCKS5 proxy support for SSH/SMTP fingerprinting
    ],
    entry_points={
        'changedetectionio': [
            'osint_processor = changedetectionio_osint.plugin',
        ],
    },
    python_requires='>=3.10',
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Intended Audience :: System Administrators',
        'Intended Audience :: Information Technology',
        'Topic :: Internet :: WWW/HTTP :: Site Management',
        'Topic :: System :: Monitoring',
        'Topic :: System :: Networking :: Monitoring',
        'License :: OSI Approved :: GNU Affero General Public License v3',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
        'Programming Language :: Python :: 3.12',
    ],
    keywords='osint reconnaissance dns dnssec spf dmarc dkim whois ssl tls ssh smtp port-scan changedetection monitoring email-security',
    license='AGPL-3.0',
)

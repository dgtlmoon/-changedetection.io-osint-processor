"""
OSINT Reconnaissance Processor for changedetection.io

Uses the osint PyPI package for comprehensive reconnaissance.
"""

# Translation marker for extraction
def _(x): return x
processor_description = _('OSINT Reconnaissance (DNS, WHOIS, SSL, Ports)')
name = _('OSINT Reconnaissance')
description = _('Comprehensive reconnaissance using OSINT tools (DNS, WHOIS, SSL certificates, port scanning)')
processor_weight = -50  # Show before text_json_diff
list_badge_text = "OSINT"
del _

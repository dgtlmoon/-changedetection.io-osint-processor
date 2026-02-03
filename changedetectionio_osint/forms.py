"""
Forms for OSINT Reconnaissance Processor configuration.

Fields prefixed with 'processor_config_*' are automatically saved to
a JSON file in the watch data directory (osint_recon.json).
"""

from wtforms import (
    BooleanField,
    StringField,
    validators
)
from wtforms.fields.choices import RadioField
from flask_babel import lazy_gettext as _l

from changedetectionio.forms import processor_text_json_diff_form


class processor_settings_form(processor_text_json_diff_form):
    """Form for OSINT Reconnaissance processor settings."""

    # DNS Configuration
    processor_config_dns_server = StringField(
        _l('DNS Server'),
        validators=[
            validators.Optional(),
            validators.Length(max=100, message=_l('DNS server address is too long'))
        ],
        render_kw={"placeholder": "8.8.8.8", "size": "20"}
    )

    # Execution Mode
    processor_config_scan_mode = RadioField(
        _l('Scan Mode'),
        choices=[
            ('serial', _l('Serial (slower, safer, easier to debug)')),
            ('parallel', _l('Parallel (faster, 4-5x speedup)'))
        ],
        default='serial'
    )

    # Individual scan step toggles
    processor_config_enable_dns = BooleanField(
        _l('DNS Queries'),
        default=True
    )

    processor_config_enable_whois = BooleanField(
        _l('WHOIS Lookup'),
        default=True
    )

    processor_config_enable_http = BooleanField(
        _l('HTTP Fingerprinting'),
        default=True
    )

    processor_config_enable_tls = BooleanField(
        _l('SSL/TLS Analysis'),
        default=True
    )

    processor_config_tls_vulnerability_scan = BooleanField(
        _l('TLS Vulnerability Scanning'),
        default=False
    )

    processor_config_enable_portscan = BooleanField(
        _l('Port Scanning'),
        default=False
    )

    processor_config_enable_traceroute = BooleanField(
        _l('Traceroute'),
        default=True
    )

    processor_config_enable_bgp = BooleanField(
        _l('BGP/ASN Information'),
        default=True
    )

    processor_config_enable_os_detection = BooleanField(
        _l('OS Detection'),
        default=True
    )

    def extra_tab_content(self):
        """Tab label for processor-specific settings."""
        return _l('OSINT Settings')

    def extra_form_content(self):
        """Render processor-specific form fields.

        @NOTE: Fields prefixed with processor_config_* are saved to
        datadir/uuid/osint_recon.json and read at process time.
        """
        return '''
        {% from '_helpers.html' import render_field, render_checkbox_field %}
        <fieldset>
            <legend>OSINT Reconnaissance Configuration</legend>

            <div class="pure-control-group">
                {{ render_field(form.processor_config_dns_server) }}
                <span class="pure-form-message-inline">
                    <strong>DNS server to use for all DNS lookups.</strong><br>
                    Default: 8.8.8.8 (Google DNS). Other options: 1.1.1.1 (Cloudflare), 9.9.9.9 (Quad9)
                </span>
            </div>

            <div class="pure-control-group">
                <fieldset class="pure-group inline-radio">
                    {{ render_field(form.processor_config_scan_mode) }}
                </fieldset>
                <span class="pure-form-message-inline">
                    <strong>Serial mode</strong> runs scans one after another (safer, easier to debug).<br>
                    <strong>Parallel mode</strong> runs all scans simultaneously (4-5x faster).
                </span>
            </div>
        </fieldset>

        <fieldset>
            <legend>Enable/Disable Scan Steps</legend>
            <span class="pure-form-message-inline" style="display: block; margin-bottom: 10px;">
                Uncheck any scan steps you don't want to run. This can reduce processing time and output size.
            </span>

            <div class="pure-control-group">
                {{ render_checkbox_field(form.processor_config_enable_dns) }}
                <span class="pure-form-message-inline">
                    DNS queries: A, AAAA, MX, NS, TXT, SOA, CAA records
                </span>
            </div>

            <div class="pure-control-group">
                {{ render_checkbox_field(form.processor_config_enable_whois) }}
                <span class="pure-form-message-inline">
                    WHOIS domain registration information (registrar, nameservers, dates)
                </span>
            </div>

            <div class="pure-control-group">
                {{ render_checkbox_field(form.processor_config_enable_http) }}
                <span class="pure-form-message-inline">
                    HTTP fingerprinting: Server headers, CDN/WAF detection, redirect chains, cookies
                </span>
            </div>

            <div class="pure-control-group">
                {{ render_checkbox_field(form.processor_config_enable_tls) }}
                <span class="pure-form-message-inline">
                    SSL/TLS certificate analysis: Validity, issuer, cipher suites, protocols
                </span>
            </div>

            <div class="pure-control-group" style="margin-left: 25px;">
                {{ render_checkbox_field(form.processor_config_tls_vulnerability_scan) }}
                <span class="pure-form-message-inline">
                    <strong>⚠️ Advanced TLS security checks:</strong> Heartbleed, ROBOT, CCS Injection, TLS Compression (CRIME), Session Renegotiation, and more. Adds ~5-10 seconds to scan time.
                </span>
            </div>

            <div class="pure-control-group">
                {{ render_checkbox_field(form.processor_config_enable_portscan) }}
                <span class="pure-form-message-inline">
                    Port scanning: Check common service ports (HTTP, HTTPS, SSH, FTP, etc.)
                </span>
            </div>

            <div class="pure-control-group">
                {{ render_checkbox_field(form.processor_config_enable_traceroute) }}
                <span class="pure-form-message-inline">
                    Traceroute: Network path analysis (last N hops to target)
                </span>
            </div>

            <div class="pure-control-group">
                {{ render_checkbox_field(form.processor_config_enable_bgp) }}
                <span class="pure-form-message-inline">
                    BGP/ASN information: Autonomous System Number and ISP details
                </span>
            </div>

            <div class="pure-control-group">
                {{ render_checkbox_field(form.processor_config_enable_os_detection) }}
                <span class="pure-form-message-inline">
                    OS detection via TTL fingerprinting (requires raw socket permissions for active scanning)
                </span>
            </div>
        </fieldset>
        '''

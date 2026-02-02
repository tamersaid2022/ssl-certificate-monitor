#!/usr/bin/env python3
"""
SSL/TLS Certificate Monitor
Automated certificate monitoring, expiration alerting, chain validation,
and SSL inspection analysis for enterprise networks

Author: Tamer Khalifa (CCIE #68867)
GitHub: https://github.com/tamersaid2022
"""

import os
import sys
import ssl
import json
import socket
import logging
import argparse
import hashlib
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, field, asdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse
import ipaddress

import yaml
from dotenv import load_dotenv

# Optional imports
try:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa, ec
    from cryptography.x509.oid import NameOID, ExtensionOID
    CRYPTOGRAPHY_AVAILABLE = True
except ImportError:
    CRYPTOGRAPHY_AVAILABLE = False
    print("⚠️ cryptography not installed. Install with: pip install cryptography")

try:
    import OpenSSL
    OPENSSL_AVAILABLE = True
except ImportError:
    OPENSSL_AVAILABLE = False

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

try:
    import pandas as pd
    PANDAS_AVAILABLE = True
except ImportError:
    PANDAS_AVAILABLE = False

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.progress import Progress
    console = Console()
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False
    console = None

try:
    from flask import Flask, jsonify, request, render_template_string
    FLASK_AVAILABLE = True
except ImportError:
    FLASK_AVAILABLE = False

# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('ssl_monitor.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)


# =============================================================================
# CONFIGURATION
# =============================================================================

@dataclass
class Config:
    """Application configuration"""
    timeout: int = 10
    retries: int = 2
    threads: int = 20
    ports: List[int] = field(default_factory=lambda: [443, 8443, 636, 993, 995, 587, 465])
    critical_days: int = 7
    warning_days: int = 30
    notice_days: int = 60
    info_days: int = 90
    min_protocol: str = "TLSv1.2"
    min_key_size: int = 2048
    prohibited_ciphers: List[str] = field(default_factory=lambda: [
        "RC4", "DES", "3DES", "MD5", "NULL", "EXPORT"
    ])
    flask_host: str = "0.0.0.0"
    flask_port: int = 5000
    flask_secret: str = "change-me-in-production"

    @classmethod
    def from_file(cls, filepath: str) -> "Config":
        """Load config from YAML file"""
        config = cls()
        if os.path.exists(filepath):
            with open(filepath) as f:
                data = yaml.safe_load(f) or {}

            scanning = data.get("scanning", {})
            config.timeout = scanning.get("timeout", 10)
            config.retries = scanning.get("retries", 2)
            config.threads = scanning.get("threads", 20)
            config.ports = scanning.get("ports", config.ports)

            thresholds = data.get("thresholds", {})
            config.critical_days = thresholds.get("critical", 7)
            config.warning_days = thresholds.get("warning", 30)
            config.notice_days = thresholds.get("notice", 60)
            config.info_days = thresholds.get("info", 90)

            compliance = data.get("compliance", {})
            config.min_protocol = compliance.get("min_protocol", "TLSv1.2")
            config.min_key_size = compliance.get("min_key_size", 2048)
            config.prohibited_ciphers = compliance.get("prohibited_ciphers", config.prohibited_ciphers)

            dashboard = data.get("dashboard", {})
            config.flask_host = dashboard.get("host", "0.0.0.0")
            config.flask_port = dashboard.get("port", 5000)
            config.flask_secret = os.path.expandvars(dashboard.get("secret_key", "change-me"))

        return config


# =============================================================================
# DATA CLASSES
# =============================================================================

@dataclass
class CertificateInfo:
    """SSL/TLS certificate information"""
    host: str
    port: int = 443
    status: str = "unknown"         # valid, expiring, expired, error
    subject: str = ""
    issuer: str = ""
    issuer_org: str = ""
    serial_number: str = ""
    not_before: Optional[datetime] = None
    not_after: Optional[datetime] = None
    days_remaining: int = 0
    key_type: str = ""
    key_size: int = 0
    signature_algorithm: str = ""
    protocol_version: str = ""
    cipher_name: str = ""
    cipher_bits: int = 0
    san: List[str] = field(default_factory=list)
    chain_length: int = 0
    chain_valid: bool = False
    chain_details: List[Dict] = field(default_factory=list)
    is_self_signed: bool = False
    is_wildcard: bool = False
    is_intercepted: bool = False
    intercepted_by: str = ""
    hsts_enabled: bool = False
    hsts_max_age: int = 0
    ocsp_stapling: bool = False
    fingerprint_sha256: str = ""
    compliance_pci: bool = True
    compliance_nist: bool = True
    compliance_issues: List[str] = field(default_factory=list)
    error_message: str = ""
    last_checked: datetime = field(default_factory=datetime.now)

    @property
    def severity(self) -> str:
        """Get severity based on days remaining"""
        if self.status == "expired":
            return "expired"
        if self.days_remaining <= 7:
            return "critical"
        if self.days_remaining <= 30:
            return "warning"
        if self.days_remaining <= 60:
            return "notice"
        return "healthy"

    def to_dict(self) -> Dict:
        """Convert to dictionary"""
        data = asdict(self)
        data['not_before'] = self.not_before.isoformat() if self.not_before else None
        data['not_after'] = self.not_after.isoformat() if self.not_after else None
        data['last_checked'] = self.last_checked.isoformat()
        data['severity'] = self.severity
        return data


@dataclass
class ScanSummary:
    """Summary of a certificate scan"""
    total: int = 0
    healthy: int = 0
    notice: int = 0
    warning: int = 0
    critical: int = 0
    expired: int = 0
    errors: int = 0
    intercepted: int = 0
    non_compliant: int = 0
    scan_start: datetime = field(default_factory=datetime.now)
    scan_end: Optional[datetime] = None
    certificates: List[CertificateInfo] = field(default_factory=list)


# =============================================================================
# KNOWN SSL INSPECTION ISSUERS
# =============================================================================

SSL_INSPECTION_ISSUERS = [
    # Palo Alto Networks
    "palo alto", "pan-os", "paloalto",
    # Zscaler
    "zscaler", "zscaler intermediate root",
    # Fortinet
    "fortinet", "fortigate",
    # Broadcom / Blue Coat / Symantec
    "blue coat", "bluecoat", "symantec web security",
    # Check Point
    "check point", "checkpoint",
    # Cisco
    "cisco umbrella", "cisco web security", "ironport",
    # Sophos
    "sophos",
    # Barracuda
    "barracuda",
    # Untangle
    "untangle",
    # F5
    "f5 networks",
    # Generic inspection indicators
    "ssl inspection", "ssl intercept", "ssl proxy",
    "web filter", "content inspection", "decryption",
    "firewall ca", "proxy ca", "security appliance",
]


# =============================================================================
# CERTIFICATE CHECKER
# =============================================================================

class CertificateChecker:
    """Core certificate checking engine"""

    def __init__(self, config: Config = None):
        self.config = config or Config()

    def check_host(self, host: str, port: int = 443) -> CertificateInfo:
        """
        Check SSL/TLS certificate for a host

        Args:
            host: Hostname or IP address
            port: Port number (default: 443)

        Returns:
            CertificateInfo with all certificate details
        """
        cert_info = CertificateInfo(host=host, port=port)

        try:
            # Create SSL context
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE  # We'll verify manually

            # Connect and get certificate
            with socket.create_connection(
                (host, port), timeout=self.config.timeout
            ) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    # Get protocol and cipher info
                    cert_info.protocol_version = ssock.version() or ""
                    cipher = ssock.cipher()
                    if cipher:
                        cert_info.cipher_name = cipher[0]
                        cert_info.cipher_bits = cipher[2] if len(cipher) > 2 else 0

                    # Get certificate in DER format
                    der_cert = ssock.getpeercert(binary_form=True)
                    pem_cert_dict = ssock.getpeercert()

                    if der_cert and CRYPTOGRAPHY_AVAILABLE:
                        self._parse_certificate(cert_info, der_cert)
                    elif pem_cert_dict:
                        self._parse_cert_dict(cert_info, pem_cert_dict)

                    # Get certificate chain
                    self._check_chain(cert_info, host, port)

            # Check for SSL inspection
            self._check_ssl_inspection(cert_info)

            # Run compliance checks
            self._check_compliance(cert_info)

            # Determine overall status
            if cert_info.not_after:
                now = datetime.utcnow()
                delta = cert_info.not_after - now
                cert_info.days_remaining = max(0, delta.days)

                if cert_info.days_remaining <= 0:
                    cert_info.status = "expired"
                elif cert_info.days_remaining <= self.config.critical_days:
                    cert_info.status = "critical"
                elif cert_info.days_remaining <= self.config.warning_days:
                    cert_info.status = "expiring"
                else:
                    cert_info.status = "valid"
            else:
                cert_info.status = "valid"

        except ssl.SSLCertVerificationError as e:
            cert_info.status = "error"
            cert_info.error_message = f"SSL verification failed: {e}"
            logger.warning(f"SSL verification error for {host}:{port}: {e}")

        except socket.timeout:
            cert_info.status = "error"
            cert_info.error_message = "Connection timed out"
            logger.warning(f"Timeout connecting to {host}:{port}")

        except ConnectionRefusedError:
            cert_info.status = "error"
            cert_info.error_message = "Connection refused"
            logger.warning(f"Connection refused: {host}:{port}")

        except socket.gaierror as e:
            cert_info.status = "error"
            cert_info.error_message = f"DNS resolution failed: {e}"
            logger.warning(f"DNS error for {host}: {e}")

        except Exception as e:
            cert_info.status = "error"
            cert_info.error_message = str(e)
            logger.error(f"Error checking {host}:{port}: {e}")

        cert_info.last_checked = datetime.now()
        return cert_info

    def _parse_certificate(self, cert_info: CertificateInfo, der_cert: bytes):
        """Parse certificate using cryptography library"""
        cert = x509.load_der_x509_certificate(der_cert)

        # Subject
        try:
            cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
            cert_info.subject = cn[0].value if cn else str(cert.subject)
        except:
            cert_info.subject = str(cert.subject)

        # Issuer
        try:
            issuer_cn = cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)
            cert_info.issuer = issuer_cn[0].value if issuer_cn else str(cert.issuer)
            issuer_org = cert.issuer.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)
            cert_info.issuer_org = issuer_org[0].value if issuer_org else ""
        except:
            cert_info.issuer = str(cert.issuer)

        # Validity
        cert_info.not_before = cert.not_valid_before_utc if hasattr(cert, 'not_valid_before_utc') else cert.not_valid_before
        cert_info.not_after = cert.not_valid_after_utc if hasattr(cert, 'not_valid_after_utc') else cert.not_valid_after

        # Serial number
        cert_info.serial_number = format(cert.serial_number, 'X')

        # Key info
        public_key = cert.public_key()
        if isinstance(public_key, rsa.RSAPublicKey):
            cert_info.key_type = "RSA"
            cert_info.key_size = public_key.key_size
        elif isinstance(public_key, ec.EllipticCurvePublicKey):
            cert_info.key_type = "EC"
            cert_info.key_size = public_key.curve.key_size
        else:
            cert_info.key_type = type(public_key).__name__

        # Signature algorithm
        cert_info.signature_algorithm = cert.signature_algorithm_oid._name if hasattr(cert.signature_algorithm_oid, '_name') else str(cert.signature_algorithm_oid)

        # Subject Alternative Names
        try:
            san_ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
            cert_info.san = san_ext.value.get_values_for_type(x509.DNSName)
        except:
            cert_info.san = []

        # Check if self-signed
        cert_info.is_self_signed = (cert.subject == cert.issuer)

        # Check if wildcard
        cert_info.is_wildcard = cert_info.subject.startswith("*.")

        # Fingerprint
        cert_info.fingerprint_sha256 = cert.fingerprint(hashes.SHA256()).hex()

    def _parse_cert_dict(self, cert_info: CertificateInfo, cert_dict: Dict):
        """Parse certificate from Python ssl getpeercert() dict"""
        # Subject
        subject = cert_dict.get('subject', ())
        for rdn in subject:
            for attr_type, attr_value in rdn:
                if attr_type == 'commonName':
                    cert_info.subject = attr_value

        # Issuer
        issuer = cert_dict.get('issuer', ())
        for rdn in issuer:
            for attr_type, attr_value in rdn:
                if attr_type == 'commonName':
                    cert_info.issuer = attr_value
                elif attr_type == 'organizationName':
                    cert_info.issuer_org = attr_value

        # Validity dates
        not_before = cert_dict.get('notBefore')
        not_after = cert_dict.get('notAfter')

        if not_before:
            try:
                cert_info.not_before = datetime.strptime(not_before, '%b %d %H:%M:%S %Y %Z')
            except:
                pass

        if not_after:
            try:
                cert_info.not_after = datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
            except:
                pass

        # Serial number
        cert_info.serial_number = cert_dict.get('serialNumber', '')

        # SANs
        san_list = cert_dict.get('subjectAltName', ())
        cert_info.san = [value for type_, value in san_list if type_ == 'DNS']

        # Self-signed check
        cert_info.is_self_signed = (cert_info.subject == cert_info.issuer)

        # Wildcard check
        cert_info.is_wildcard = cert_info.subject.startswith("*.")

    def _check_chain(self, cert_info: CertificateInfo, host: str, port: int):
        """Validate certificate chain"""
        try:
            context = ssl.create_default_context()
            with socket.create_connection((host, port), timeout=self.config.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    cert_info.chain_valid = True
                    cert_info.chain_length = 1  # At minimum the leaf cert

                    # Try to get chain via OpenSSL if available
                    if OPENSSL_AVAILABLE:
                        try:
                            ossl_ctx = OpenSSL.SSL.Context(OpenSSL.SSL.TLS_CLIENT_METHOD)
                            ossl_conn = OpenSSL.SSL.Connection(ossl_ctx, socket.create_connection((host, port), timeout=self.config.timeout))
                            ossl_conn.set_tlsext_host_name(host.encode())
                            ossl_conn.set_connect_state()
                            ossl_conn.do_handshake()
                            chain = ossl_conn.get_peer_cert_chain()
                            if chain:
                                cert_info.chain_length = len(chain)
                                for i, c in enumerate(chain):
                                    cert_info.chain_details.append({
                                        "index": i,
                                        "subject": str(c.get_subject().CN or c.get_subject()),
                                        "issuer": str(c.get_issuer().CN or c.get_issuer()),
                                        "type": "Leaf" if i == 0 else ("Root" if i == len(chain) - 1 else "Intermediate")
                                    })
                            ossl_conn.close()
                        except:
                            pass

        except ssl.SSLCertVerificationError:
            cert_info.chain_valid = False
        except:
            pass

    def _check_ssl_inspection(self, cert_info: CertificateInfo):
        """Detect if certificate has been re-signed by SSL inspection device"""
        check_strings = [
            cert_info.issuer.lower(),
            cert_info.issuer_org.lower(),
        ]

        for check_str in check_strings:
            if not check_str:
                continue

            for pattern in SSL_INSPECTION_ISSUERS:
                if pattern in check_str:
                    cert_info.is_intercepted = True
                    # Determine which product
                    if "palo alto" in check_str or "pan-os" in check_str or "paloalto" in check_str:
                        cert_info.intercepted_by = "Palo Alto Networks"
                    elif "zscaler" in check_str:
                        cert_info.intercepted_by = "Zscaler"
                    elif "fortinet" in check_str or "fortigate" in check_str:
                        cert_info.intercepted_by = "Fortinet"
                    elif "blue coat" in check_str or "bluecoat" in check_str:
                        cert_info.intercepted_by = "Blue Coat / Symantec"
                    elif "check point" in check_str or "checkpoint" in check_str:
                        cert_info.intercepted_by = "Check Point"
                    elif "cisco" in check_str:
                        cert_info.intercepted_by = "Cisco"
                    elif "sophos" in check_str:
                        cert_info.intercepted_by = "Sophos"
                    elif "barracuda" in check_str:
                        cert_info.intercepted_by = "Barracuda"
                    else:
                        cert_info.intercepted_by = f"Unknown ({check_str})"
                    return

    def _check_compliance(self, cert_info: CertificateInfo):
        """Check certificate compliance against standards"""
        issues = []

        # Protocol version check
        protocol_order = {"SSLv2": 0, "SSLv3": 1, "TLSv1": 2, "TLSv1.1": 3, "TLSv1.2": 4, "TLSv1.3": 5}
        min_version = protocol_order.get(self.config.min_protocol, 4)
        current_version = protocol_order.get(cert_info.protocol_version, -1)

        if current_version < min_version:
            issues.append(f"Protocol {cert_info.protocol_version} below minimum {self.config.min_protocol}")
            cert_info.compliance_pci = False
            cert_info.compliance_nist = False

        # Key size check
        if cert_info.key_size > 0 and cert_info.key_size < self.config.min_key_size:
            if cert_info.key_type == "RSA":
                issues.append(f"RSA key size {cert_info.key_size}-bit below minimum {self.config.min_key_size}-bit")
                cert_info.compliance_pci = False

        # Cipher check
        cipher_lower = cert_info.cipher_name.lower()
        for prohibited in self.config.prohibited_ciphers:
            if prohibited.lower() in cipher_lower:
                issues.append(f"Prohibited cipher component: {prohibited}")
                cert_info.compliance_pci = False
                cert_info.compliance_nist = False

        # Self-signed check (not compliant for external services)
        if cert_info.is_self_signed:
            issues.append("Self-signed certificate - not trusted by clients")

        # Expiration check
        if cert_info.status == "expired":
            issues.append("Certificate has expired")
            cert_info.compliance_pci = False
            cert_info.compliance_nist = False

        # Signature algorithm
        weak_algorithms = ["md5", "sha1"]
        if cert_info.signature_algorithm:
            sig_lower = cert_info.signature_algorithm.lower()
            for weak in weak_algorithms:
                if weak in sig_lower:
                    issues.append(f"Weak signature algorithm: {cert_info.signature_algorithm}")
                    cert_info.compliance_pci = False

        cert_info.compliance_issues = issues


# =============================================================================
# SSL MONITOR (ORCHESTRATOR)
# =============================================================================

class SSLMonitor:
    """Main SSL/TLS monitoring orchestrator"""

    def __init__(self, config: Config = None):
        self.config = config or Config()
        self.checker = CertificateChecker(self.config)
        self.results: List[CertificateInfo] = []

    def check_host(self, host: str, port: int = 443) -> CertificateInfo:
        """Check a single host"""
        # Parse host:port format
        if ':' in host and not host.startswith('['):
            parts = host.rsplit(':', 1)
            host = parts[0]
            try:
                port = int(parts[1])
            except ValueError:
                pass

        result = self.checker.check_host(host, port)
        self.results.append(result)
        return result

    def scan_hosts(self, hosts: List[str], port: int = 443) -> ScanSummary:
        """
        Scan multiple hosts in parallel

        Args:
            hosts: List of hostnames (optionally with :port)
            port: Default port

        Returns:
            ScanSummary with all results
        """
        summary = ScanSummary(scan_start=datetime.now())
        logger.info(f"🔍 Scanning {len(hosts)} hosts...")

        with ThreadPoolExecutor(max_workers=self.config.threads) as executor:
            futures = {}
            for host in hosts:
                h, p = host, port
                if ':' in host and not host.startswith('['):
                    parts = host.rsplit(':', 1)
                    h = parts[0]
                    try:
                        p = int(parts[1])
                    except ValueError:
                        p = port

                futures[executor.submit(self.checker.check_host, h, p)] = host

            for future in as_completed(futures):
                host = futures[future]
                try:
                    result = future.result()
                    summary.certificates.append(result)
                    self.results.append(result)

                    severity = result.severity
                    if severity == "healthy":
                        summary.healthy += 1
                    elif severity == "notice":
                        summary.notice += 1
                    elif severity == "warning":
                        summary.warning += 1
                    elif severity == "critical":
                        summary.critical += 1
                    elif severity == "expired":
                        summary.expired += 1

                    if result.status == "error":
                        summary.errors += 1
                    if result.is_intercepted:
                        summary.intercepted += 1
                    if not result.compliance_pci or not result.compliance_nist:
                        summary.non_compliant += 1

                except Exception as e:
                    summary.errors += 1
                    logger.error(f"Error scanning {host}: {e}")

        summary.total = len(summary.certificates)
        summary.scan_end = datetime.now()

        return summary

    def scan_from_file(self, filepath: str) -> ScanSummary:
        """Scan hosts from a text file (one per line)"""
        hosts = []
        with open(filepath) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    hosts.append(line)

        return self.scan_hosts(hosts)

    def discover_network(self, network: str) -> List[str]:
        """Discover SSL services in a network"""
        discovered = []
        try:
            net = ipaddress.ip_network(network, strict=False)
            hosts = list(net.hosts())

            logger.info(f"🔍 Scanning {len(hosts)} IPs for SSL services...")

            with ThreadPoolExecutor(max_workers=min(self.config.threads * 2, 200)) as executor:
                futures = {}
                for ip in hosts:
                    for port in self.config.ports:
                        futures[executor.submit(self._check_ssl_port, str(ip), port)] = (str(ip), port)

                for future in as_completed(futures):
                    ip, port = futures[future]
                    try:
                        if future.result():
                            discovered.append(f"{ip}:{port}")
                            logger.info(f"  ✅ Found SSL service: {ip}:{port}")
                    except:
                        pass

        except Exception as e:
            logger.error(f"Discovery error: {e}")

        return discovered

    def _check_ssl_port(self, host: str, port: int) -> bool:
        """Check if a port has SSL/TLS service"""
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            with socket.create_connection((host, port), timeout=3) as sock:
                with context.wrap_socket(sock) as ssock:
                    return True
        except:
            return False

    def get_expiring(self, days: int = 30) -> List[CertificateInfo]:
        """Get certificates expiring within N days"""
        return [
            c for c in self.results
            if c.status != "error" and 0 < c.days_remaining <= days
        ]

    def get_expired(self) -> List[CertificateInfo]:
        """Get expired certificates"""
        return [c for c in self.results if c.status == "expired"]

    def get_intercepted(self) -> List[CertificateInfo]:
        """Get SSL-inspected certificates"""
        return [c for c in self.results if c.is_intercepted]

    def get_non_compliant(self) -> List[CertificateInfo]:
        """Get non-compliant certificates"""
        return [c for c in self.results if not c.compliance_pci or not c.compliance_nist]

    # =========================================================================
    # EXPORTERS
    # =========================================================================

    def export_json(self, filename: str = "certificates.json") -> str:
        """Export results to JSON"""
        data = {
            "scan_date": datetime.now().isoformat(),
            "total": len(self.results),
            "certificates": [c.to_dict() for c in self.results]
        }
        filepath = Path(filename)
        filepath.parent.mkdir(parents=True, exist_ok=True)
        with open(filepath, 'w') as f:
            json.dump(data, f, indent=2, default=str)
        logger.info(f"📄 Exported JSON: {filepath}")
        return str(filepath)

    def export_csv(self, filename: str = "certificates.csv") -> str:
        """Export results to CSV"""
        filepath = Path(filename)
        filepath.parent.mkdir(parents=True, exist_ok=True)

        rows = [{
            'Host': c.host,
            'Port': c.port,
            'Status': c.status,
            'Subject': c.subject,
            'Issuer': c.issuer,
            'Not Before': c.not_before.strftime('%Y-%m-%d') if c.not_before else '',
            'Not After': c.not_after.strftime('%Y-%m-%d') if c.not_after else '',
            'Days Remaining': c.days_remaining,
            'Key Type': c.key_type,
            'Key Size': c.key_size,
            'Protocol': c.protocol_version,
            'Cipher': c.cipher_name,
            'Chain Valid': c.chain_valid,
            'SSL Inspected': c.is_intercepted,
            'Inspected By': c.intercepted_by,
            'PCI Compliant': c.compliance_pci,
            'Issues': '; '.join(c.compliance_issues),
        } for c in self.results]

        if PANDAS_AVAILABLE:
            pd.DataFrame(rows).to_csv(filepath, index=False)
        else:
            import csv
            if rows:
                with open(filepath, 'w', newline='') as f:
                    writer = csv.DictWriter(f, fieldnames=rows[0].keys())
                    writer.writeheader()
                    writer.writerows(rows)

        logger.info(f"📄 Exported CSV: {filepath}")
        return str(filepath)

    def export_html(self, filename: str = "certificate_report.html") -> str:
        """Export results to HTML report"""
        filepath = Path(filename)
        filepath.parent.mkdir(parents=True, exist_ok=True)

        total = len(self.results)
        healthy = sum(1 for c in self.results if c.severity == "healthy")
        warning = sum(1 for c in self.results if c.severity in ["warning", "notice"])
        critical = sum(1 for c in self.results if c.severity == "critical")
        expired = sum(1 for c in self.results if c.severity == "expired")
        inspected = sum(1 for c in self.results if c.is_intercepted)

        rows_html = ""
        for c in sorted(self.results, key=lambda x: x.days_remaining):
            status_color = {
                "healthy": "bg-green-100 text-green-800",
                "notice": "bg-yellow-100 text-yellow-800",
                "warning": "bg-orange-100 text-orange-800",
                "critical": "bg-red-100 text-red-800",
                "expired": "bg-red-200 text-red-900",
            }.get(c.severity, "bg-gray-100 text-gray-800")

            rows_html += f"""
            <tr class="hover:bg-gray-50">
                <td class="px-4 py-3">{c.host}:{c.port}</td>
                <td class="px-4 py-3"><span class="px-2 py-1 rounded-full text-xs font-medium {status_color}">{c.severity.upper()}</span></td>
                <td class="px-4 py-3">{c.subject or '-'}</td>
                <td class="px-4 py-3">{c.issuer or '-'}</td>
                <td class="px-4 py-3">{c.not_after.strftime('%Y-%m-%d') if c.not_after else '-'}</td>
                <td class="px-4 py-3 font-bold">{c.days_remaining}</td>
                <td class="px-4 py-3">{c.protocol_version or '-'}</td>
                <td class="px-4 py-3">{'⚠️ ' + c.intercepted_by if c.is_intercepted else '✅ No'}</td>
                <td class="px-4 py-3">{'✅' if c.compliance_pci else '❌'}</td>
            </tr>
            """

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SSL/TLS Certificate Report</title>
    <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-gray-100 p-8">
    <div class="max-w-7xl mx-auto">
        <div class="bg-white rounded-lg shadow-lg p-6 mb-8">
            <h1 class="text-3xl font-bold text-gray-800 mb-4">🔒 SSL/TLS Certificate Report</h1>
            <p class="text-gray-500 mb-6">Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            <div class="grid grid-cols-2 md:grid-cols-6 gap-4">
                <div class="bg-blue-50 rounded-lg p-4 text-center">
                    <div class="text-3xl font-bold text-blue-600">{total}</div>
                    <div class="text-sm text-gray-600">Total</div>
                </div>
                <div class="bg-green-50 rounded-lg p-4 text-center">
                    <div class="text-3xl font-bold text-green-600">{healthy}</div>
                    <div class="text-sm text-gray-600">Healthy</div>
                </div>
                <div class="bg-yellow-50 rounded-lg p-4 text-center">
                    <div class="text-3xl font-bold text-yellow-600">{warning}</div>
                    <div class="text-sm text-gray-600">Warning</div>
                </div>
                <div class="bg-red-50 rounded-lg p-4 text-center">
                    <div class="text-3xl font-bold text-red-600">{critical}</div>
                    <div class="text-sm text-gray-600">Critical</div>
                </div>
                <div class="bg-red-100 rounded-lg p-4 text-center">
                    <div class="text-3xl font-bold text-red-700">{expired}</div>
                    <div class="text-sm text-gray-600">Expired</div>
                </div>
                <div class="bg-purple-50 rounded-lg p-4 text-center">
                    <div class="text-3xl font-bold text-purple-600">{inspected}</div>
                    <div class="text-sm text-gray-600">Inspected</div>
                </div>
            </div>
        </div>
        <div class="bg-white rounded-lg shadow-lg overflow-hidden">
            <div class="overflow-x-auto">
                <table class="w-full">
                    <thead class="bg-gray-800 text-white">
                        <tr>
                            <th class="px-4 py-3 text-left">Host</th>
                            <th class="px-4 py-3 text-left">Status</th>
                            <th class="px-4 py-3 text-left">Subject</th>
                            <th class="px-4 py-3 text-left">Issuer</th>
                            <th class="px-4 py-3 text-left">Expires</th>
                            <th class="px-4 py-3 text-left">Days</th>
                            <th class="px-4 py-3 text-left">Protocol</th>
                            <th class="px-4 py-3 text-left">SSL Inspect</th>
                            <th class="px-4 py-3 text-left">PCI</th>
                        </tr>
                    </thead>
                    <tbody class="divide-y divide-gray-200">{rows_html}
                    </tbody>
                </table>
            </div>
        </div>
        <div class="text-center text-gray-500 mt-8 text-sm">
            Generated by SSL/TLS Certificate Monitor | Author: Tamer Khalifa (CCIE #68867)
        </div>
    </div>
</body>
</html>"""

        with open(filepath, 'w') as f:
            f.write(html)

        logger.info(f"🌐 Exported HTML: {filepath}")
        return str(filepath)


# =============================================================================
# PRETTY PRINTER
# =============================================================================

class CertificatePrinter:
    """Pretty print certificate information"""

    @staticmethod
    def print_cert(cert: CertificateInfo):
        """Print detailed certificate info"""
        status_icon = {
            "valid": "✅",
            "expiring": "⚠️",
            "critical": "🔴",
            "expired": "❌",
            "error": "💥"
        }.get(cert.status, "❓")

        print(f"\n{'='*62}")
        print(f"  SSL/TLS CERTIFICATE REPORT")
        print(f"{'='*62}")
        print(f"  Host:           {cert.host}:{cert.port}")
        print(f"  Status:         {status_icon} {cert.status.upper()}")
        print(f"{'='*62}")
        print(f"  CERTIFICATE DETAILS")
        print(f"  ├─ Subject:     {cert.subject}")
        print(f"  ├─ Issuer:      {cert.issuer}")
        print(f"  ├─ Serial:      {cert.serial_number[:20]}...")
        if cert.not_before:
            print(f"  ├─ Valid From:  {cert.not_before.strftime('%Y-%m-%d')}")
        if cert.not_after:
            print(f"  ├─ Valid Until: {cert.not_after.strftime('%Y-%m-%d')}")
        print(f"  ├─ Days Left:   {cert.days_remaining} days {status_icon}")
        print(f"  ├─ Key Type:    {cert.key_type} {cert.key_size}-bit")
        if cert.san:
            print(f"  └─ SANs:        {', '.join(cert.san[:5])}")
        print(f"{'='*62}")
        print(f"  TLS CONFIGURATION")
        print(f"  ├─ Protocol:    {cert.protocol_version}")
        print(f"  ├─ Cipher:      {cert.cipher_name}")
        print(f"  └─ Chain:       {cert.chain_length} certificates ({'✅ Valid' if cert.chain_valid else '❌ Invalid'})")

        if cert.chain_details:
            print(f"{'='*62}")
            print(f"  CERTIFICATE CHAIN")
            for c in cert.chain_details:
                print(f"  ├─ [{c['index']}] {c['subject']} ({c['type']})")

        print(f"{'='*62}")
        if cert.is_intercepted:
            print(f"  ⚠️  SSL INSPECTION: DETECTED - {cert.intercepted_by}")
        else:
            print(f"  SSL INSPECTION:  ✅ NOT DETECTED")

        pci = "✅ COMPLIANT" if cert.compliance_pci else "❌ NON-COMPLIANT"
        print(f"  PCI-DSS:         {pci}")

        if cert.compliance_issues:
            print(f"\n  ⚠️  COMPLIANCE ISSUES:")
            for issue in cert.compliance_issues:
                print(f"     • {issue}")

        if cert.error_message:
            print(f"\n  ❌ ERROR: {cert.error_message}")

        print(f"{'='*62}\n")

    @staticmethod
    def print_summary(summary: ScanSummary):
        """Print scan summary"""
        duration = (summary.scan_end - summary.scan_start).total_seconds() if summary.scan_end else 0

        print(f"\n{'='*62}")
        print(f"  CERTIFICATE SCAN SUMMARY")
        print(f"{'='*62}")
        print(f"  Total Scanned:    {summary.total}")
        print(f"  Duration:         {duration:.1f}s")
        print(f"{'='*62}")
        print(f"  🟢 Healthy:        {summary.healthy}")
        print(f"  🟡 Notice (60d):   {summary.notice}")
        print(f"  🟠 Warning (30d):  {summary.warning}")
        print(f"  🔴 Critical (7d):  {summary.critical}")
        print(f"  ❌ Expired:        {summary.expired}")
        print(f"  💥 Errors:         {summary.errors}")
        print(f"  🔍 SSL Inspected:  {summary.intercepted}")
        print(f"  ⚠️  Non-Compliant:  {summary.non_compliant}")
        print(f"{'='*62}\n")

        # Print problem certificates
        problems = [c for c in summary.certificates if c.severity in ["critical", "expired", "warning"]]
        if problems:
            print(f"  ⚠️  ATTENTION REQUIRED ({len(problems)} certificates):")
            print(f"  {'-'*58}")
            for c in sorted(problems, key=lambda x: x.days_remaining):
                icon = "❌" if c.severity == "expired" else "🔴" if c.severity == "critical" else "🟠"
                days = f"Expired {abs(c.days_remaining)}d ago" if c.days_remaining <= 0 else f"{c.days_remaining}d left"
                print(f"  {icon} {c.host}:{c.port} - {c.subject} ({days})")
            print()


# =============================================================================
# FLASK DASHBOARD
# =============================================================================

def create_dashboard(monitor: SSLMonitor, config: Config) -> Optional[Any]:
    """Create Flask dashboard application"""
    if not FLASK_AVAILABLE:
        logger.error("Flask not installed. Install with: pip install flask")
        return None

    app = Flask(__name__)
    app.secret_key = config.flask_secret

    DASHBOARD_HTML = '''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SSL/TLS Certificate Monitor</title>
    <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-gray-900 text-white min-h-screen">
    <nav class="bg-gray-800 border-b border-gray-700 px-6 py-4">
        <h1 class="text-2xl font-bold">🔒 SSL/TLS Certificate Monitor</h1>
    </nav>
    <main class="container mx-auto px-6 py-8" id="app">
        <div class="grid grid-cols-2 md:grid-cols-5 gap-4 mb-8">
            <div class="bg-gray-800 rounded-lg p-4 text-center border border-gray-700">
                <div class="text-3xl font-bold text-blue-400" id="total">--</div>
                <div class="text-sm text-gray-400">Total</div>
            </div>
            <div class="bg-gray-800 rounded-lg p-4 text-center border border-gray-700">
                <div class="text-3xl font-bold text-green-400" id="healthy">--</div>
                <div class="text-sm text-gray-400">Healthy</div>
            </div>
            <div class="bg-gray-800 rounded-lg p-4 text-center border border-gray-700">
                <div class="text-3xl font-bold text-yellow-400" id="warning">--</div>
                <div class="text-sm text-gray-400">Warning</div>
            </div>
            <div class="bg-gray-800 rounded-lg p-4 text-center border border-gray-700">
                <div class="text-3xl font-bold text-red-400" id="critical">--</div>
                <div class="text-sm text-gray-400">Critical</div>
            </div>
            <div class="bg-gray-800 rounded-lg p-4 text-center border border-gray-700">
                <div class="text-3xl font-bold text-purple-400" id="inspected">--</div>
                <div class="text-sm text-gray-400">Inspected</div>
            </div>
        </div>
        <div class="bg-gray-800 rounded-lg border border-gray-700 overflow-hidden">
            <div class="px-6 py-4 border-b border-gray-700 flex justify-between items-center">
                <h2 class="text-lg font-semibold">Certificates</h2>
                <input type="text" id="search" placeholder="Search..." class="bg-gray-700 border border-gray-600 rounded px-3 py-1 text-sm">
            </div>
            <table class="w-full"><thead class="bg-gray-750"><tr class="text-left text-gray-400 text-sm">
                <th class="px-4 py-3">Host</th><th class="px-4 py-3">Status</th><th class="px-4 py-3">Subject</th>
                <th class="px-4 py-3">Issuer</th><th class="px-4 py-3">Expires</th><th class="px-4 py-3">Days</th>
                <th class="px-4 py-3">Inspected</th><th class="px-4 py-3">PCI</th>
            </tr></thead><tbody id="table"><tr><td colspan="8" class="px-4 py-8 text-center text-gray-500">Loading...</td></tr></tbody></table>
        </div>
    </main>
    <script>
    fetch('/api/certificates').then(r=>r.json()).then(data=>{
        document.getElementById('total').textContent=data.certificates.length;
        let h=0,w=0,c=0,i=0;
        data.certificates.forEach(cert=>{
            if(cert.severity==='healthy')h++;
            if(cert.severity==='warning'||cert.severity==='notice')w++;
            if(cert.severity==='critical'||cert.severity==='expired')c++;
            if(cert.is_intercepted)i++;
        });
        document.getElementById('healthy').textContent=h;
        document.getElementById('warning').textContent=w;
        document.getElementById('critical').textContent=c;
        document.getElementById('inspected').textContent=i;
        const tbody=document.getElementById('table');
        tbody.innerHTML=data.certificates.sort((a,b)=>a.days_remaining-b.days_remaining).map(c=>{
            const sc={'healthy':'bg-green-600','notice':'bg-yellow-600','warning':'bg-orange-600','critical':'bg-red-600','expired':'bg-red-800'}[c.severity]||'bg-gray-600';
            return `<tr class="border-b border-gray-700 hover:bg-gray-750"><td class="px-4 py-3">${c.host}:${c.port}</td><td class="px-4 py-3"><span class="px-2 py-1 rounded-full text-xs ${sc}">${c.severity}</span></td><td class="px-4 py-3">${c.subject||'-'}</td><td class="px-4 py-3">${c.issuer||'-'}</td><td class="px-4 py-3">${c.not_after?c.not_after.slice(0,10):'-'}</td><td class="px-4 py-3 font-bold">${c.days_remaining}</td><td class="px-4 py-3">${c.is_intercepted?'⚠️ '+c.intercepted_by:'✅'}</td><td class="px-4 py-3">${c.compliance_pci?'✅':'❌'}</td></tr>`;
        }).join('');
    });
    </script>
</body>
</html>'''

    @app.route('/')
    def index():
        return DASHBOARD_HTML

    @app.route('/api/certificates')
    def api_certificates():
        return jsonify({"certificates": [c.to_dict() for c in monitor.results]})

    @app.route('/api/certificates/<host>')
    def api_certificate(host):
        for c in monitor.results:
            if c.host == host:
                return jsonify(c.to_dict())
        return jsonify({"error": "Not found"}), 404

    @app.route('/api/check', methods=['POST'])
    def api_check():
        data = request.get_json()
        host = data.get('host', '')
        port = data.get('port', 443)
        if not host:
            return jsonify({"error": "Host required"}), 400
        result = monitor.check_host(host, port)
        return jsonify(result.to_dict())

    @app.route('/api/expiring')
    def api_expiring():
        days = request.args.get('days', 30, type=int)
        expiring = [c.to_dict() for c in monitor.results if 0 < c.days_remaining <= days]
        return jsonify({"days": days, "certificates": expiring})

    @app.route('/api/inspected')
    def api_inspected():
        inspected = [c.to_dict() for c in monitor.results if c.is_intercepted]
        return jsonify({"certificates": inspected})

    @app.route('/api/health')
    def api_health():
        total = len(monitor.results)
        return jsonify({
            "total": total,
            "healthy": sum(1 for c in monitor.results if c.severity == "healthy"),
            "warning": sum(1 for c in monitor.results if c.severity in ["warning", "notice"]),
            "critical": sum(1 for c in monitor.results if c.severity in ["critical", "expired"]),
            "intercepted": sum(1 for c in monitor.results if c.is_intercepted),
        })

    return app


# =============================================================================
# CLI INTERFACE
# =============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="SSL/TLS Certificate Monitor - Enterprise certificate monitoring",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  Check single host:
    python ssl_monitor.py check --host google.com

  Scan from file:
    python ssl_monitor.py scan --file hosts.txt

  Discover SSL in subnet:
    python ssl_monitor.py discover --network 192.168.1.0/24

  Check expiring certs:
    python ssl_monitor.py expiring --days 30 --file hosts.txt

  Run compliance check:
    python ssl_monitor.py compliance --host company.com

  Detect SSL inspection:
    python ssl_monitor.py inspect --host app.company.com

  Generate report:
    python ssl_monitor.py report --file hosts.txt --output report.html

  Start dashboard:
    python ssl_monitor.py dashboard --port 5000

Author: Tamer Khalifa (CCIE #68867)
        """
    )

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # Check command
    check_parser = subparsers.add_parser("check", help="Check single host certificate")
    check_parser.add_argument("--host", "-H", required=True, help="Hostname or IP")
    check_parser.add_argument("--port", "-p", type=int, default=443, help="Port (default: 443)")

    # Scan command
    scan_parser = subparsers.add_parser("scan", help="Scan multiple hosts")
    scan_parser.add_argument("--file", "-f", required=True, help="Hosts file (one per line)")
    scan_parser.add_argument("--output", "-o", help="Output file")
    scan_parser.add_argument("--format", choices=['json', 'csv', 'html', 'all'], default='all')

    # Discover command
    discover_parser = subparsers.add_parser("discover", help="Discover SSL services in subnet")
    discover_parser.add_argument("--network", "-n", required=True, help="Network CIDR")

    # Expiring command
    expiring_parser = subparsers.add_parser("expiring", help="Show expiring certificates")
    expiring_parser.add_argument("--days", "-d", type=int, default=30, help="Days threshold")
    expiring_parser.add_argument("--file", "-f", required=True, help="Hosts file")

    # Compliance command
    compliance_parser = subparsers.add_parser("compliance", help="Run compliance check")
    compliance_parser.add_argument("--host", "-H", required=True, help="Hostname")
    compliance_parser.add_argument("--port", "-p", type=int, default=443, help="Port")

    # Inspect command
    inspect_parser = subparsers.add_parser("inspect", help="Detect SSL inspection")
    inspect_parser.add_argument("--host", "-H", required=True, help="Hostname")
    inspect_parser.add_argument("--port", "-p", type=int, default=443, help="Port")

    # Report command
    report_parser = subparsers.add_parser("report", help="Generate full report")
    report_parser.add_argument("--file", "-f", required=True, help="Hosts file")
    report_parser.add_argument("--output", "-o", default="certificate_report.html", help="Output file")

    # Dashboard command
    dash_parser = subparsers.add_parser("dashboard", help="Start web dashboard")
    dash_parser.add_argument("--port", "-p", type=int, default=5000, help="Dashboard port")
    dash_parser.add_argument("--file", "-f", help="Pre-load hosts file")
    dash_parser.add_argument("--config", "-c", default="config.yaml", help="Config file")

    # Common args
    parser.add_argument("--config", "-c", default="config.yaml", help="Configuration file")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    # Load configuration
    config = Config.from_file(getattr(args, 'config', 'config.yaml'))
    monitor = SSLMonitor(config)
    printer = CertificatePrinter()

    # Execute commands
    if args.command == "check":
        cert = monitor.check_host(args.host, args.port)
        printer.print_cert(cert)

    elif args.command == "scan":
        summary = monitor.scan_from_file(args.file)
        printer.print_summary(summary)

        fmt = args.format
        if fmt == 'all':
            monitor.export_json()
            monitor.export_csv()
            monitor.export_html()
        elif fmt == 'json':
            monitor.export_json(args.output or "certificates.json")
        elif fmt == 'csv':
            monitor.export_csv(args.output or "certificates.csv")
        elif fmt == 'html':
            monitor.export_html(args.output or "certificate_report.html")

    elif args.command == "discover":
        discovered = monitor.discover_network(args.network)
        print(f"\n✅ Found {len(discovered)} SSL services:")
        for svc in discovered:
            print(f"   • {svc}")

    elif args.command == "expiring":
        summary = monitor.scan_from_file(args.file)
        expiring = monitor.get_expiring(args.days)

        print(f"\n⚠️  Certificates expiring within {args.days} days: {len(expiring)}")
        print(f"{'='*62}")
        for c in sorted(expiring, key=lambda x: x.days_remaining):
            icon = "🔴" if c.days_remaining <= 7 else "🟠"
            print(f"  {icon} {c.host}:{c.port} - {c.subject} ({c.days_remaining} days)")

    elif args.command == "compliance":
        cert = monitor.check_host(args.host, args.port)
        printer.print_cert(cert)

        if cert.compliance_issues:
            print(f"\n❌ COMPLIANCE ISSUES FOUND:")
            for issue in cert.compliance_issues:
                print(f"   • {issue}")
        else:
            print(f"\n✅ Certificate is compliant with PCI-DSS and NIST standards")

    elif args.command == "inspect":
        cert = monitor.check_host(args.host, args.port)

        if cert.is_intercepted:
            print(f"\n{'='*62}")
            print(f"  ⚠️  SSL INSPECTION DETECTED")
            print(f"{'='*62}")
            print(f"  Host:            {cert.host}:{cert.port}")
            print(f"  Current Issuer:  {cert.issuer}")
            print(f"  Intercepted By:  {cert.intercepted_by}")
            print(f"{'='*62}")
            print(f"  💡 RECOMMENDATIONS:")
            print(f"  ├─ Verify decryption policy is intentional")
            print(f"  ├─ Check for certificate pinning issues")
            print(f"  ├─ Ensure no dual SSL inspection (FW + proxy)")
            print(f"  └─ Add to bypass list if causing issues")
            print(f"{'='*62}\n")
        else:
            print(f"\n✅ No SSL inspection detected for {cert.host}:{cert.port}")
            print(f"   Issuer: {cert.issuer}")

    elif args.command == "report":
        summary = monitor.scan_from_file(args.file)
        printer.print_summary(summary)
        output = monitor.export_html(args.output)
        print(f"📄 Report saved to: {output}")

    elif args.command == "dashboard":
        if args.file:
            print("📋 Pre-loading hosts...")
            monitor.scan_from_file(args.file)

        app = create_dashboard(monitor, config)
        if app:
            port = args.port or config.flask_port
            print(f"\n{'='*62}")
            print(f"  🔒 SSL/TLS Certificate Monitor Dashboard")
            print(f"{'='*62}")
            print(f"  URL:     http://0.0.0.0:{port}")
            print(f"  API:     http://0.0.0.0:{port}/api/certificates")
            print(f"  Certs:   {len(monitor.results)} loaded")
            print(f"{'='*62}\n")
            app.run(host=config.flask_host, port=port, debug=False)


if __name__ == "__main__":
    main()

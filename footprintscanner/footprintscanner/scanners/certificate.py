"""SSL/TLS certificate analysis."""

from __future__ import annotations

import ssl
import socket
from datetime import datetime

import requests

from footprintscanner.config import Config
from footprintscanner.models import Finding, Severity, Target, ScannerCategory
from .base import BaseScanner


class CertificateScanner(BaseScanner):
    """Analyze SSL/TLS certificates for security issues."""

    name = "Certificate Scanner"
    category = ScannerCategory.CERTIFICATE

    def scan(self, target: Target) -> list[Finding]:
        findings: list[Finding] = []

        if not target.domain:
            return findings

        domain = target.domain

        findings.extend(self._check_certificate_validity(domain))
        findings.extend(self._check_certificate_expiry(domain))
        findings.extend(self._check_certificate_transparency(domain))
        findings.extend(self._check_tls_config(domain))

        return findings

    def _get_certificate(self, domain: str) -> dict | None:
        """Retrieve certificate details for a domain."""
        try:
            cert = ssl.get_server_certificate((domain, 443))
            pem = f"-----BEGIN CERTIFICATE-----\n{cert}\n-----END CERTIFICATE-----"
            return {"pem": pem}
        except ssl.SSLError:
            return None
        except (socket.error, OSError):
            return None

    def _check_certificate_validity(self, domain: str) -> list[Finding]:
        """Check if the certificate is valid."""
        cert_data = self._get_certificate(domain)
        if not cert_data:
            return [
                Finding(
                    category=self.category,
                    title="No Valid TLS Certificate",
                    description=(
                        f"Domain {domain} does not have a valid TLS certificate "
                        "on port 443. This means connections are either unencrypted "
                        "or using an invalid/expired certificate."
                    ),
                    severity=Severity.HIGH,
                    details={"domain": domain, "certificate": "invalid_or_missing"},
                    remediation="Obtain and install a valid TLS certificate. Use Let's Encrypt for free certificates.",
                    scanner=self.name,
                )
            ]

        return [
            Finding(
                category=self.category,
                title="Valid TLS Certificate Present",
                description=f"Domain {domain} has a valid TLS certificate.",
                severity=Severity.INFO,
                details={"domain": domain, "certificate": "present"},
                scanner=self.name,
            )
        ]

    def _check_certificate_expiry(self, domain: str) -> list[Finding]:
        """Check certificate expiration dates."""
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=self.config.timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()

                    not_after = cert.get("notAfter", "")
                    not_before = cert.get("notBefore", "")

                    # Parse dates
                    expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                    issued = datetime.strptime(not_before, "%b %d %H:%M:%S %Y %Z")

                    days_until_expiry = (expiry - datetime.now()).days

                    if days_until_expiry < 0:
                        return [
                            Finding(
                                category=self.category,
                                title="Certificate Expired",
                                description=(
                                    f"TLS certificate for {domain} expired {abs(days_until_expiry)} "
                                    f"days ago (on {not_after}). Expired certificates cause browser "
                                    f"security warnings and may indicate abandoned infrastructure."
                                ),
                                severity=Severity.CRITICAL,
                                details={
                                    "domain": domain,
                                    "expiry_date": not_after,
                                    "days_until_expiry": days_until_expiry,
                                },
                                remediation="Renew the TLS certificate immediately.",
                                scanner=self.name,
                            )
                        ]

                    if days_until_expiry < 30:
                        return [
                            Finding(
                                category=self.category,
                                title="Certificate Expiring Soon",
                                description=(
                                    f"TLS certificate for {domain} expires in {days_until_expiry} "
                                    f"days ({not_after}). An expired certificate will cause "
                                    f"security warnings for all visitors."
                                ),
                                severity=Severity.HIGH,
                                details={
                                    "domain": domain,
                                    "expiry_date": not_after,
                                    "days_until_expiry": days_until_expiry,
                                },
                                remediation="Renew the certificate before expiry. Set up auto-renewal with certbot.",
                                scanner=self.name,
                            )
                        ]

                    if days_until_expiry < 90:
                        return [
                            Finding(
                                category=self.category,
                                title="Certificate Expires Within 90 Days",
                                description=(
                                    f"TLS certificate for {domain} expires in {days_until_expiry} "
                                    f"days. Plan renewal soon."
                                ),
                                severity=Severity.MEDIUM,
                                details={
                                    "domain": domain,
                                    "expiry_date": not_after,
                                    "days_until_expiry": days_until_expiry,
                                },
                                remediation="Schedule certificate renewal before expiry.",
                                scanner=self.name,
                            )
                        ]

                    return [
                        Finding(
                            category=self.category,
                            title="Certificate Valid for {days} More Days".format(days=days_until_expiry),
                            description=(
                                f"TLS certificate for {domain} is valid until {not_after}. "
                                f"Currently {days_until_expiry} days remaining."
                            ),
                            severity=Severity.INFO,
                            details={
                                "domain": domain,
                                "expiry_date": not_after,
                                "days_until_expiry": days_until_expiry,
                            },
                            scanner=self.name,
                        )
                    ]
        except Exception as e:
            return [
                Finding(
                    category=self.category,
                    title="Certificate Expiry Check Failed",
                    description=f"Could not check certificate expiry: {e}",
                    severity=Severity.LOW,
                    details={"domain": domain, "error": str(e)},
                    scanner=self.name,
                )
            ]

    def _check_certificate_transparency(self, domain: str) -> list[Finding]:
        """Check for Certificate Transparency logs."""
        try:
            url = f"https://crt.sh/?q=%25.{domain}&output=json"
            resp = requests.get(url, timeout=self.config.timeout)
            if resp.status_code == 200:
                entries = resp.json()
                return [
                    Finding(
                        category=self.category,
                        title="Certificate Transparency Logs",
                        description=(
                            f"Found {len(entries)} certificate entries in CT logs for "
                            f"{domain}. Certificate Transparency provides public "
                            f"auditability of all SSL/TLS certificates."
                        ),
                        severity=Severity.INFO,
                        details={
                            "domain": domain,
                            "ct_entries": len(entries),
                            "sample_issuers": list(set(
                                e.get("issuerNameID", e.get("issuerDN", "Unknown"))
                                for e in entries[:20]
                            ))[:5],
                        },
                        scanner=self.name,
                    )
                ]
        except Exception:
            pass

        return []

    def _check_tls_config(self, domain: str) -> list[Finding]:
        """Check TLS configuration security."""
        findings = []

        try:
            # Check protocol versions
            protocols = {
                "TLSv1.2": ssl.PROTOCOL_TLSv1_2,
                "TLSv1.3": ssl.PROTOCOL_TLSv1_3,
            }

            for proto_name, proto in protocols.items():
                try:
                    ctx = ssl.SSLContext(proto)
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE
                    with socket.create_connection((domain, 443), timeout=5) as sock:
                        with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                            findings.append(
                                Finding(
                                    category=self.category,
                                    title=f"{proto_name} — Supported",
                                    description=f"Server supports {proto_name}.",
                                    severity=Severity.INFO,
                                    details={"domain": domain, "protocol": proto_name, "supported": True},
                                    scanner=self.name,
                                )
                            )
                except (ssl.SSLError, socket.error):
                    findings.append(
                        Finding(
                            category=self.category,
                            title=f"{proto_name} — Not Supported",
                            description=f"Server does not support {proto_name}.",
                            severity=Severity.MEDIUM,
                            details={"domain": domain, "protocol": proto_name, "supported": False},
                            scanner=self.name,
                        )
                    )
        except Exception:
            pass

        return findings

"""Domain & WHOIS information gathering."""

from __future__ import annotations

import re
import socket
from datetime import datetime, timezone

import requests
import tldextract
import whois

from footprintscanner.config import Config
from footprintscanner.models import Finding, Severity, Target, ScannerCategory
from .base import BaseScanner


class DomainScanner(BaseScanner):
    """Gather WHOIS, DNS, and domain registration data."""

    name = "Domain Scanner"
    category = ScannerCategory.DOMAIN

    def scan(self, target: Target) -> list[Finding]:
        findings: list[Finding] = []

        if not target.domain:
            return findings

        findings.extend(self._check_domain_age(target))
        findings.extend(self._check_registrar_privacy(target))
        findings.extend(self._check_domain_expiry(target))
        findings.extend(self._check_mx_records(target))
        findings.extend(self._check_cname_records(target))
        findings.extend(self._check_ip_exposure(target))
        findings.extend(self._check_hosting_consistency(target))

        return findings

    def _get_whois(self, domain: str) -> whois.DOMain | None:
        try:
            return whois.whois(domain)
        except Exception as e:
            self.log(f"WHOIS lookup failed: {e}", "warning")
            return None

    def _check_domain_age(self, target: Target) -> list[Finding]:
        """Check if domain is newly registered (suspicious)."""
        whois_data = self._get_whois(target.domain)
        if not whois_data:
            return []

        domain_age_days = self._calculate_age(whois_data)
        if domain_age_days is None:
            return []

        if domain_age_days < 30:
            return [
                Finding(
                    category=self.category,
                    title="Newly Registered Domain",
                    description=(
                        f"The domain {target.domain} was registered only "
                        f"{domain_age_days} days ago. New domains are frequently "
                        "used in phishing, scam, and malware campaigns."
                    ),
                    severity=Severity.MEDIUM,
                    details={
                        "domain_age_days": domain_age_days,
                        "registration_date": str(whois_data.get("creation_date", "N/A")),
                    },
                    scanner=self.name,
                )
            ]

        if domain_age_days < 365:
            return [
                Finding(
                    category=self.category,
                    title="Domain Less Than One Year Old",
                    description=(
                        f"The domain {target.domain} is {domain_age_days} days old. "
                        "While not inherently dangerous, newer domains have a higher "
                        "likelihood of being associated with malicious activity."
                    ),
                    severity=Severity.LOW,
                    details={
                        "domain_age_days": domain_age_days,
                        "registration_date": str(whois_data.get("creation_date", "N/A")),
                    },
                    scanner=self.name,
                )
            ]

        return [
            Finding(
                category=self.category,
                title="Domain Age — Established",
                description=(
                    f"The domain {target.domain} has been registered for "
                    f"{domain_age_days} days. An established domain age "
                    "is a positive signal of legitimacy."
                ),
                severity=Severity.INFO,
                details={
                    "domain_age_days": domain_age_days,
                    "registration_date": str(whois_data.get("creation_date", "N/A")),
                },
                scanner=self.name,
            )
        ]

    def _calculate_age(self, whois_data) -> int | None:
        creation_dates = whois_data.get("creation_date")
        if isinstance(creation_dates, list):
            creation_dates = creation_dates[0]
        if isinstance(creation_dates, datetime):
            return (datetime.now(timezone.utc) - creation_dates).days
        if isinstance(creation_dates, str):
            try:
                cleaned = re.sub(r"\s*\(\w+\)$", "", creation_dates).strip()
                for fmt in ["%Y-%m-%d", "%d-%b-%Y", "%Y-%m-%dT%H:%M:%S"]:
                    try:
                        d = datetime.strptime(cleaned, fmt)
                        return (datetime.now(timezone.utc) - d).days
                    except ValueError:
                        continue
            except Exception:
                pass
        return None

    def _check_registrar_privacy(self, target: Target) -> list[Finding]:
        """Check if WHOIS privacy protection is enabled."""
        whois_data = self._get_whois(target.domain)
        if not whois_data:
            return []

        registrant_name = whois_data.get("name", "")
        registrant_org = whois_data.get("org", "") or whois_data.get("organization", "")

        is_private = False
        privacy_providers = [
            "whoisprivacy", "protection", "privacy", "anonymize",
            "redact", "masked", "hidden", "protected by",
        ]

        for text in [str(registrant_name), str(registrant_org)]:
            if any(p in text.lower() for p in privacy_providers):
                is_private = True
                break

        if is_private:
            return [
                Finding(
                    category=self.category,
                    title="WHOIS Privacy Protection Enabled",
                    description=(
                        "WHOIS privacy protection is active for this domain. "
                        "This is a positive security practice — it prevents "
                        "attackers from easily obtaining owner contact details."
                    ),
                    severity=Severity.INFO,
                    details={"privacy_status": "enabled"},
                    scanner=self.name,
                )
            ]

        return [
            Finding(
                category=self.category,
                title="WHOIS Information Exposed",
                description=(
                    "WHOIS registration details are publicly visible. "
                    "Consider enabling WHOIS privacy protection to mask "
                    "owner information. Public WHOIS data can be used "
                    "for social engineering and targeted attacks."
                ),
                severity=Severity.LOW,
                details={
                    "registrant_name": str(registrant_name),
                    "registrant_org": str(registrant_org),
                    "privacy_status": "disabled",
                },
                references=[
                    "https://whois.protomail.com/",
                ],
                scanner=self.name,
            )
        ]

    def _check_domain_expiry(self, target: Target) -> list[Finding]:
        """Check if the domain is nearing expiry."""
        whois_data = self._get_whois(target.domain)
        if not whois_data:
            return []

        expiry = whois_data.get("expiration_date")
        if isinstance(expiry, list):
            expiry = expiry[0]
        if isinstance(expiry, str):
            for fmt in ["%Y-%m-%d", "%d-%b-%Y", "%Y-%m-%dT%H:%M:%S"]:
                try:
                    expiry = datetime.strptime(expiry[:10].strip(), fmt)
                    break
                except ValueError:
                    continue

        if expiry is None:
            return []

        days_until_expiry = (expiry - datetime.now(timezone.utc)).days
        if days_until_expiry < 0:
            return [
                Finding(
                    category=self.category,
                    title="Domain Expired",
                    description=(
                        f"The domain {target.domain} expired {abs(days_until_expiry)} "
                        "days ago. An expired domain can be re-registered by anyone, "
                        "potentially redirecting traffic or damaging reputation."
                    ),
                    severity=Severity.CRITICAL,
                    details={"expiry_date": str(expiry), "days_since_expiry": abs(days_until_expiry)},
                    remediation="Renew the domain registration immediately. Configure auto-renewal.",
                    scanner=self.name,
                )
            ]

        if days_until_expiry < 30:
            return [
                Finding(
                    category=self.category,
                    title="Domain Expiring Soon",
                    description=(
                        f"The domain {target.domain} expires in {days_until_expiry} "
                        "days. Loss of domain control could lead to phishing or "
                        "malware distribution impersonating your brand."
                    ),
                    severity=Severity.HIGH,
                    details={"expiry_date": str(expiry), "days_until_expiry": days_until_expiry},
                    remediation="Renew the domain immediately. Enable auto-renewal and multi-factor authentication on the registrar.",
                    scanner=self.name,
                )
            ]

        return [
            Finding(
                category=self.category,
                title="Domain Expiration — Adequate",
                description=(
                    f"The domain expires in {days_until_expiry} days. "
                    "Consider setting up auto-renewal as a precaution."
                ),
                severity=Severity.INFO,
                details={"expiry_date": str(expiry), "days_until_expiry": days_until_expiry},
                scanner=self.name,
            )
        ]

    def _check_mx_records(self, target: Target) -> list[Finding]:
        """Check MX records for misconfiguration."""
        try:
            import dns.resolver
            answers = dns.resolver.resolve(target.domain, "MX")
            mx_records = [(str(r.exchange), r.preference) for r in answers]
        except Exception as e:
            return [
                Finding(
                    category=self.category,
                    title="MX Record Resolution Failed",
                    description=f"MX records could not be resolved: {e}",
                    severity=Severity.MEDIUM,
                    details={"error": str(e)},
                    scanner=self.name,
                )
            ]

        if not mx_records:
            return [
                Finding(
                    category=self.category,
                    title="No MX Records Found",
                    description=(
                        "No MX (mail exchange) records exist for this domain. "
                        "Email sent to this domain will fail. If email is expected, "
                        "this is misconfigured."
                    ),
                    severity=Severity.MEDIUM,
                    details={"mx_records": []},
                    scanner=self.name,
                )
            ]

        mx_sorted = sorted(mx_records, key=lambda x: x[1])
        return [
            Finding(
                category=self.category,
                title="MX Records Configured",
                description=(
                    f"MX records found: {', '.join(m[0] for m in mx_sorted)}. "
                    "Email routing is operational."
                ),
                severity=Severity.INFO,
                details={"mx_records": [str(m) for m in mx_sorted]},
                scanner=self.name,
            )
        ]

    def _check_cname_records(self, target: Target) -> list[Finding]:
        """Check for CNAME chains that could indicate misconfiguration."""
        try:
            import dns.resolver
            try:
                answers = dns.resolver.resolve(target.domain, "CNAME")
                chain = [str(r.target) for r in answers]
            except dns.resolver.NoAnswer:
                return []

            if len(chain) > 3:
                return [
                    Finding(
                        category=self.category,
                        title="Deep CNAME Chain Detected",
                        description=(
                            f"The domain has a CNAME chain of {len(chain)} hops. "
                            "Deep chains can cause DNS resolution delays and "
                            "increase the attack surface."
                        ),
                        severity=Severity.LOW,
                        details={"cname_chain": chain},
                        scanner=self.name,
                    )
                ]
        except Exception:
            pass
        return []

    def _check_ip_exposure(self, target: Target) -> list[Finding]:
        """Check if the domain resolves to a private IP address."""
        try:
            ips = socket.gethostbyname_ex(target.domain)
            private_prefixes = ("10.", "192.168.", "172.16.", "172.17.", "172.18.",
                              "172.19.", "172.20.", "172.21.", "172.22.", "172.23.",
                              "172.24.", "172.25.", "172.26.", "172.27.", "172.28.",
                              "172.29.", "172.30.", "172.31.", "127.", "0.0.0.0")
            internal_ips = [ip for ip in ips[2] if ip.startswith(private_prefixes)]
            if internal_ips:
                return [
                    Finding(
                        category=self.category,
                        title="Internal IP Address Exposed via DNS",
                        description=(
                            f"DNS resolution for {target.domain} returned internal "
                            f"IP addresses: {', '.join(internal_ips)}. "
                            "This exposes your internal network topology to anyone "
                            " who queries your DNS."
                        ),
                        severity=Severity.CRITICAL,
                        details={"internal_ips": internal_ips, "all_ips": ips[2]},
                        remediation="Remove internal IP addresses from public DNS records. Use split-horizon DNS.",
                        scanner=self.name,
                    )
                ]
        except Exception:
            pass
        return []

    def _check_hosting_consistency(self, target: Target) -> list[Finding]:
        """Check if the domain resolves to an unexpected IP."""
        if target.ip:
            try:
                resolved = socket.gethostbyname(target.domain)
                if resolved != target.ip:
                    return [
                        Finding(
                            category=self.category,
                            title="DNS Resolution Mismatch",
                            description=(
                                f"The provided IP ({target.ip}) does not match "
                                f"the DNS resolution ({resolved}). This could "
                                "indicate DNS hijacking or misconfiguration."
                            ),
                            severity=Severity.HIGH,
                            details={"provided_ip": target.ip, "resolved_ip": resolved},
                            remediation="Verify DNS records are correct. Check for DNS hijacking.",
                            scanner=self.name,
                        )
                    ]
            except Exception:
                pass
        return []

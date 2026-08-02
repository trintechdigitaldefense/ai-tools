"""DNS and security configuration analysis."""

from __future__ import annotations

import dns.resolver
import dns.name

from footprintscanner.config import Config
from footprintscanner.models import Finding, Severity, Target, ScannerCategory
from .base import BaseScanner


class DNSAnalyzer(BaseScanner):
    """Analyze DNS records, SPF, DKIM, DMARC, DNSSEC, and more."""

    name = "DNS Analyzer"
    category = ScannerCategory.DOMAIN

    def scan(self, target: Target) -> list[Finding]:
        findings: list[Finding] = []

        if not target.domain:
            return findings

        domain = target.domain

        if not self._is_valid_domain(domain):
            return [
                Finding(
                    category=self.category,
                    title="Invalid Domain for DNS Analysis",
                    description=f"Cannot perform DNS analysis on non-domain identifier.",
                    severity=Severity.LOW,
                    details={"target": domain},
                    scanner=self.name,
                )
            ]

        findings.extend(self._check_dnssec(domain))
        findings.extend(self._check_spf(domain))
        findings.extend(self._check_dkim(domain))
        findings.extend(self._check_dmarc(domain))
        findings.extend(self._check_dane(domain))
        findings.extend(self._check_dns_records(domain))
        findings.extend(self._check_caa_records(domain))

        return findings

    def _is_valid_domain(self, domain: str) -> bool:
        """Check if a string looks like a domain (not an IP or email)."""
        import re
        return bool(re.match(r"^[a-zA-Z0-9][a-zA-Z0-9-]*\.[a-zA-Z]{2,}$", domain))

    def _check_dnssec(self, domain: str) -> list[Finding]:
        """Check if DNSSEC is configured."""
        try:
            answers = dns.resolver.resolve(domain, "DNSKEY")
            dnssec_enabled = len(list(answers)) > 0

            if dnssec_enabled:
                return [
                    Finding(
                        category=self.category,
                        title="DNSSEC Enabled",
                        description=(
                            "DNSSEC (Domain Name System Security Extensions) is "
                            "configured. This protects against DNS spoofing and "
                            "cache poisoning attacks."
                        ),
                        severity=Severity.INFO,
                        details={"dnssec": "enabled"},
                        scanner=self.name,
                    )
                ]

            return [
                Finding(
                    category=self.category,
                    title="DNSSEC Not Configured",
                    description=(
                        "DNSSEC is not enabled for this domain. Without DNSSEC, "
                        "attackers can perform DNS spoofing, redirecting users to "
                        "malicious sites. This is especially dangerous for email "
                        "security."
                    ),
                    severity=Severity.MEDIUM,
                    details={"dnssec": "disabled"},
                    remediation=(
                        "Enable DNSSEC at your domain registrar. Most registrars "
                        "provide one-click DNSSEC enabling. Consult your DNS provider's "
                        "documentation for configuration steps."
                    ),
                    references=[
                        "https://dnssec-analyzer.verisignlabs.com/",
                        "https://www.icann.org/resources/pages/dnssec-what-is-it-why-important-2019-03-05-en",
                    ],
                    scanner=self.name,
                )
            ]
        except dns.resolver.NoAnswer:
            return [
                Finding(
                    category=self.category,
                    title="DNSSEC Check Failed",
                    description="DNSSEC could not be verified. The domain may not support it.",
                    severity=Severity.LOW,
                    details={"dnssec": "unknown"},
                    scanner=self.name,
                )
            ]
        except Exception as e:
            return [
                Finding(
                    category=self.category,
                    title="DNSSEC Analysis Error",
                    description=f"Error checking DNSSEC: {e}",
                    severity=Severity.LOW,
                    details={"error": str(e)},
                    scanner=self.name,
                )
            ]

    def _check_spf(self, domain: str) -> list[Finding]:
        """Check SPF record configuration."""
        try:
            answers = dns.resolver.resolve(domain, "TXT")
            spf_records = []
            for rdata in answers:
                txt = str(rdata).strip('"')
                if txt.startswith("v=spf1"):
                    spf_records.append(txt)

            if not spf_records:
                return [
                    Finding(
                        category=self.category,
                        title="No SPF Record Found",
                        description=(
                            "No SPF (Sender Policy Framework) record exists. "
                            "Without SPF, attackers can send emails that appear "
                            "to come from your domain — enabling phishing and "
                            "email impersonation attacks."
                        ),
                        severity=Severity.HIGH,
                        details={"spf": "missing"},
                        remediation=(
                            "Add an SPF record to your DNS:\n"
                            "  v=spf1 include:_spf.google.com ~all\n"
                            "(Replace with your mail provider's SPF record.)\n"
                            "Use ~all (softfail) initially, then move to -all (hardfail) "
                            "after verifying all legitimate mail sources."
                        ),
                        references=[
                            "https://www.cloudflare.com/learning/dns/dns-records/spf-record/",
                        ],
                        scanner=self.name,
                    )
                ]

            spf_str = spf_records[0]

            if "+all" in spf_str or "all" not in spf_str:
                return [
                    Finding(
                        category=self.category,
                        title="Dangerous SPF Configuration",
                        description=(
                            f"SPF record '{spf_str}' is misconfigured. "
                            "This could allow anyone to send email from your domain."
                        ),
                        severity=Severity.CRITICAL,
                        details={"spf": spf_str, "spf_status": "dangerous"},
                        remediation=(
                            "Fix the SPF record to use ~all (softfail) or -all (hardfail): "
                            "v=spf1 <include> ~all"
                        ),
                        scanner=self.name,
                    )
                ]

            if "-all" in spf_str:
                return [
                    Finding(
                        category=self.category,
                        title="SPF Record — Hard Fail Configured",
                        description=(
                            f"SPF record: {spf_str}\n"
                            "SPF is properly configured with hard fail. "
                            "This is the most restrictive and recommended setting."
                        ),
                        severity=Severity.INFO,
                        details={"spf": spf_str, "spf_status": "hard_fail"},
                        scanner=self.name,
                    )
                ]

            if "~all" in spf_str:
                return [
                    Finding(
                        category=self.category,
                        title="SPF Record — Soft Fail",
                        description=(
                            f"SPF record: {spf_str}\n"
                            "SPF uses soft fail (~all). While functional, "
                            "switching to hard fail (-all) provides stronger protection."
                        ),
                        severity=Severity.LOW,
                        details={"spf": spf_str, "spf_status": "soft_fail"},
                        remediation="Change ~all to -all after verifying all mail sources.",
                        scanner=self.name,
                    )
                ]

        except dns.resolver.NoAnswer:
            return [self._spf_missing()]
        except Exception as e:
            return [
                Finding(
                    category=self.category,
                    title="SPF Check Failed",
                    description=f"Could not check SPF: {e}",
                    severity=Severity.LOW,
                    details={"error": str(e)},
                    scanner=self.name,
                )
            ]

        return []

    def _spf_missing(self) -> Finding:
        return Finding(
            category=self.category,
            title="No SPF Record Found",
            description=(
                "No SPF record exists. Attackers can send phishing emails "
                "from your domain."
            ),
            severity=Severity.HIGH,
            details={"spf": "missing"},
            remediation="Add an SPF record: v=spf1 include:_your_provider ~all",
            scanner=self.name,
        )

    def _check_dkim(self, domain: str) -> list[Finding]:
        """Check DKIM configuration."""
        try:
            # Try common DKIM selectors
            selectors = ["default", "google", "google._domainkey", "dkim"]
            found = False

            for selector in selectors:
                try:
                    answers = dns.resolver.resolve(f"{selector}._domainkey.{domain}", "TXT")
                    for rdata in answers:
                        txt = str(rdata)
                        if "v=DKIM1" in txt:
                            found = True
                            break
                    if found:
                        break
                except dns.resolver.NoAnswer:
                    continue

            if found:
                return [
                    Finding(
                        category=self.category,
                        title="DKIM Configured",
                        description=(
                            "DKIM (DomainKeys Identified Mail) is configured. "
                            "This adds a digital signature to emails, verifying "
                            "they haven't been altered in transit."
                        ),
                        severity=Severity.INFO,
                        details={"dkim": "configured"},
                        scanner=self.name,
                    )
                ]

            return [
                Finding(
                    category=self.category,
                    title="DKIM Not Configured",
                    description=(
                        "DKIM is not configured for this domain. Without DKIM, "
                        "recipients cannot verify that emails genuinely came from "
                        "your domain and weren't modified."
                    ),
                    severity=Severity.HIGH,
                    details={"dkim": "missing"},
                    remediation=(
                        "Add a DKIM record to your DNS. Contact your email provider "
                        "(Google, Microsoft, etc.) for the specific DKIM record to add."
                    ),
                    scanner=self.name,
                )
            ]
        except Exception as e:
            return [
                Finding(
                    category=self.category,
                    title="DKIM Check Failed",
                    description=f"Could not check DKIM: {e}",
                    severity=Severity.LOW,
                    details={"error": str(e)},
                    scanner=self.name,
                )
            ]

    def _check_dmarc(self, domain: str) -> list[Finding]:
        """Check DMARC configuration."""
        try:
            answers = dns.resolver.resolve(f"_dmarc.{domain}", "TXT")
            dmarc_records = []
            for rdata in answers:
                txt = str(rdata).strip('"')
                if "v=DMARC1" in txt:
                    dmarc_records.append(txt)

            if not dmarc_records:
                return [
                    Finding(
                        category=self.category,
                        title="No DMARC Record Found",
                        description=(
                            "No DMARC (Domain-based Message Authentication, Reporting "
                            "and Conformance) record exists. DMARC tells receiving "
                            "mail servers what to do with emails that fail SPF/DKIM "
                            "checks. Without it, attackers can more easily impersonate "
                            "your domain."
                        ),
                        severity=Severity.HIGH,
                        details={"dmarc": "missing"},
                        remediation=(
                            "Add a DMARC record to your DNS. Start with a monitoring-only policy:\n"
                            "  v=DMARC1; p=none; rua=mailto:dmarc-reports@yourdomain.com\n"
                            "After monitoring for 2-4 weeks, upgrade to:\n"
                            "  v=DMARC1; p=quarantine; rua=mailto:dmarc@yourdomain.com\n"
                            "Finally, when confident:\n"
                            "  v=DMARC1; p=reject; rua=mailto:dmarc@yourdomain.com"
                        ),
                        references=[
                            "https://dmarc.org/",
                            "https://developers.cloudflare.com/dns/dmarc-records/",
                        ],
                        scanner=self.name,
                    )
                ]

            record = dmarc_records[0]
            is_reject = "p=reject" in record
            is_quarantine = "p=quarantine" in record
            has_reporting = "rua=" in record

            if is_reject:
                return [
                    Finding(
                        category=self.category,
                        title="DMARC — Reject Policy Configured",
                        description=(
                            f"DMARC record: {record}\n"
                            "DMARC is properly configured with reject policy. "
                            "This is the strongest DMARC setting."
                        ),
                        severity=Severity.INFO,
                        details={"dmarc": record, "dmarc_status": "reject"},
                        scanner=self.name,
                    )
                ]

            if is_quarantine:
                return [
                    Finding(
                        category=self.category,
                        title="DMARC — Quarantine Policy",
                        description=(
                            f"DMARC record: {record}\n"
                            "DMARC uses quarantine policy. Consider upgrading to reject."
                        ),
                        severity=Severity.LOW,
                        details={"dmarc": record, "dmarc_status": "quarantine"},
                        remediation="Change policy from p=quarantine to p=reject.",
                        scanner=self.name,
                    )
                ]

            return [
                Finding(
                    category=self.category,
                    title="DMARC — Monitoring Only",
                    description=(
                        f"DMARC record: {record}\n"
                        "DMARC is set to monitoring-only (p=none). This does not "
                        "enforce any policy — emails failing authentication will "
                        "still be delivered."
                    ),
                    severity=Severity.MEDIUM,
                    details={"dmarc": record, "dmarc_status": "none"},
                    remediation="Upgrade DMARC policy to quarantine or reject.",
                    scanner=self.name,
                )
            ]

        except dns.resolver.NoAnswer:
            return [
                Finding(
                    category=self.category,
                    title="No DMARC Record Found",
                    description=(
                        "No DMARC record found for this domain."
                    ),
                    severity=Severity.HIGH,
                    details={"dmarc": "missing"},
                    remediation="Add DMARC record: v=DMARC1; p=none; rua=mailto:dmarc@yourdomain.com",
                    scanner=self.name,
                )
            ]
        except Exception as e:
            return [
                Finding(
                    category=self.category,
                    title="DMARC Check Failed",
                    description=f"Could not check DMARC: {e}",
                    severity=Severity.LOW,
                    details={"error": str(e)},
                    scanner=self.name,
                )
            ]

    def _check_dane(self, domain: str) -> list[Finding]:
        """Check for DANE (DNS-based Authentication of Named Entities)."""
        try:
            answers = dns.resolver.resolve(f"_25._tcp.{domain}", "TLSA")
            if len(list(answers)) > 0:
                return [
                    Finding(
                        category=self.category,
                        title="DANE TLSA Record Found",
                        description=(
                            "DANE TLSA records are configured. This provides "
                            "additional email security by binding TLS certificates "
                            "to DNSSEC-signed records."
                        ),
                        severity=Severity.INFO,
                        details={"dane": "enabled"},
                        scanner=self.name,
                    )
                ]
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            pass
        except Exception:
            pass
        return [
            Finding(
                category=self.category,
                title="DANE Not Configured",
                description=(
                    "DANE is not configured. DANE adds an extra layer of "
                    "security for email by tying TLS certificates to DNS."
                ),
                severity=Severity.LOW,
                details={"dane": "disabled"},
                scanner=self.name,
            )
        ]

    def _check_dns_records(self, domain: str) -> list[Finding]:
        """Check common DNS records for completeness."""
        findings = []
        record_types = ["A", "AAAA", "CNAME", "NS", "SOA", "MX", "TXT"]
        missing = []
        present = {}

        for rtype in record_types:
            try:
                answers = dns.resolver.resolve(domain, rtype)
                present[rtype] = len(list(answers))
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                missing.append(rtype)

        if missing:
            findings.append(
                Finding(
                    category=self.category,
                    title=f"Missing DNS Records: {', '.join(missing)}",
                    description=(
                        f"DNS record type(s) {', '.join(missing)} are not "
                        f"configured for {domain}. Missing records may indicate "
                        "an incomplete DNS setup."
                    ),
                    severity=Severity.LOW,
                    details={"present": present, "missing": missing},
                    scanner=self.name,
                )
            )

        return findings

    def _check_caa_records(self, domain: str) -> list[Finding]:
        """Check CAA (Certificate Authority Authorization) records."""
        try:
            answers = dns.resolver.resolve(domain, "CAA")
            caas = [str(rdata) for rdata in answers]
            return [
                Finding(
                    category=self.category,
                    title="CAA Records Configured",
                    description=(
                        f"CAA records found: {caas}. "
                        "CAA records restrict which certificate authorities can "
                        "issue certificates for this domain, preventing unauthorized SSL certs."
                    ),
                    severity=Severity.INFO,
                    details={"caa": caas},
                    scanner=self.name,
                )
            ]
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            return [
                Finding(
                    category=self.category,
                    title="No CAA Records Found",
                    description=(
                        "No CAA records exist. Any CA can issue an SSL certificate "
                        "for this domain, which could allow an attacker to create "
                        "a valid certificate for your domain."
                    ),
                    severity=Severity.LOW,
                    details={"caa": "missing"},
                    remediation=(
                        "Add CAA records to restrict certificate issuance. "
                        "Example: 0 issue \"letsencrypt.org\""
                    ),
                    scanner=self.name,
                )
            ]
        except Exception as e:
            return [
                Finding(
                    category=self.category,
                    title="CAA Check Failed",
                    description=f"Error checking CAA: {e}",
                    severity=Severity.LOW,
                    details={"error": str(e)},
                    scanner=self.name,
                )
            ]

"""IP and network infrastructure analysis."""

from __future__ import annotations

import socket

import requests

from footprintscanner.config import Config
from footprintscanner.models import Finding, Severity, Target, ScannerCategory
from .base import BaseScanner


class IPScanner(BaseScanner):
    """Analyze IP addresses and network infrastructure."""

    name = "IP Scanner"
    category = ScannerCategory.IP_INFRASTRUCTURE

    def scan(self, target: Target) -> list[Finding]:
        findings: list[Finding] = []

        # If domain provided, resolve it
        if target.domain and not target.ip:
            try:
                ip = socket.gethostbyname(target.domain)
                target.ip = ip
            except socket.gaierror:
                target.ip = ""

        # IP lookup
        if target.ip:
            findings.extend(self._check_ip_reputation(target.ip))
            findings.extend(self._check_ip_location(target.ip))
            findings.extend(self._check_ip_type(target.ip))

        # Reverse DNS for domain
        if target.domain:
            findings.extend(self._check_reverse_dns(target.domain))

        # Reverse IP lookup (if we have an IP)
        if target.ip:
            findings.extend(self._check_reverse_ip(target.ip))

        return findings

    def _check_ip_reputation(self, ip: str) -> list[Finding]:
        """Check if an IP has a bad reputation."""
        findings = []

        api_urls = [
            f"https://api.abuseipdb.com/api/v2/ip/{ip}",
            f"https://threatfox-api.abuse.ch/api/v1/ip/{ip}",
        ]

        for api_url in api_urls[:1]:  # Use abuseipdb as primary
            try:
                headers = {
                    "User-Agent": self.config.user_agent,
                    "Accept": "application/json",
                }
                resp = requests.get(api_url, headers=headers, timeout=self.config.timeout)
                if resp.status_code == 200:
                    data = resp.json()
                    report = data.get("data", {})
                    report_count = report.get("reportCount", 0)

                    if report_count > 10:
                        findings.append(
                            Finding(
                                category=self.category,
                                title=f"High Abuse Reports for {ip}",
                                description=(
                                    f"IP {ip} has {report_count} abuse reports. "
                                    f"This IP is associated with malicious activity."
                                ),
                                severity=Severity.CRITICAL,
                                details={
                                    "ip": ip,
                                    "abuse_reports": report_count,
                                    "categories": report.get("categories", []),
                                },
                                remediation=(
                                    "Investigate why this IP is associated with "
                                    "abuse. If it's your own infrastructure, "
                                    "immediately isolate and investigate affected systems."
                                ),
                                scanner=self.name,
                            )
                        )
                    elif report_count > 0:
                        findings.append(
                            Finding(
                                category=self.category,
                                title=f"Some Abuse Reports for {ip}",
                                description=(
                                    f"IP {ip} has {report_count} abuse reports. "
                                    f"While not critical, this warrants investigation."
                                ),
                                severity=Severity.MEDIUM,
                                details={
                                    "ip": ip,
                                    "abuse_reports": report_count,
                                },
                                scanner=self.name,
                            )
                        )
                elif resp.status_code == 401:
                    findings.append(
                        Finding(
                            category=self.category,
                            title="AbuseIPDB API Key Required",
                            description="AbuseIPDB requires an API key. Free tier available.",
                            severity=Severity.LOW,
                            details={"ip": ip},
                            scanner=self.name,
                        )
                    )
            except requests.RequestException:
                pass

        return findings

    def _check_ip_location(self, ip: str) -> list[Finding]:
        """Get IP geolocation info."""
        findings = []

        try:
            resp = requests.get(
                f"https://ipinfo.io/{ip}/json",
                headers={"User-Agent": self.config.user_agent},
                timeout=self.config.timeout,
            )
            if resp.status_code == 200:
                data = resp.json()
                city = data.get("city", "")
                region = data.get("region", "")
                country = data.get("country", "")
                org = data.get("org", "")

                findings.append(
                    Finding(
                        category=self.category,
                        title=f"IP Location — {ip}",
                        description=(
                            f"{ip} is located in: {city}, {region}, {country}\n"
                            f"Organization: {org}"
                        ),
                        severity=Severity.INFO,
                        details={
                            "ip": ip,
                            "city": city,
                            "region": region,
                            "country": country,
                            "org": org,
                            "postal": data.get("postal", ""),
                            "hostname": data.get("hostname", ""),
                        },
                        scanner=self.name,
                    )
                )
            else:
                return [
                    Finding(
                        category=self.category,
                        title="IP Geolocation Failed",
                        description=f"Could not resolve geolocation for {ip} (HTTP {resp.status_code}).",
                        severity=Severity.LOW,
                        details={"ip": ip},
                        scanner=self.name,
                    )
                ]
        except requests.RequestException as e:
            return [
                Finding(
                    category=self.category,
                    title="IP Geolocation Error",
                    description=f"Error checking IP location: {e}",
                    severity=Severity.LOW,
                    details={"ip": ip},
                    scanner=self.name,
                )
            ]

        return findings

    def _check_ip_type(self, ip: str) -> list[Finding]:
        """Check if an IP is a known cloud provider or dynamic IP."""
        findings = []

        if ip.startswith("10.") or ip.startswith("192.168.") or ip.startswith("172."):
            return [
                Finding(
                    category=self.category,
                    title="Private IP Address",
                    description=f"IP {ip} is a private/internal IP address.",
                    severity=Severity.LOW,
                    details={"ip": ip, "type": "private"},
                    scanner=self.name,
                )
            ]

        if ip.startswith("127.") or ip == "0.0.0.0":
            return [
                Finding(
                    category=self.category,
                    title="Loopback/Local IP",
                    description=f"IP {ip} is a loopback or local address.",
                    severity=Severity.LOW,
                    details={"ip": ip, "type": "loopback"},
                    scanner=self.name,
                )
            ]

        # Check if it's a known cloud provider
        cloud_prefixes = {
            "AWS": "13.",
            "Google Cloud": "34.",
            "Microsoft Azure": "40.",
            "Cloudflare": "104.",
        }

        for provider, prefix in cloud_prefixes.items():
            if ip.startswith(prefix):
                findings.append(
                    Finding(
                        category=self.category,
                        title=f"Cloud Provider Detected",
                        description=(
                            f"IP {ip} appears to be hosted on {provider} infrastructure. "
                            f"Cloud-hosted services can be spun up and taken down quickly, "
                            f"making abuse harder to track."
                        ),
                        severity=Severity.LOW,
                        details={"ip": ip, "cloud_provider": provider},
                        scanner=self.name,
                    )
                )
                break

        return findings

    def _check_reverse_dns(self, domain: str) -> list[Finding]:
        """Check reverse DNS for a domain."""
        try:
            reverse = socket.gethostbyaddr(socket.gethostbyname(domain))
            return [
                Finding(
                    category=self.category,
                    title="Reverse DNS Configured",
                    description=(
                        f"Reverse DNS for {domain} resolves to: {reverse[0]}"
                    ),
                    severity=Severity.INFO,
                    details={
                        "domain": domain,
                        "rDNS": reverse[0],
                    },
                    scanner=self.name,
                )
            ]
        except Exception:
            return [
                Finding(
                    category=self.category,
                    title="No Reverse DNS",
                    description=f"No reverse DNS record found for {domain}.",
                    severity=Severity.LOW,
                    details={"domain": domain, "rDNS": "none"},
                    scanner=self.name,
                )
            ]

    def _check_reverse_ip(self, ip: str) -> list[Finding]:
        """Check for other domains sharing the same IP."""
        findings = []

        try:
            # Use a reverse IP lookup service
            resp = requests.get(
                f"https://api.hackertarget.com/reverseiplookup/?q={ip}",
                timeout=self.config.timeout,
            )
            if resp.status_code == 200:
                domains = [line.strip() for line in resp.text.splitlines() if line.strip()]
                if len(domains) > 5:
                    findings.append(
                        Finding(
                            category=self.category,
                            title=f"Multiple Domains on Same IP ({len(domains)})",
                            description=(
                                f"IP {ip} hosts {len(domains)} domains. "
                                f"Hosting many domains on a single IP means "
                                f"compromise of one site could affect all others."
                            ),
                            severity=Severity.MEDIUM,
                            details={
                                "ip": ip,
                                "hosted_domains_count": len(domains),
                                "sample_domains": domains[:20],
                            },
                            remediation=(
                                "Consider using separate IPs for critical services. "
                                "Isolate sensitive sites on dedicated infrastructure."
                            ),
                            scanner=self.name,
                        )
                    )
                elif domains:
                    findings.append(
                        Finding(
                            category=self.category,
                            title=f"Reverse IP Lookup",
                            description=(
                                f"IP {ip} hosts {len(domains)} domain(s): "
                                + ", ".join(domains[:10])
                            ),
                            severity=Severity.INFO,
                            details={
                                "ip": ip,
                                "hosted_domains": domains,
                            },
                            scanner=self.name,
                        )
                    )
        except requests.RequestException:
            pass

        return findings

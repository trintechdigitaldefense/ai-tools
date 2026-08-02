"""Security headers analysis for a domain's web presence."""

from __future__ import annotations

import re

import requests

from footprintscanner.config import Config
from footprintscanner.models import Finding, Severity, Target, ScannerCategory
from .base import BaseScanner


REQUIRED_HEADERS = {
    "strict-transport-security": {
        "name": "Strict-Transport-Security (HSTS)",
        "description": "Forces browsers to use HTTPS, preventing SSL stripping attacks.",
        "severity": Severity.HIGH,
    },
    "content-security-policy": {
        "name": "Content-Security-Policy (CSP)",
        "description": "Restricts which sources can load resources, preventing XSS and data injection.",
        "severity": Severity.HIGH,
    },
    "x-frame-options": {
        "name": "X-Frame-Options",
        "description": "Prevents clickjacking by controlling iframe embedding.",
        "severity": Severity.MEDIUM,
    },
    "x-content-type-options": {
        "name": "X-Content-Type-Options",
        "description": "Prevents MIME-type sniffing attacks.",
        "severity": Severity.MEDIUM,
    },
    "referrer-policy": {
        "name": "Referrer-Policy",
        "description": "Controls how much referrer info is sent with requests.",
        "severity": Severity.LOW,
    },
    "permissions-policy": {
        "name": "Permissions-Policy",
        "description": "Controls browser feature access (camera, mic, geolocation).",
        "severity": Severity.MEDIUM,
    },
    "x-xss-protection": {
        "name": "X-XSS-Protection",
        "description": "Legacy XSS filter header (deprecated but still useful).",
        "severity": Severity.LOW,
    },
}

DANGEROUS_HEADERS = {
    "server": {
        "description": "Exposes server software information.",
        "severity": Severity.LOW,
    },
    "x-powered-by": {
        "description": "Exposes technology stack information.",
        "severity": Severity.LOW,
    },
    "access-control-allow-origin": {
        "description": "CORS header — if set to '*', this is overly permissive.",
        "severity": Severity.MEDIUM,
    },
}


class SecurityHeadersScanner(BaseScanner):
    """Analyze HTTP security headers for a domain."""

    name = "Security Headers Scanner"
    category = ScannerCategory.SECURITY_HEADERS

    def scan(self, target: Target) -> list[Finding]:
        findings: list[Finding] = []

        if not target.domain:
            return findings

        urls_to_check = [f"https://{target.domain}", f"http://{target.domain}"]

        for url in urls_to_check:
            try:
                resp = requests.get(url, headers={"User-Agent": self.config.user_agent},
                                    timeout=self.config.timeout,
                                    allow_redirects=True, verify=True)
                findings.extend(self._analyze_headers(target.domain, resp, url))
                break  # Only analyze the first working URL
            except requests.RequestException:
                continue

        return findings

    def _analyze_headers(self, domain: str, resp: requests.Response, url: str) -> list[Finding]:
        findings: list[Finding] = []

        headers_lower = {k.lower(): v for k, v in resp.headers.items()}

        # Check required headers
        for header, info in REQUIRED_HEADERS.items():
            value = headers_lower.get(header)
            if value:
                findings.append(
                    Finding(
                        category=self.category,
                        title=f"{info['name']} — Present",
                        description=(
                            f"{info['description']}\n"
                            f"Value: {value}"
                        ),
                        severity=Severity.INFO,
                        details={"header": header, "value": value, "url": url},
                        scanner=self.name,
                    )
                )
            else:
                findings.append(
                    Finding(
                        category=self.category,
                        title=f"{info['name']} — Missing",
                        description=(
                            f"{info['description']}\n"
                            f"Header '{header}' is NOT set on {url}."
                        ),
                        severity=info["severity"],
                        details={"header": header, "status": "missing", "url": url},
                        remediation=self._get_remediation(header),
                        references=[
                            f"https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/{header}",
                        ],
                        scanner=self.name,
                    )
                )

        # Check dangerous headers
        for header, info in DANGEROUS_HEADERS.items():
            value = headers_lower.get(header)
            if value:
                severity = info["severity"]
                if header == "access-control-allow-origin" and value == "*":
                    severity = Severity.HIGH
                    findings.append(
                        Finding(
                            category=self.category,
                            title=f"CORS Wildcard Detected",
                            description=(
                                f"{info['description']}\n"
                                f"CORS is set to '*' (allow all origins) on {url}. "
                                "This is a serious misconfiguration that could allow "
                                "any website to make requests to this domain."
                            ),
                            severity=severity,
                            details={"header": header, "value": value, "url": url},
                            remediation=(
                                "Replace '*' with specific allowed origins. "
                                "Example: Access-Control-Allow-Origin: https://yourdomain.com"
                            ),
                            scanner=self.name,
                        )
                    )
                else:
                    findings.append(
                        Finding(
                            category=self.category,
                            title=f"{header} — Information Disclosure",
                            description=(
                                f"{info['description']}\n"
                                f"Value: {value}"
                            ),
                            severity=severity,
                            details={"header": header, "value": value, "url": url},
                            remediation=f"Remove the {header} header from server configuration.",
                            scanner=self.name,
                        )
                    )

        # Check HTTPS redirect
        if url.startswith("http://") and resp.status_code == 200:
            if "https://" not in resp.url:
                findings.append(
                    Finding(
                        category=self.category,
                        title="HTTP to HTTPS Redirect Missing",
                        description=(
                            f"{url} served content over plain HTTP without redirecting to HTTPS. "
                            "All traffic should redirect to HTTPS."
                        ),
                        severity=Severity.HIGH,
                        details={"http_url": url, "https_redirect": False},
                        remediation="Configure your server to redirect all HTTP traffic to HTTPS.",
                        scanner=self.name,
                    )
                )

        # Check response headers for security-relevant info
        if "content-type" in headers_lower:
            ct = headers_lower["content-type"]
            if "charset=ascii" in ct or "charset=us-ascii" in ct:
                findings.append(
                    Finding(
                        category=self.category,
                        title="ASCII Content-Type Detected",
                        description=(
                            f"Content-Type charset is set to ASCII. Modern pages should "
                            f"use UTF-8 to prevent character encoding attacks."
                        ),
                        severity=Severity.LOW,
                        details={"content_type": ct},
                        remediation="Set Content-Type charset to UTF-8.",
                        scanner=self.name,
                    )
                )

        return findings

    def _get_remediation(self, header: str) -> str:
        remappings = {
            "strict-transport-security": (
                'Add: Strict-Transport-Security: "max-age=63072000; includeSubDomains; preload"'
            ),
            "content-security-policy": (
                "Add a CSP header. Example:\n"
                "  Content-Security-Policy: default-src 'self'; "
                "script-src 'self'; style-src 'self' 'unsafe-inline'"
            ),
            "x-frame-options": (
                'Add: X-Frame-Options: "DENY" or "SAMEORIGIN"'
            ),
            "x-content-type-options": (
                'Add: X-Content-Type-Options: "nosniff"'
            ),
            "referrer-policy": (
                'Add: Referrer-Policy: "strict-origin-when-cross-origin"'
            ),
            "permissions-policy": (
                'Add: Permissions-Policy: "camera=(), microphone=(), geolocation=()"'
            ),
            "x-xss-protection": (
                "Note: X-XSS-Protection is deprecated. Rely on CSP instead."
            ),
        }
        return remappings.get(header, f"Configure the {header} header on your web server.")

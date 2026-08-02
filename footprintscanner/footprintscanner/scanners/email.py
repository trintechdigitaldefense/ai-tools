"""Email footprint scanning — breach checking, alias lookup, mailbox verification."""

from __future__ import annotations

import re
import urllib.parse

import requests

from footprintscanner.config import Config
from footprintscanner.models import Finding, Severity, Target, ScannerCategory
from .base import BaseScanner


# Well-known email providers for format validation
KNOWN_PROVIDERS = [
    "gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "icloud.com",
    "protonmail.com", "mail.com", "aol.com", "zoho.com", "yandex.com",
    "fastmail.com", "tutanota.com", "gmx.com",
]

# Common email format patterns
EMAIL_FORMATS = [
    ("first.last", r"^([a-z0-9.]+)@.*$"),  # first.last@example.com
    ("first", r"^([a-z0-9.]+)@.*$"),        # first@example.com
    ("last.first", r"^([a-z0-9.]+)@.*$"),   # last.first@example.com
    ("first_last", r"^([a-z0-9.]+)@.*$"),   # first_last@example.com
    ("flast", r"^([a-z0-9.]+)@.*$"),        # flast@example.com
]


class EmailScanner(BaseScanner):
    """Scan for email footprint across the clearnet."""

    name = "Email Scanner"
    category = ScannerCategory.EMAIL

    def scan(self, target: Target) -> list[Finding]:
        findings: list[Finding] = []

        if not target.email:
            return findings

        email = target.email.lower().strip()
        findings.extend(self._check_email_format(email))
        findings.extend(self._check_common_variations(email))
        findings.extend(self._check_breach_data(email))
        findings.extend(self._check_gravatar(email))
        findings.extend(self._check_leaked_on_pastes(email))
        findings.extend(self._check_professional_profiles(email))

        return findings

    def _check_email_format(self, email: str) -> list[Finding]:
        """Validate email address format and identify the pattern."""
        pattern = r"^([a-z0-9.]+)@([a-z0-9.-]+\.[a-z]{2,})$"
        match = re.match(pattern, email, re.IGNORECASE)

        if not match:
            return [
                Finding(
                    category=self.category,
                    title="Invalid Email Format",
                    description=f"The provided email address does not match standard format: {email}",
                    severity=Severity.MEDIUM,
                    details={"email": email},
                    scanner=self.name,
                )
            ]

        local_part = match.group(1)
        domain = match.group(2)
        is_common_provider = domain in KNOWN_PROVIDERS

        if local_part.count(".") >= 3:
            return [
                Finding(
                    category=self.category,
                    title="Unusual Email Structure",
                    description=(
                        f"The email address has an unusual structure with many "
                        f"dots ({local_part.count('.')}). This could indicate a "
                        "catch-all address or a poorly configured mailbox."
                    ),
                    severity=Severity.LOW,
                    details={"email": email, "dot_count": local_part.count(".")},
                    scanner=self.name,
                )
            ]

        if not is_common_provider:
            return [
                Finding(
                    category=self.category,
                    title="Custom Domain Email",
                    description=(
                        f"The email uses the domain '{domain}' which is not a "
                        "known public provider. Custom domain emails are more "
                        "likely to be associated with specific organizations, "
                        "making correlation across breaches easier."
                    ),
                    severity=Severity.INFO,
                    details={"email": email, "domain": domain, "is_custom": True},
                    scanner=self.name,
                )
            ]

        return [
            Finding(
                category=self.category,
                title="Standard Email Format",
                description=f"Email '{email}' follows a standard format and uses a known provider.",
                severity=Severity.INFO,
                details={"email": email},
                scanner=self.name,
            )
        ]

    def _check_common_variations(self, email: str) -> list[Finding]:
        """Identify common email variations that may also be in use."""
        match = re.match(r"^([a-z0-9.]+)@([a-z0-9.-]+\.[a-z]{2,})$", email, re.IGNORECASE)
        if not match:
            return []

        local = match.group(1)
        domain = match.group(2)

        variations = set()

        # Simple forms
        for fmt in [local, local.replace(".", ""), local.replace(".", "_"),
                     local.replace(".", "-"), local[:3], local[0] + local[-1]]:
            if len(fmt) >= 2 and fmt != local:
                variations.add(f"{fmt}@{domain}")

        # Check for dot-based variations (Gmail ignores dots)
        if domain == "gmail.com" or domain == "googlemail.com":
            bare = local.replace(".", "")
            variations.add(f"{bare}@{domain}")
            variations.add(f"{bare}@gmail.com")

        return [
            Finding(
                category=self.category,
                title="Email Alias Variations Identified",
                description=(
                    f"Found {len(variations)} common variations of this email "
                    "address that may also be in use. An attacker who compromises "
                    "one variation may gain access to the same inbox."
                ),
                severity=Severity.MEDIUM,
                details={
                    "primary_email": email,
                    "variations": list(variations)[:20],  # cap at 20
                },
                remediation=(
                    "Use a dedicated email address for each service. "
                    "Consider using email aliases (e.g., SimpleLogin, AnonAddy) "
                    "to avoid exposing your primary address."
                ),
                scanner=self.name,
            )
        ]

    def _check_breach_data(self, email: str) -> list[Finding]:
        """Check if the email appears in known data breaches (HIBP)."""
        try:
            url = "https://haveibeenpwned.com/api/v3/breachedaccount"
            headers = {
                "User-Agent": self.config.user_agent,
                "hibp-api-key": self.config.hibp_api_key or "",
            }
            resp = requests.get(url, params={"account": email}, headers=headers, timeout=self.config.timeout)

            if resp.status_code == 404:
                return [
                    Finding(
                        category=self.category,
                        title="No Breach Data Found",
                        description=(
                            f"The email '{email}' was not found in any known "
                            "breaches. This is a positive security indicator."
                        ),
                        severity=Severity.INFO,
                        details={"email": email, "breach_count": 0},
                        scanner=self.name,
                    )
                ]

            if resp.status_code == 401 or resp.status_code == 403:
                return [
                    Finding(
                        category=self.category,
                        title="HIBP API Key Required",
                        description=(
                            "HaveIBeenPwned API requires a subscription key (starting at $7/mo). "
                            "Add your key to config.yaml for breach checking."
                        ),
                        severity=Severity.LOW,
                        details={"api_status": "unauthorized"},
                        scanner=self.name,
                    )
                ]

            if resp.status_code == 429:
                return [
                    Finding(
                        category=self.category,
                        title="HIBP API Rate Limited",
                        description="Rate limit exceeded. Retry after a few minutes.",
                        severity=Severity.LOW,
                        details={"api_status": "rate_limited"},
                        scanner=self.name,
                    )
                ]

            if resp.status_code == 200:
                breaches = resp.json()
                return [
                    Finding(
                        category=self.category,
                        title="Email Found in Data Breaches",
                        description=(
                            f"The email '{email}' was found in {len(breaches)} "
                            "known data breach(es). This means credentials, emails, "
                            "or other personal data may be exposed on the dark web."
                        ),
                        severity=Severity.CRITICAL,
                        details={
                            "email": email,
                            "breach_count": len(breaches),
                            "breaches": [
                                {
                                    "name": b["Name"],
                                    "title": b.get("Title", "Unknown"),
                                    "date": b.get("BreachDate", "Unknown"),
                                    "data_classes": b.get("DataClasses", []),
                                    "is_verified": b.get("IsVerified", False),
                                    "is_fabricated": b.get("IsFabricated", False),
                                }
                                for b in breaches
                            ],
                        },
                        remediation=(
                            "1. Change passwords for all affected services immediately.\n"
                            "2. Enable multi-factor authentication (MFA) everywhere.\n"
                            "3. Use a password manager with unique passwords.\n"
                            "4. Monitor for suspicious account activity.\n"
                            "5. Consider using a credential monitoring service."
                        ),
                        scanner=self.name,
                    )
                ]
        except requests.Timeout:
            return [
                Finding(
                    category=self.category,
                    title="HIBP API Timed Out",
                    description="HaveIBeenPwned API did not respond in time. Try again later.",
                    severity=Severity.LOW,
                    details={"email": email, "error": "timeout"},
                    scanner=self.name,
                )
            ]
        except requests.RequestException as e:
            return [
                Finding(
                    category=self.category,
                    title="HIBP API Error",
                    description=f"Could not check breach data: {e}",
                    severity=Severity.LOW,
                    details={"email": email, "error": str(e)},
                    scanner=self.name,
                )
            ]

        return []

    def _check_gravatar(self, email: str) -> list[Finding]:
        """Check if a Gravatar profile is associated with the email."""
        import hashlib
        email_hash = hashlib.md5(email.strip().lower().encode()).hexdigest()
        url = f"https://en.gravatar.com/{email_hash}.json"

        try:
            resp = requests.get(url, timeout=self.config.timeout)
            if resp.status_code == 200:
                data = resp.json()
                profile = data.get("entry", [{}])[0]
                display_name = profile.get("displayName", "")
                profile_url = profile.get("entryUrl", "")

                return [
                    Finding(
                        category=self.category,
                        title="Gravatar Profile Found",
                        description=(
                            f"A Gravatar profile associated with '{email}' is publicly visible. "
                            f"Profile display name: '{display_name}'. "
                            "Gravatar can be used to correlate your email identity "
                            "across blog comments, WordPress sites, and other platforms."
                        ),
                        severity=Severity.MEDIUM,
                        details={
                            "email": email,
                            "display_name": display_name,
                            "profile_url": profile_url,
                        },
                        remediation=(
                            "Disable Gravatar by creating a free account and toggling "
                            "off the 'Display my profile publicly' setting."
                        ),
                        scanner=self.name,
                    )
                ]
        except (requests.RequestException, ValueError):
            pass

        return [
            Finding(
                category=self.category,
                title="No Gravatar Profile Found",
                description="No publicly visible Gravatar profile found for this email.",
                severity=Severity.INFO,
                details={"email": email, "gravatar_check": "negative"},
                scanner=self.name,
            )
        ]

    def _check_leaked_on_pastes(self, email: str) -> list[Finding]:
        """Check if the email appears on pastebin-like services."""
        findings = []

        services = {
            "Pastebin": "https://pastebin.com/search/all/{query}",
            "Pastie": "https://pastie.org/search?q={query}",
        }

        query = urllib.parse.quote(email)
        exposed_count = 0

        for service, url_template in services.items():
            try:
                url = url_template.format(query=query)
                resp = requests.get(url, headers={"User-Agent": self.config.user_agent},
                                    timeout=self.config.timeout, allow_redirects=True)
                if resp.status_code == 200 and email in resp.text:
                    exposed_count += 1
            except requests.RequestException:
                continue

        if exposed_count > 0:
            return [
                Finding(
                    category=self.category,
                    title="Email Found on Paste Sites",
                    description=(
                        f"The email was found on {exposed_count} paste site(s). "
                        "Paste sites are commonly used by attackers to distribute "
                        "stolen credentials and data."
                    ),
                    severity=Severity.HIGH,
                    details={"email": email, "paste_sites_found": exposed_count},
                    remediation=(
                        "1. Change affected passwords immediately.\n"
                        "2. Monitor services associated with the email.\n"
                        "3. Enable MFA on all accounts."
                    ),
                    scanner=self.name,
                )
            ]

        return [
            Finding(
                category=self.category,
                title="No Paste Site Leaks Detected",
                description="No evidence of this email appearing on public paste sites.",
                severity=Severity.INFO,
                details={"email": email},
                scanner=self.name,
            )
        ]

    def _check_professional_profiles(self, email: str) -> list[Finding]:
        """Check if the email is linked to professional network profiles."""
        findings = []

        platforms = {
            "LinkedIn": "https://www.linkedin.com",
            "GitHub": "https://github.com",
            "StackOverflow": "https://stackoverflow.com",
        }

        for platform, base_url in platforms.items():
            if platform == "GitHub":
                # GitHub search endpoint for user emails
                try:
                    url = f"https://github.com/search?q={urllib.parse.quote(email)}&type=users"
                    resp = requests.get(url, headers={"User-Agent": self.config.user_agent},
                                        timeout=self.config.timeout)
                    if resp.status_code == 200 and email.lower() in resp.text.lower():
                        findings.append(
                            Finding(
                                category=self.category,
                                title=f"{platform} Profile Linked to Email",
                                description=(
                                    f"An email address match was found on {platform}. "
                                    "Professional profiles can reveal employment history, "
                                    "skills, connections, and potentially sensitive info."
                                ),
                                severity=Severity.MEDIUM,
                                details={"email": email, "platform": platform, "url": base_url},
                                remediation=(
                                    f"Review your {platform} profile privacy settings. "
                                    "Consider limiting visible information."
                                ),
                                scanner=self.name,
                            )
                        )
                except requests.RequestException:
                    continue

        if not findings:
            return [
                Finding(
                    category=self.category,
                    title="No Professional Profile Matches Found",
                    description="No obvious profile matches found on major platforms for this email.",
                    severity=Severity.INFO,
                    details={"email": email},
                    scanner=self.name,
                )
            ]

        return findings

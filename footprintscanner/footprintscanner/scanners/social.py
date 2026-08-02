"""Social media footprint scanning — check platform presence."""

from __future__ import annotations

import re

import requests

from footprintscanner.config import Config
from footprintscanner.models import Finding, Severity, Target, ScannerCategory
from .base import BaseScanner


SOCIAL_PLATFORMS = [
    {"name": "Twitter/X", "url": "https://twitter.com/{}", "username": True},
    {"name": "Facebook", "url": "https://facebook.com/{}", "username": True},
    {"name": "Instagram", "url": "https://instagram.com/{}", "username": True},
    {"name": "LinkedIn", "url": "https://linkedin.com/in/{}", "username": True},
    {"name": "GitHub", "url": "https://github.com/{}", "username": True},
    {"name": "YouTube", "url": "https://youtube.com/@{}", "username": True},
    {"name": "TikTok", "url": "https://tiktok.com/@{}", "username": True},
    {"name": "Reddit", "url": "https://reddit.com/user/{}", "username": True},
    {"name": "Pinterest", "url": "https://pinterest.com/{}", "username": True},
    {"name": "Twitch", "url": "https://twitch.tv/{}", "username": True},
]


class SocialMediaScanner(BaseScanner):
    """Scan for social media profiles linked to a name or username."""

    name = "Social Media Scanner"
    category = ScannerCategory.SOCIAL_MEDIA

    def scan(self, target: Target) -> list[Finding]:
        findings: list[Finding] = []

        # Check by username
        if target.social_username or target.name:
            username = target.social_username or self._sanitize_for_username(target.name or "")
            findings.extend(self._check_usernames(username, target))

        # Check by name for professional profiles
        if target.name:
            findings.extend(self._check_professional_name(target.name))

        return findings

    def _sanitize_for_username(self, name: str) -> str:
        """Convert a name to a username-like string."""
        username = name.lower().strip()
        username = re.sub(r"[^a-z0-9._-]", "", username)
        username = re.sub(r"[._-]+", "", username)
        username = username[:30]
        return username

    def _check_usernames(self, username: str, target: Target) -> list[Finding]:
        """Check if a username exists on various platforms."""
        findings = []

        for platform in SOCIAL_PLATFORMS:
            try:
                url = platform["url"].format(username)
                resp = requests.head(url, headers={"User-Agent": self.config.user_agent},
                                     timeout=self.config.timeout, allow_redirects=True)

                if resp.status_code == 200:
                    # Profile exists!
                    details = {
                        "platform": platform["name"],
                        "url": resp.url,
                        "username": username,
                    }

                    # Check if profile is public
                    # For most platforms, 200 means accessible
                    findings.append(
                        Finding(
                            category=self.category,
                            title=f"Social Profile Found — {platform['name']}",
                            description=(
                                f"A profile with username '{username}' was found on "
                                f"{platform['name']}: {resp.url}\n\n"
                                "Public social media profiles can reveal personal "
                                "information, social connections, employment history, "
                                "and location data that can be used for social engineering."
                            ),
                            severity=Severity.MEDIUM,
                            details=details,
                            remediation=(
                                "1. Review privacy settings on this profile.\n"
                                "2. Limit visible personal information.\n"
                                "3. Consider using a pseudonym instead of your real name.\n"
                                "4. Regularly audit your digital footprint on social platforms."
                            ),
                            scanner=self.name,
                        )
                    )
                elif resp.status_code == 404:
                    pass  # Not found — expected
                elif resp.status_code in (403, 410):
                    # Might exist but require login
                    findings.append(
                        Finding(
                            category=self.category,
                            title=f"Social Profile Possibly Exists — {platform['name']}",
                            description=(
                                f"The URL {resp.url} returned {resp.status_code}. "
                                f"A profile for '{username}' may exist but requires "
                                "authentication to view."
                            ),
                            severity=Severity.MEDIUM,
                            details={
                                "platform": platform["name"],
                                "username": username,
                                "status_code": resp.status_code,
                                "url": resp.url,
                            },
                            scanner=self.name,
                        )
                    )
            except requests.RequestException:
                findings.append(
                    Finding(
                        category=self.category,
                        title=f"Check Failed — {platform['name']}",
                        description=f"Could not check {platform['name']} for username '{username}'.",
                        severity=Severity.LOW,
                        details={"platform": platform["name"], "username": username},
                        scanner=self.name,
                    )
                )

        return findings

    def _check_professional_name(self, name: str) -> list[Finding]:
        """Check for professional/academic profiles by name."""
        findings = []

        # Check Google Scholar-style academic footprint
        try:
            url = f"https://scholar.google.com/citations?view_op=search_authors&mauthors={name}"
            resp = requests.get(url, headers={"User-Agent": self.config.user_agent},
                                timeout=self.config.timeout, allow_redirects=True)
            if "author" in resp.url or "citations?" in resp.text:
                findings.append(
                    Finding(
                        category=self.category,
                        title="Academic Presence Detected",
                        description=(
                            f"An academic profile for '{name}' was found on Google Scholar. "
                            "Academic profiles can reveal research interests, affiliations, "
                            "and publications that could be useful to attackers for "
                            "targeted spear-phishing."
                        ),
                        severity=Severity.LOW,
                        details={"name": name, "platform": "Google Scholar"},
                        scanner=self.name,
                    )
                )
        except requests.RequestException:
            pass

        return findings

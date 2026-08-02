"""Search engine footprint scanning — what can be found about a target online."""

from __future__ import annotations

import re

import requests
import tldextract

from footprintscanner.config import Config
from footprintscanner.models import Finding, Severity, Target, ScannerCategory
from .base import BaseScanner


class SearchEngineScanner(BaseScanner):
    """Scan what's publicly discoverable about a target via search engines."""

    name = "Search Engine Scanner"
    category = ScannerCategory.SEARCH_ENGINE

    def scan(self, target: Target) -> list[Finding]:
        findings: list[Finding] = []

        if target.domain:
            findings.extend(self._scan_domain(domain=target.domain))
        if target.email:
            findings.extend(self._scan_email(email=target.email))
        if target.name:
            findings.extend(self._scan_name(name=target.name))
            findings.extend(self._scan_name_with_domain(name=target.name, domain=target.domain))

        return findings

    def _search_google(self, query: str, max_results: int = 10) -> list[dict]:
        """Simple Google search using public Dorks API (Shodan-like)."""
        results = []
        try:
            url = "https://html.duckduckgo.com/html/"
            params = {"q": query}
            headers = {"User-Agent": self.config.user_agent}
            resp = requests.get(url, params=params, headers=headers, timeout=self.config.timeout)

            if resp.status_code == 200:
                # Extract results from DuckDuckGo HTML
                pattern = r'<a class="result__a" href="(.*?)"[^>]*>(.*?)</a>'
                links = re.findall(pattern, resp.text)
                for link, title in links[:max_results]:
                    if link.startswith("http"):
                        results.append({"title": title.strip(), "url": link})

            # Also try Bing
            try:
                bing_url = "https://www.bing.com/search"
                bing_params = {"q": query}
                bing_headers = {"User-Agent": self.config.user_agent}
                bing_resp = requests.get(
                    bing_url, params=bing_params, headers=bing_headers,
                    timeout=self.config.timeout, allow_redirects=True
                )
                bing_pattern = r'<li class="b_algo"><h2><a href="(.*?)"[^>]*>(.*?)</a></h2>'
                bing_results = re.findall(bing_pattern, bing_resp.text)
                for link, title in bing_results[:max_results]:
                    title = re.sub(r'<[^>]+>', '', title).strip()
                    if link.startswith("http") and not any(r["url"] == link for r in results):
                        results.append({"title": title, "url": link})
            except requests.RequestException:
                pass
        except requests.RequestException:
            pass

        return results

    def _scan_domain(self, domain: str) -> list[Finding]:
        """Search for what's publicly indexed about a domain."""
        findings = []

        queries = [
            f'site:{domain}',
            f'"@{domain}"',
            f'site:{domain} "login"',
            f'site:{domain} "password"',
            f'site:{domain} "admin"',
        ]

        for query in queries:
            try:
                results = self._search_google(query, max_results=5)
                if results:
                    findings.append(
                        Finding(
                            category=self.category,
                            title=f"Public Results for: {query}",
                            description=(
                                f"Found {len(results)} public result(s) for search query: "
                                f'"{query}"\n\n' + "\n".join(
                                    f"  - {r['title']}" for r in results[:5]
                                )
                            ),
                            severity=Severity.INFO,
                            details={"query": query, "result_count": len(results)},
                            scanner=self.name,
                        )
                    )
            except Exception:
                continue

        return findings

    def _scan_email(self, email: str) -> list[Finding]:
        """Search for email addresses online."""
        findings = []

        queries = [
            f'"{email}"',
            f'"{email}" "password"',
            f'"{email}" "leak"',
            f'"{email}" "breach"',
        ]

        for query in queries:
            try:
                results = self._search_google(query, max_results=3)
                if results:
                    findings.append(
                        Finding(
                            category=self.category,
                            title=f"Email Search Results: {query}",
                            description=(
                                f"The email address appears in {len(results)} "
                                f"public web result(s):\n\n" + "\n".join(
                                    f"  - {r['title']}" for r in results[:3]
                                )
                            ),
                            severity=Severity.HIGH,
                            details={
                                "query": query,
                                "result_count": len(results),
                                "results": results[:5],
                            },
                            remediation=(
                                "1. Request removal of personal data from search results.\n"
                                "2. Use data removal services.\n"
                                "3. Consider using a disposable email for signups."
                            ),
                            scanner=self.name,
                        )
                    )
            except Exception:
                continue

        return findings

    def _scan_name(self, name: str) -> list[Finding]:
        """Search for a person's name online."""
        findings = []

        query = f'"{name}"'
        try:
            results = self._search_google(query, max_results=10)
            if results:
                findings.append(
                    Finding(
                        category=self.category,
                        title=f'Personal Name Found Online — "{name}"',
                        description=(
                            f"The name '{name}' appears in {len(results)} "
                            f"public web result(s). A name that returns many "
                            f"results is a larger digital footprint and increases "
                            f"the risk of identity correlation and social engineering."
                        ),
                        severity=Severity.MEDIUM,
                        details={
                            "name": name,
                            "result_count": len(results),
                            "sample_results": results[:5],
                        },
                        remediation=(
                            "1. Request data removal from people-search sites.\n"
                            "2. Use privacy-friendly aliases online.\n"
                            "3. Audit social media profiles for name exposure.\n"
                            "4. Monitor Google for your name with alerts."
                        ),
                        scanner=self.name,
                    )
                )
        except Exception:
            pass

        return findings

    def _scan_name_with_domain(self, name: str, domain: str | None) -> list[Finding]:
        """Search for name + domain combos (employee profiles, etc.)."""
        if not domain:
            return []

        findings = []
        query = f'"{name}" "{domain}"'
        try:
            results = self._search_google(query, max_results=5)
            if results:
                findings.append(
                    Finding(
                        category=self.category,
                        title=f"Employee/Person Found: {name} @ {domain}",
                        description=(
                            f"Search for '{name}' at '{domain}' found "
                            f"{len(results)} result(s). This indicates a "
                            f"person is publicly associated with this organization, "
                            f"which can be used for targeted social engineering."
                        ),
                        severity=Severity.MEDIUM,
                        details={
                            "query": query,
                            "result_count": len(results),
                            "sample_results": results[:5],
                        },
                        remediation=(
                            "Encourage employees to use privacy settings on social media. "
                            "Consider a social media policy that limits what employees "
                            "share about their employer publicly."
                        ),
                        scanner=self.name,
                    )
                )
        except Exception:
            pass

        return findings

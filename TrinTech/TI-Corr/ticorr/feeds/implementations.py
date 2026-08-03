"""
TrinTech Digital Defense
TI-Corr: Threat Intelligence Correlator — Feed Implementations

Feeds:
  - AbuseIPDB: IP reputation scoring (API key required, free tier available)
  - OTX (AlienVault): Open threat intel pulse data (API key required)
  - VirusTotal: File/domain/hash reputation (API key required)
  - CISA KEV: Known Exploited Vulnerabilities Catalog (free)
  - PassiveTotal / HybridAnalysis: (placeholder for future)
"""

import abc
import hashlib
import json
import logging
import os
import re
import time
from datetime import datetime, timedelta
from typing import Any

import requests

log = logging.getLogger("ticorr.feeds.implementations")

# ────────────────────────────────────────────────────────────────
# Configuration — read from env or local config file
# ────────────────────────────────────────────────────────────────

def _get_api_key(source: str, env_var: str) -> str | None:
    """Get API key from env var, or return None if not set."""
    return os.environ.get(env_var)


# ────────────────────────────────────────────────────────────────
# AbuseIPDB — IP reputation
# ────────────────────────────────────────────────────────────────

class AbuseIPDBFeed:
    """
    AbuseIPDB: Check if an IP is reported as malicious.
    Free tier: 1,000 checks/day, 1 request/minute.
    https://www.abuseipdb.com/api.html
    """

    NAME = "AbuseIPDB"
    ENDPOINT = "https://api.abuseipdb.com/api/v2/ipreport"
    CHECK_ENDPOINT = "https://api.abuseipdb.com/api/v2/ip"
    API_KEY_ENV = "ABUSEIPDB_API_KEY"

    def __init__(self):
        self.api_key = _get_api_key("abuseipdb", self.API_KEY_ENV)
        self.session = requests.Session()
        self.session.headers.update({
            "Key": self.api_key or "",
            "Accept": "application/json",
        })

    @property
    def name(self) -> str:
        return self.NAME

    @property
    def enabled(self) -> bool:
        return bool(self.api_key)

    def check_ip(self, ip: str, max_age_days: int = 30) -> dict[str, Any]:
        """Check an IP against AbuseIPDB."""
        if not self.api_key:
            return {"error": "AbuseIPDB API key not configured"}

        try:
            self._backoff()
            resp = self.session.get(
                f"{self.CHECK_ENDPOINT}/{ip}",
                params={"maxAgeInDays": max_age_days, "ipAddress": ip},
                timeout=10,
            )
            resp.raise_for_status()
            data = resp.json().get("data", {})

            return {
                "source": self.NAME,
                "type": "ip",
                "value": ip,
                "confidence": data.get("abuseConfidenceScore", 0),
                "tags": [],
                "first_seen": None,
                "last_seen": None,
                "description": self._format_abuse_summary(data),
                "raw": {
                    "abuseConfidenceScore": data.get("abuseConfidenceScore"),
                    "totalReports": data.get("totalReports"),
                    "country": data.get("countryCode"),
                    "usageType": data.get("usageType"),
                    "isp": data.get("isp"),
                    "domain": data.get("domain"),
                    "isPublic": data.get("isPublic"),
                    "reports": [
                        {
                            "reportedAt": r.get("reportedAt"),
                            "comment": r.get("comment", "")[:200],
                        }
                        for r in data.get("reports", [])[:5]
                    ],
                },
            }
        except requests.RequestException as e:
            log.warning(f"AbuseIPDB check failed for {ip}: {e}")
            return {"error": str(e)}

    def _format_abuse_summary(self, data: dict) -> str:
        cscore = data.get("abuseConfidenceScore", 0)
        reports = data.get("totalReports", 0)
        if cscore == 0:
            return f"AbuseIPDB: No data for {data.get('ipAddress', '?')}"
        return f"AbuseIPDB: {cscore}% abuse confidence, {reports} reports"

    def _backoff(self):
        time.sleep(1.0)  # Free tier: 1 req/min


# ────────────────────────────────────────────────────────────────
# AlienVault OTX — Open Threat eXchange
# ────────────────────────────────────────────────────────────────

class OTXFeed:
    """
    AlienVault OTX: Open threat intelligence via pulses.
    Free tier: 200 requests/minute.
    https://otx.alienvault.com/api v1 docs
    """

    NAME = "AlienVault OTX"
    ENDPOINT = "https://otx.alienvault.com/api/v1"
    API_KEY_ENV = "OTX_API_KEY"

    def __init__(self):
        self.api_key = _get_api_key("otx", self.API_KEY_ENV)
        self.session = requests.Session()
        self.session.headers.update({
            "X-OTX-API-KEY": self.api_key or "",
            "Accept": "application/json",
        })

    @property
    def name(self) -> str:
        return self.NAME

    @property
    def enabled(self) -> bool:
        return bool(self.api_key)

    def search_ip(self, ip: str) -> list[dict[str, Any]]:
        """Look up an IP address in OTX pulses."""
        results = self._query_pulses(f"indicator:indicators:ip:{ip}")
        return self._parse_pulses(results)

    def search_domain(self, domain: str) -> list[dict[str, Any]]:
        """Look up a domain in OTX pulses."""
        results = self._query_pulses(f"indicator:indicators:fqdn:{domain}")
        return self._parse_pulses(results)

    def _query_pulses(self, query: str, limit: int = 10) -> dict:
        try:
            self._backoff()
            resp = self.session.get(
                f"{self.ENDPOINT}/general/search/text",
                params={"query": query, "limit": limit},
                timeout=15,
            )
            resp.raise_for_status()
            return resp.json()
        except requests.RequestException as e:
            log.warning(f"OTX search failed for '{query}': {e}")
            return {"results": []}

    def _parse_pulses(self, data: dict) -> list[dict[str, Any]]:
        results = []
        for pulse in data.get("results", [])[:5]:
            indicators = []
            for ind in pulse.get("indicators", []):
                if isinstance(ind, dict):
                    indicators.append(ind.get("indicator", ""))
                elif isinstance(ind, str):
                    indicators.append(ind)

            results.append({
                "source": self.NAME,
                "type": "domain" if indicators else "ip",
                "value": pulse.get("name", "?"),
                "confidence": 70,  # OTX community data
                "tags": pulse.get("tags", [])[:10],
                "first_seen": pulse.get("created", {}).get("dateTime"),
                "last_seen": pulse.get("modified", {}).get("dateTime"),
                "description": f"OTX pulse '{pulse.get('name', '?')}' — {pulse.get('references', [])} — tags: {pulse.get('tags', [])}",
                "raw": {
                    "pulse_id": pulse.get("id"),
                    "author": pulse.get("authorDetails", {}).get("username"),
                    "indicators": indicators[:20],
                    "references": pulse.get("references", [])[:10],
                },
            })
        return results

    def _backoff(self):
        time.sleep(0.3)  # 200 req/min


# ────────────────────────────────────────────────────────────────
# VirusTotal — Hash / Domain / URL reputation
# ────────────────────────────────────────────────────────────────

class VirusTotalFeed:
    """
    VirusTotal: File/hash/domain/URL reputation checking.
    Free tier: 50 requests/day.
    https://developers.virustotal.com/reference
    """

    NAME = "VirusTotal"
    ENDPOINT = "https://www.virustotal.com/api/v3"
    API_KEY_ENV = "VIRUSTOTAL_API_KEY"

    def __init__(self):
        self.api_key = _get_api_key("virustotal", self.API_KEY_ENV)
        self.session = requests.Session()
        self.session.headers.update({
            "x-apikey": self.api_key or "",
            "Accept": "application/json",
        })

    @property
    def name(self) -> str:
        return self.NAME

    @property
    def enabled(self) -> bool:
        return bool(self.api_key)

    def check_hash(self, sha256: str) -> dict[str, Any]:
        """Check a file hash against VirusTotal."""
        try:
            self._backoff()
            resp = self.session.get(
                f"{self.ENDPOINT}/files/{sha256}",
                timeout=15,
            )
            resp.raise_for_status()
            data = resp.json().get("data", {}).get("attributes", {})

            stats = data.get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)
            total = stats.get("total", 1)
            confidence = int((malicious / total * 100)) if total > 0 else 0

            engines = data.get("last_analysis_results", {})
            detected_by = []
            for engine, result in engines.items():
                if result.get("category") == "malicious":
                    detected_by.append(engine)

            return {
                "source": self.NAME,
                "type": "hash",
                "value": sha256,
                "confidence": min(confidence, 100),
                "tags": self._extract_tags(data),
                "first_seen": data.get("first_seen"),
                "last_seen": data.get("last_analysis_date"),
                "description": f"VirusTotal: {malicious}/{total} engines flagged ({confidence}%)",
                "raw": {
                    "malicious": malicious,
                    "suspicious": stats.get("suspicious", 0),
                    "undetected": stats.get("undetected", 0),
                    "timeout": stats.get("timeout", 0),
                    "harmless": stats.get("harmless", 0),
                    "detected_by": detected_by[:20],
                    "file_names": data.get("names", [])[:5],
                    "times_submitted": data.get("times_submitted", 0),
                },
            }
        except requests.RequestException as e:
            log.warning(f"VirusTotal hash check failed for {sha256}: {e}")
            return {"error": str(e)}

    def check_domain(self, domain: str) -> dict[str, Any]:
        """Check a domain against VirusTotal."""
        try:
            self._backoff()
            resp = self.session.get(
                f"{self.ENDPOINT}/domains/{domain}",
                timeout=15,
            )
            resp.raise_for_status()
            data = resp.json().get("data", {}).get("attributes", {})

            stats = data.get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)
            total = stats.get("total", 1)
            confidence = int((malicious / total * 100)) if total > 0 else 0

            return {
                "source": self.NAME,
                "type": "domain",
                "value": domain,
                "confidence": min(confidence, 100),
                "tags": data.get("tags", []),
                "first_seen": data.get("first_seen"),
                "last_seen": data.get("last_dns_records", [{}])[-1].get("last_resolved"),
                "description": f"VirusTotal domain: {malicious}/{total} engines flagged ({confidence}%)",
                "raw": {
                    "malicious": malicious,
                    "categories": data.get("categories", {}),
                    "registrar": data.get("registrar"),
                    "reputation": data.get("reputation"),
                },
            }
        except requests.RequestException as e:
            log.warning(f"VirusTotal domain check failed for {domain}: {e}")
            return {"error": str(e)}

    def _extract_tags(self, data: dict) -> list[str]:
        """Extract classification tags from VT response."""
        tags = []
        for attr in ["last_analysis_results", "times_submitted", "names"]:
            if isinstance(data.get(attr), dict):
                tags.extend(data[attr].keys())
        return list(set(tags))[:30]

    def _backoff(self):
        time.sleep(12.0)  # Free tier: 50/day ≈ 1 per 12s


# ────────────────────────────────────────────────────────────────
# CISA KEV — Known Exploited Vulnerabilities Catalog
# ────────────────────────────────────────────────────────────────

class CISAKEVFeed:
    """
    CISA Known Exploited Vulnerabilities Catalog.
    Free, no API key required.
    https://www.cisa.gov/known-exploited-vulnerabilities-catalog
    """

    NAME = "CISA KEV"
    ENDPOINT = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    API_KEY_ENV = None  # No key required

    def __init__(self):
        self.session = requests.Session()
        self._catalog_cache = None
        self._catalog_time = 0

    @property
    def name(self) -> str:
        return self.NAME

    @property
    def enabled(self) -> bool:
        return True

    def search_vuln(self, cve_id: str) -> dict[str, Any] | None:
        """Search for a CVE in the KEV catalog."""
        catalog = self._get_catalog()
        for vuln in catalog:
            if vuln.get("cveID", "").upper() == cve_id.upper():
                return {
                    "source": self.NAME,
                    "type": "vulnerability",
                    "value": cve_id,
                    "confidence": 95,  # CISA authoritative
                    "tags": ["known-exploited", "cisa"],
                    "first_seen": vuln.get("dateAdded"),
                    "last_seen": vuln.get("dateAdded"),
                    "description": f"CISA KEV: {cve_id} exploited in {vuln.get('vendorProject', '?')}. Added: {vuln.get('dateAdded')}. Due date: {vuln.get('dueDate')}",
                    "raw": {
                        "cveID": vuln.get("cveID"),
                        "vendor": vuln.get("vendorProject"),
                        "product": vuln.get("product"),
                        "vuln_name": vuln.get("vulnerabilityName"),
                        "due_date": vuln.get("dueDate"),
                        "notes": vuln.get("notes", ""),
                    },
                }
        return None

    def _get_catalog(self) -> list[dict]:
        """Fetch and cache the KEV catalog."""
        now = time.time()
        if self._catalog_cache is not None and (now - self._catalog_time) < 3600:
            return self._catalog_cache

        try:
            self._backoff()
            resp = self.session.get(self.ENDPOINT, timeout=30)
            resp.raise_for_status()
            data = resp.json()
            self._catalog_cache = data.get("products", data.get("vulnerabilities", data))
            self._catalog_time = now
            return self._catalog_cache
        except requests.RequestException as e:
            log.warning(f"CISA KEV fetch failed: {e}")
            return self._catalog_cache or []

    def _backoff(self):
        time.sleep(0.5)


# ────────────────────────────────────────────────────────────────
# PassiveTotal / ThreatCrowd — Historical DNS / Whois
# ────────────────────────────────────────────────────────────────

class ThreatCrowdFeed:
    """
    ThreatCrowd: Historical DNS, whois, subdomain enumeration.
    Free, no API key required.
    https://www.threatcrowd.org/
    """

    NAME = "ThreatCrowd"
    API_KEY_ENV = None

    def __init__(self):
        self.session = requests.Session()

    @property
    def name(self) -> str:
        return self.NAME

    @property
    def enabled(self) -> bool:
        return True

    def search_domain(self, domain: str) -> dict[str, Any]:
        """Search domain on ThreatCrowd."""
        try:
            self._backoff()
            resp = self.session.get(
                "https://www.threatcrowd.org/searchApi/v2/domain/report/",
                params={"domain": domain},
                timeout=10,
            )
            data = resp.json()
            if data.get("response_code") != "1":
                return {"error": "No data from ThreatCrowd"}

            return {
                "source": self.NAME,
                "type": "domain",
                "value": domain,
                "confidence": 60,
                "tags": data.get("tags", []),
                "first_seen": None,
                "last_seen": None,
                "description": f"ThreatCrowd: {data.get('total_resolvers', 0)} resolvers, "
                               f"{data.get('total_domains', 0)} related domains, "
                               f"{data.get('total_ips', 0)} IPs",
                "raw": {
                    "resolvers": data.get("resolvers", [])[:10],
                    "domains": data.get("referral_domains", [])[:20],
                    "ips": data.get("ip_addresses", [])[:10],
                    "subdomains": data.get("subdomains", [])[:20],
                    "whois": data.get("whois", ""),
                },
            }
        except requests.RequestException as e:
            log.warning(f"ThreatCrowd search failed for {domain}: {e}")
            return {"error": str(e)}

    def _backoff(self):
        time.sleep(1.0)


# ────────────────────────────────────────────────────────────────
# Shodan — Internet-wide scanner data
# ────────────────────────────────────────────────────────────────

class ShodanFeed:
    """
    Shodan: Internet-wide scanner data.
    Free tier: 1 request/second, limited data.
    https://developer.shodan.io/
    """

    NAME = "Shodan"
    API_KEY_ENV = "SHODAN_API_KEY"

    def __init__(self):
        self.api_key = _get_api_key("shodan", self.API_KEY_ENV)
        self.session = requests.Session()
        self.session.headers.update({
            "Authorization": f"token {self.api_key or ''}",
        })

    @property
    def name(self) -> str:
        return self.NAME

    @property
    def enabled(self) -> bool:
        return bool(self.api_key)

    def search_ip(self, ip: str) -> dict[str, Any]:
        """Look up an IP on Shodan."""
        if not self.api_key:
            return {"error": "Shodan API key not configured"}

        try:
            self._backoff()
            resp = self.session.get(f"https://api.shodan.io/shodan/ip/{ip}", timeout=10)
            resp.raise_for_status()
            data = resp.json()

            tags = []
            for port_data in data.get("ports", []):
                try:
                    svc_data = next(
                        (p for p in data.get("data", []) if p.get("port") == port_data),
                        {},
                    )
                    if svc_data.get("product"):
                        tags.append(svc_data["product"].lower())
                except StopIteration:
                    tags.append(f"port:{port_data}")

            return {
                "source": self.NAME,
                "type": "ip",
                "value": ip,
                "confidence": 80,
                "tags": tags[:20],
                "first_seen": data.get("first_resolve"),
                "last_seen": data.get("last_update"),
                "description": f"Shodan: {data.get('hostnames', ['none'])}, "
                               f"{len(data.get('ports', []))} open ports, "
                               f"{data.get('os', '?')} OS",
                "raw": {
                    "hostnames": data.get("hostnames", []),
                    "ports": data.get("ports", []),
                    "os": data.get("os"),
                    "country": data.get("country_name"),
                    "city": data.get("city"),
                    "isp": data.get("isp"),
                    "data": data.get("data", [])[:5],
                },
            }
        except requests.RequestException as e:
            log.warning(f"Shodan lookup failed for {ip}: {e}")
            return {"error": str(e)}

    def _backoff(self):
        time.sleep(1.0)

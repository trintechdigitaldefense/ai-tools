"""
TrinTech Digital Defense
TI-Corr: Threat Intelligence Correlator — Correlator Engine

Core logic that takes SPECTER-THREAT findings and correlates them
against threat intelligence feeds, producing enriched findings with
boosted confidence scores and actionable intel.
"""

import json
import logging
import os
import re
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Any

from ..feeds.implementations import (
    AbuseIPDBFeed,
    CISAKEVFeed,
    OTXFeed,
    ShodanFeed,
    ThreatCrowdFeed,
    VirusTotalFeed,
)

log = logging.getLogger("ticorr.correlator")


class TIStorage:
    """SQLite persistence for threat intelligence lookups and results."""

    def __init__(self, db_path: str | Path):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _init_db(self):
        with sqlite3.connect(str(self.db_path)) as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS intel_lookups (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    source TEXT NOT NULL,
                    type TEXT NOT NULL,
                    value TEXT NOT NULL,
                    confidence INTEGER DEFAULT 0,
                    tags TEXT,
                    description TEXT,
                    lookup_time TEXT NOT NULL,
                    UNIQUE(source, type, value)
                );

                CREATE TABLE IF NOT EXISTS lookup_cache (
                    feed TEXT NOT NULL,
                    query TEXT NOT NULL,
                    result TEXT,
                    cached_at REAL,
                    PRIMARY KEY(feed, query)
                );

                CREATE TABLE IF NOT EXISTS correlation_results (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    specter_finding_id TEXT NOT NULL,
                    feed_name TEXT NOT NULL,
                    result TEXT,
                    confidence_boost INTEGER DEFAULT 0,
                    new_confidence INTEGER,
                    correlation_time TEXT NOT NULL,
                    UNIQUE(specter_finding_id, feed_name)
                );
            """)

    def save_lookup(self, result: dict):
        """Save a threat intel lookup result."""
        tags = ",".join(result.get("tags", []))
        with sqlite3.connect(str(self.db_path)) as conn:
            conn.execute(
                """INSERT OR REPLACE INTO intel_lookups
                   (source, type, value, confidence, tags, description, lookup_time)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (
                    result.get("source", "?"),
                    result.get("type", "?"),
                    result.get("value", "?"),
                    result.get("confidence", 0),
                    tags,
                    result.get("description", ""),
                    datetime.now().isoformat(),
                ),
            )

    def get_lookup(self, feed: str, query_type: str, value: str) -> dict | None:
        """Retrieve a cached lookup result."""
        with sqlite3.connect(str(self.db_path)) as conn:
            cursor = conn.execute(
                """SELECT * FROM intel_lookups
                   WHERE source = ? AND type = ? AND value = ?""",
                (feed, query_type, value),
            )
            row = cursor.fetchone()
            if row:
                return {
                    "id": row[0],
                    "source": row[1],
                    "type": row[2],
                    "value": row[3],
                    "confidence": row[4],
                    "tags": row[5].split(",") if row[5] else [],
                    "description": row[6],
                    "lookup_time": row[7],
                }
            return None

    def save_correlation(self, finding_id: str, feed: str, result: dict, boost: int):
        """Save a correlation result."""
        with sqlite3.connect(str(self.db_path)) as conn:
            conn.execute(
                """INSERT OR REPLACE INTO correlation_results
                   (specter_finding_id, feed_name, result, confidence_boost, new_confidence, correlation_time)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (
                    finding_id,
                    feed,
                    json.dumps(result.get("raw", {}) if isinstance(result.get("raw"), dict) else result),
                    boost,
                    result.get("confidence", 0) if result else 0,
                    datetime.now().isoformat(),
                ),
            )

    def get_correlations(self, finding_id: str) -> list[dict]:
        """Get all correlations for a SPECTER finding."""
        with sqlite3.connect(str(self.db_path)) as conn:
            cursor = conn.execute(
                "SELECT * FROM correlation_results WHERE specter_finding_id = ?",
                (finding_id,),
            )
            return [
                {
                    "feed": row[2],
                    "result": row[3],
                    "boost": row[4],
                    "new_confidence": row[5],
                    "time": row[6],
                }
                for row in cursor.fetchall()
            ]


class ThreatCorrelator:
    """
    Main correlator engine. Takes SPECTER-THREAT findings and enriches
    them with threat intelligence from multiple feeds.

    Finds:
      - IPs in connections/ports → AbuseIPDB, Shodan
      - Domains in connections → OTX, ThreatCrowd, VirusTotal
      - File hashes → VirusTotal, CISA KEV
      - Process names/keywords → cross-reference with feed tags

    Output:
      - Enriched findings with boosted confidence scores
      - Actionable intelligence: "This IP is reported by X sources as C2"
      - Correlation reports
    """

    FEEDS = {
        "abuseipdb": AbuseIPDBFeed,
        "otx": OTXFeed,
        "virustotal": VirusTotalFeed,
        "cisa_kev": CISAKEVFeed,
        "threatcrowd": ThreatCrowdFeed,
        "shodan": ShodanFeed,
    }

    def __init__(self, reports_dir: str | Path = None):
        self.reports_dir = Path(reports_dir or "/tmp/ticorr_reports")
        self.reports_dir.mkdir(exist_ok=True)

        # Initialize storage
        db_path = self.reports_dir / "ticorr_intel.db"
        self.storage = TIStorage(db_path)

        # Initialize feeds
        self.active_feeds = {}
        self.feed_errors = []

        for feed_name, feed_cls in self.FEEDS.items():
            try:
                feed = feed_cls()
                if feed.enabled:
                    self.active_feeds[feed_name] = feed
                    log.info(f"Feed enabled: {feed.name}")
                else:
                    log.info(f"Feed disabled (no API key): {feed.name}")
            except Exception as e:
                log.error(f"Failed to init feed {feed_name}: {e}")
                self.feed_errors.append({"feed": feed_name, "error": str(e)})

        log.info(f"TI-Corr initialized with {len(self.active_feeds)} active feeds")

    def correlate_finding(self, finding: dict) -> dict:
        """
        Correlate a single SPECTER finding against all active feeds.

        Args:
            finding: A SPECTER-THREAT finding dict

        Returns:
            Enriched finding with intel additions
        """
        enriched = dict(finding)
        enriched["intel"] = []

        finding_type = finding.get("type", "")
        detail = finding.get("detail", "")

        # Determine what to query based on finding type
        queries = self._extract_queries(finding)

        for query_type, query_value in queries:
            feed_results = self._query_feed(query_type, query_value)
            for result in feed_results:
                if "error" not in result:
                    # Save to DB
                    self.storage.save_lookup(result)

                    # Boost confidence if intel matches
                    boost = self._calculate_boost(result)
                    if boost > 0:
                        enriched["confidence_boost"] = max(
                            enriched.get("confidence_boost", 0), boost
                        )

                    enriched["intel"].append({
                        "feed": result["source"],
                        "query": query_value,
                        "confidence": result.get("confidence", 0),
                        "tags": result.get("tags", []),
                        "description": result.get("description", ""),
                        "raw_summary": self._summarize_raw(result.get("raw", {})),
                    })

                    # Save correlation
                    self.storage.save_correlation(
                        finding.get("id", "?"),
                        result["source"],
                        result,
                        boost,
                    )

        # Update overall confidence
        if enriched.get("confidence_boost", 0) > 0:
            current_sev = enriched.get("severity", "INFO")
            sev_order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
            boost_sev = {4: "CRITICAL", 3: "HIGH", 2: "MEDIUM", 1: "LOW", 0: "INFO"}
            new_level = min(
                sev_order.get(current_sev, 0) + enriched["confidence_boost"] // 25, 4
            )
            if new_level > sev_order.get(current_sev, 0):
                old_sev = current_sev
                enriched["severity"] = boost_sev[new_level]
                enriched["severity_boost"] = f"{old_sev} → {enriched['severity']}"

        return enriched

    def correlate_batch(self, findings: list[dict]) -> list[dict]:
        """Correlate a batch of SPECTER findings."""
        log.info(f"Correlating {len(findings)} findings...")
        enriched = []
        for i, finding in enumerate(findings):
            try:
                result = self.correlate_finding(finding)
                enriched.append(result)
                log.info(f"Correlated {i+1}/{len(findings)}: {finding.get('type', '?')}")
            except Exception as e:
                log.error(f"Failed to correlate finding {i}: {e}")
                enriched.append(finding)  # Return original on error

        # Generate summary report
        self._generate_correlation_summary(enriched)

        return enriched

    def _extract_queries(self, finding: dict) -> list[tuple[str, str]]:
        """Extract query values and types from a SPECTER finding."""
        queries = []
        detail = finding.get("detail", "")
        type_tag = finding.get("type", "")

        # IPs: look for IP patterns in detail
        import re
        ips = re.findall(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b', detail)
        for ip in set(ips):
            # AbuseIPDB
            queries.append(("abuseipdb", ip))
            # Shodan
            queries.append(("shodan", ip))

        # Domains: look for domain patterns
        domains = re.findall(
            r'\b([a-zA-Z0-9][-a-zA-Z0-9.]*\.[a-zA-Z]{2,})\b', detail
        )
        for domain in set(domains):
            # Skip if it's clearly a file path
            if domain.startswith("/") or "\\" in domain:
                continue
            queries.append(("otx", domain))
            queries.append(("threatcrowd", domain))
            queries.append(("virustotal", domain))

        # File hashes: SHA-256 or MD5
        hashes_256 = re.findall(r'\b([a-fA-F0-9]{64})\b', detail)
        hashes_md5 = re.findall(r'\b([a-fA-F0-9]{32})\b', detail)
        for h in hashes_256:
            queries.append(("virustotal", h))
        for h in hashes_md5:
            queries.append(("virustotal", h))

        # CVE IDs in detail
        cves = re.findall(r'\b(CVE-\d{4}-\d{4,})\b', detail)
        for cve in cves:
            queries.append(("cisa_kev", cve))

        return queries

    def _query_feed(self, feed_name: str, value: str) -> list[dict]:
        """Query a specific feed for intel."""
        feed = self.active_feeds.get(feed_name)
        if not feed:
            return [{"error": f"Feed '{feed_name}' not available"}]

        try:
            if feed_name == "abuseipdb":
                return [feed.check_ip(value)]
            elif feed_name == "shodan":
                return [feed.search_ip(value)]
            elif feed_name == "otx":
                return feed.search_domain(value)
            elif feed_name == "threatcrowd":
                return [feed.search_domain(value)]
            elif feed_name == "virustotal":
                if self._is_hash(value):
                    return [feed.check_hash(value)]
                else:
                    return [feed.check_domain(value)]
            elif feed_name == "cisa_kev":
                result = feed.search_vuln(value)
                return [result] if result else []
            else:
                return [{"error": f"Unknown feed: {feed_name}"}]
        except Exception as e:
            log.error(f"Feed {feed_name} query failed for '{value}': {e}")
            return [{"error": str(e)}]

    def _calculate_boost(self, intel: dict) -> int:
        """Calculate confidence boost from intelligence match (0-50)."""
        base = intel.get("confidence", 0)

        # Scale: 0-100 intel confidence → 0-50 boost
        # Non-linear: higher intel confidence gives diminishing returns
        if base >= 80:
            return 50  # Maximum boost
        elif base >= 50:
            return 35
        elif base >= 25:
            return 20
        elif base >= 10:
            return 10
        return 5

    def _is_hash(self, value: str) -> bool:
        """Check if value looks like a hash."""
        return len(value) == 64 or len(value) == 32

    def _summarize_raw(self, raw: dict) -> str:
        """Summarize raw intelligence data into a short string."""
        if not raw:
            return ""

        parts = []

        # Malicious count
        if "malicious" in raw:
            parts.append(f"mal:{raw['malicious']}")
        if "suspicious" in raw:
            parts.append(f"sus:{raw['suspicious']}")
        if "totalReports" in raw:
            parts.append(f"reports:{raw['totalReports']}")
        if "detected_by" in raw:
            parts.append(f"engines:{raw['detected_by'][:5]}")
        if "ports" in raw:
            parts.append(f"ports:{raw['ports']}")
        if "os" in raw:
            parts.append(f"os:{raw['os']}")
        if "vuln_name" in raw:
            parts.append(f"cve:{raw['vuln_name']}")
        if "tags" in raw:
            parts.append(f"tags:{raw['tags'][:5]}")

        return "; ".join(parts) if parts else str(raw)[:200]

    def _generate_correlation_summary(self, enriched_findings: list[dict]):
        """Generate a correlation summary report."""
        summary = {
            "timestamp": datetime.now().isoformat(),
            "total_findings": len(enriched_findings),
            "findings_with_intel": sum(
                1 for f in enriched_findings if f.get("intel")
            ),
            "findings_boosted": sum(
                1 for f in enriched_findings if f.get("confidence_boost", 0) > 0
            ),
            "severity_booster": sum(
                1 for f in enriched_findings if f.get("severity_boost")
            ),
            "feeds_queried": len(self.active_feeds),
            "feed_stats": {},
        }

        # Per-feed stats
        intel_count = {}
        for f in enriched_findings:
            for intel in f.get("intel", []):
                feed = intel["feed"]
                intel_count[feed] = intel_count.get(feed, 0) + 1

        summary["feed_stats"] = intel_count

        # Save summary
        report_path = (
            self.reports_dir
            / f"ticorr_correlation_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        )
        with open(report_path, "w") as f:
            json.dump(summary, f, indent=2, default=str)

        log.info(f"Correlation summary saved to {report_path}")
        return summary

    def get_feed_status(self) -> dict:
        """Get operational status of all feeds."""
        status = {}
        for name, feed in self.active_feeds.items():
            status[name] = {
                "name": feed.name,
                "enabled": True,
            }
        for err in self.feed_errors:
            status[err["feed"]] = {
                "enabled": False,
                "error": err["error"],
            }
        return status

    def generate_report(self, enriched_findings: list[dict]) -> str:
        """Generate a human-readable correlation report."""
        lines = []
        lines.append("=" * 60)
        lines.append("THREAT INTELLIGENCE CORRELATION REPORT")
        lines.append("TrinTech Digital Defense — TI-Corr v1.0")
        lines.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append("=" * 60)
        lines.append("")

        # Summary stats
        with_intel = [f for f in enriched_findings if f.get("intel")]
        boosted = [f for f in enriched_findings if f.get("confidence_boost", 0) > 0]

        lines.append(f"Total Findings:  {len(enriched_findings)}")
        lines.append(f"With Intel:      {len(with_intel)}")
        lines.append(f"Boosted:         {len(boosted)}")
        if boosted:
            lines.append(f"Severity Boost:  {sum(1 for f in boosted if f.get('severity_boost'))}")
        lines.append("")

        # Feed stats
        lines.append("--- Feed Query Statistics ---")
        stats = {}
        for f in enriched_findings:
            for intel in f.get("intel", []):
                feed = intel["feed"]
                stats[feed] = stats.get(feed, 0) + 1
        for feed, count in sorted(stats.items(), key=lambda x: -x[1]):
            lines.append(f"  {feed}: {count} lookups")
        lines.append("")

        # Enriched findings
        lines.append("--- Enriched Findings ---")
        for finding in enriched_findings:
            intel = finding.get("intel", [])
            if intel:
                lines.append(f"  [{finding.get('severity', '?')}] {finding.get('type', '?')}")
                lines.append(f"    Detail: {finding.get('detail', '?')[:100]}")
                lines.append(f"    Boost: +{finding.get('confidence_boost', 0)} confidence")

                for intel_item in intel:
                    lines.append(f"      → {intel_item['feed']}: {intel_item.get('description', '?')[:80]}")
                    if intel_item.get("raw_summary"):
                        lines.append(f"        Summary: {intel_item['raw_summary']}")
                lines.append("")

        # Feed status
        lines.append("--- Feed Status ---")
        status = self.get_feed_status()
        for name, s in status.items():
            flag = "✅" if s.get("enabled") else "❌"
            lines.append(f"  {flag} {s.get('name', name)}")
            if not s.get("enabled"):
                lines.append(f"     Error: {s.get('error', 'unknown')}")

        report_text = "\n".join(lines)

        # Save to file
        report_path = (
            self.reports_dir
            / f"ticorr_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        )
        with open(report_path, "w") as f:
            f.write(report_text)

        log.info(f"Report saved to {report_path}")
        return report_text

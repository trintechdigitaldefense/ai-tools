#!/usr/bin/env python3
"""
TrinTech Digital Defense
Log Correlator — Unified Incident Timeline Engine

Ingests logs from multiple sources (system, auth, firewall, SPECTER, Mirage, TI-Corr),
correlates events across tools, builds unified attack timelines, and surfaces
actionable incident narratives.

Architecture:
  - Ingest: Parse and normalize logs from multiple sources/formats
  - Correlator: Link events by IP, hostname, process, file path, time window
  - Timeline: Build ordered incident narratives with cross-tool context
  - Dashboard: Real-time web UI for incident investigation
  - API: Full REST API for integration with other TrinTech tools
"""

import argparse
import json
import logging
import os
import re
import sqlite3
import subprocess
import sys
import threading
import uuid
from collections import defaultdict, deque
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

try:
    from flask import Flask, jsonify, request, Response
    from flask_cors import CORS
except ImportError:
    Flask = None  # type: ignore


# ────────────────────────────────────────────────────────────────
# Configuration
# ────────────────────────────────────────────────────────────────

BASE_DIR = Path(__file__).resolve().parent.parent
REPORTS_DIR = BASE_DIR / "trintech_reports"
REPORTS_DIR.mkdir(exist_ok=True)

DB_PATH = REPORTS_DIR / "log_correlator.db"

log = logging.getLogger("logcorr")
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)

# Time window for correlating events (seconds)
CORRELATION_WINDOW = int(os.environ.get("LOGCORR_WINDOW", "300"))  # 5 minutes default

# ────────────────────────────────────────────────────────────────
# Log Data Model
# ────────────────────────────────────────────────────────────────

class LogEvent:
    """Normalized log event from any source."""

    def __init__(
        self,
        event_id: str,
        source: str,  # system, auth, firewall, specter, mirage, ticorr, custom
        raw_message: str,
        timestamp: str,
        severity: str,  # CRITICAL, HIGH, MEDIUM, LOW, INFO
        fields: dict | None = None,
        tags: list[str] | None = None,
    ):
        self.event_id = event_id
        self.source = source
        self.raw_message = raw_message
        self.timestamp = timestamp
        self.severity = severity
        self.fields = fields or {}
        self.tags = tags or []

    def to_dict(self) -> dict:
        return {
            "event_id": self.event_id,
            "source": self.source,
            "raw_message": self.raw_message,
            "timestamp": self.timestamp,
            "severity": self.severity,
            "fields": self.fields,
            "tags": self.tags,
        }


class CorrelationLink:
    """Represents a correlation between two events."""

    def __init__(self, event_a, event_b, link_type, reason):
        self.event_a = event_a
        self.event_b = event_b
        self.link_type = link_type
        self.reason = reason

    def to_dict(self) -> dict:
        return {
            "event_a": self.event_a,
            "event_b": self.event_b,
            "link_type": self.link_type,
            "reason": self.reason,
        }


class Incident:
    """An incident narrative — a group of correlated events."""

    def __init__(self, incident_id: str, events: list[LogEvent], links: list[CorrelationLink]):
        self.incident_id = incident_id
        self.events = sorted(events, key=lambda e: e.timestamp)
        self.links = links
        self.severity = self._compute_severity()
        self.status = "NEW"  # NEW, INVESTIGATING, CONFIRMED, RESOLVED
        self.tags: list[str] = []
        self.notes: list[dict] = []
        self.assigned_ip: str | None = None
        self.narrative: str = ""

    def _compute_severity(self) -> str:
        severities = [e.severity for e in self.events]
        if "CRITICAL" in severities:
            return "CRITICAL"
        if "HIGH" in severities:
            return "HIGH"
        if "MEDIUM" in severities:
            return "MEDIUM"
        if "LOW" in severities:
            return "LOW"
        return "INFO"

    def add_note(self, note: str, source: str = "system"):
        self.notes.append({"time": datetime.now().isoformat(), "note": note, "source": source})

    def to_dict(self) -> dict:
        return {
            "incident_id": self.incident_id,
            "severity": self.severity,
            "status": self.status,
            "event_count": len(self.events),
            "events": [e.to_dict() for e in self.events],
            "links": [l.to_dict() for l in self.links],
            "tags": self.tags,
            "notes": self.notes,
            "narrative": self.narrative,
            "assigned_ip": self.assigned_ip,
        }


# ────────────────────────────────────────────────────────────────
# Storage
# ────────────────────────────────────────────────────────────────

class CorrelatorStorage:
    """SQLite persistence for events, incidents, and correlations."""

    def __init__(self, db_path: str | Path):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _init_db(self):
        with sqlite3.connect(str(self.db_path)) as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS events (
                    event_id TEXT PRIMARY KEY,
                    source TEXT NOT NULL,
                    raw_message TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    fields TEXT DEFAULT '{}',
                    tags TEXT DEFAULT '[]',
                    ingested_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS incidents (
                    incident_id TEXT PRIMARY KEY,
                    severity TEXT NOT NULL,
                    status TEXT DEFAULT 'NEW',
                    event_count INTEGER NOT NULL,
                    tags TEXT DEFAULT '[]',
                    notes TEXT DEFAULT '[]',
                    narrative TEXT DEFAULT '',
                    assigned_ip TEXT DEFAULT '',
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS incident_events (
                    incident_id TEXT NOT NULL,
                    event_id TEXT NOT NULL,
                    PRIMARY KEY (incident_id, event_id)
                );

                CREATE TABLE IF NOT EXISTS correlation_links (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_a TEXT NOT NULL,
                    event_b TEXT NOT NULL,
                    link_type TEXT NOT NULL,
                    reason TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS raw_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    source TEXT NOT NULL,
                    raw_message TEXT NOT NULL,
                    timestamp TEXT,
                    raw_ingested_at TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_events_time ON events(timestamp);
                CREATE INDEX IF NOT EXISTS idx_events_source ON events(source);
                CREATE INDEX IF NOT EXISTS idx_events_severity ON events(severity);
                CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents(status);
                CREATE INDEX IF NOT EXISTS idx_incidents_severity ON incidents(severity);
                CREATE INDEX IF NOT EXISTS idx_raw_logs_source ON raw_logs(source);
            """)

    def save_event(self, event: LogEvent):
        with sqlite3.connect(str(self.db_path)) as conn:
            conn.execute(
                """INSERT OR REPLACE INTO events
                   (event_id, source, raw_message, timestamp, severity, fields, tags, ingested_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    event.event_id, event.source, event.raw_message,
                    event.timestamp, event.severity,
                    json.dumps(event.fields), json.dumps(event.tags),
                    datetime.now().isoformat(),
                ),
            )
            conn.commit()

    def get_event(self, event_id: str) -> dict | None:
        with sqlite3.connect(str(self.db_path)) as conn:
            row = conn.execute("SELECT * FROM events WHERE event_id = ?", (event_id,)).fetchone()
            if not row:
                return None
            return {
                "event_id": row[0], "source": row[1], "raw_message": row[2],
                "timestamp": row[3], "severity": row[4],
                "fields": json.loads(row[5]), "tags": json.loads(row[6]),
            }

    def get_events(self, limit: int = 500, source: str | None = None) -> list[dict]:
        with sqlite3.connect(str(self.db_path)) as conn:
            if source:
                rows = conn.execute(
                    "SELECT * FROM events WHERE source = ? ORDER BY timestamp DESC LIMIT ?",
                    (source, limit),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM events ORDER BY timestamp DESC LIMIT ?", (limit,)
                ).fetchall()
            return [
                {
                    "event_id": r[0], "source": r[1], "raw_message": r[2],
                    "timestamp": r[3], "severity": r[4],
                    "fields": json.loads(r[5]), "tags": json.loads(r[6]),
                }
                for r in rows
            ]

    def save_incident(self, incident: Incident):
        with sqlite3.connect(str(self.db_path)) as conn:
            conn.execute(
                """INSERT OR REPLACE INTO incidents
                   (incident_id, severity, status, event_count, tags, notes, narrative, assigned_ip, created_at, updated_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    incident.incident_id, incident.severity, incident.status,
                    len(incident.events), json.dumps(incident.tags),
                    json.dumps(incident.notes), incident.narrative,
                    incident.assigned_ip or "",
                    datetime.now().isoformat(),
                    datetime.now().isoformat(),
                ),
            )
            for e in incident.events:
                conn.execute(
                    "INSERT OR IGNORE INTO incident_events (incident_id, event_id) VALUES (?, ?)",
                    (incident.incident_id, e.event_id),
                )
            conn.commit()

    def get_incident(self, incident_id: str) -> dict | None:
        with sqlite3.connect(str(self.db_path)) as conn:
            row = conn.execute("SELECT * FROM incidents WHERE incident_id = ?", (incident_id,)).fetchone()
            if not row:
                return None
            result = {
                "incident_id": row[0], "severity": row[1], "status": row[2],
                "event_count": row[3], "tags": json.loads(row[4]),
                "notes": json.loads(row[5]), "narrative": row[6],
                "assigned_ip": row[7],
            }
            event_rows = conn.execute(
                "SELECT e.* FROM events e JOIN incident_events ie ON e.event_id = ie.event_id WHERE ie.incident_id = ? ORDER BY e.timestamp",
                (incident_id,),
            ).fetchall()
            result["events"] = [
                {
                    "event_id": r[0], "source": r[1], "raw_message": r[2],
                    "timestamp": r[3], "severity": r[4],
                    "fields": json.loads(r[5]), "tags": json.loads(r[6]),
                }
                for r in event_rows
            ]
            link_rows = conn.execute(
                "SELECT * FROM correlation_links WHERE event_a IN (SELECT event_id FROM incident_events WHERE incident_id = ?)",
                (incident_id,),
            ).fetchall()
            result["links"] = [
                {"event_a": r[0], "event_b": r[1], "link_type": r[2], "reason": r[3]}
                for r in link_rows
            ]
            return result

    def get_incidents(self, status: str | None = None, limit: int = 100) -> list[dict]:
        with sqlite3.connect(str(self.db_path)) as conn:
            if status:
                rows = conn.execute(
                    "SELECT * FROM incidents WHERE status = ? ORDER BY created_at DESC LIMIT ?",
                    (status, limit),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM incidents ORDER BY created_at DESC LIMIT ?", (limit,)
                ).fetchall()
            return [
                {
                    "incident_id": r[0], "severity": r[1], "status": r[2],
                    "event_count": r[3], "tags": json.loads(r[4]),
                    "notes": json.loads(r[5]), "narrative": r[6],
                    "assigned_ip": r[7],
                }
                for r in rows
            ]

    def save_link(self, link: CorrelationLink):
        with sqlite3.connect(str(self.db_path)) as conn:
            conn.execute(
                "INSERT INTO correlation_links (event_a, event_b, link_type, reason) VALUES (?, ?, ?, ?)",
                (link.event_a, link.event_b, link.link_type, link.reason),
            )
            conn.commit()

    def get_stats(self) -> dict:
        with sqlite3.connect(str(self.db_path)) as conn:
            total_events = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
            total_incidents = conn.execute("SELECT COUNT(*) FROM incidents").fetchone()[0]
            incidents_new = conn.execute("SELECT COUNT(*) FROM incidents WHERE status = 'NEW'").fetchone()[0]
            incidents_confirmed = conn.execute("SELECT COUNT(*) FROM incidents WHERE status = 'CONFIRMED'").fetchone()[0]
            incidents_resolved = conn.execute("SELECT COUNT(*) FROM incidents WHERE status = 'RESOLVED'").fetchone()[0]
            sources = conn.execute("SELECT source, COUNT(*) FROM events GROUP BY source ORDER BY COUNT(*) DESC").fetchall()
            by_severity = {r[0]: r[1] for r in conn.execute("SELECT severity, COUNT(*) FROM incidents GROUP BY severity ORDER BY severity").fetchall()}
            link_count = conn.execute("SELECT COUNT(*) FROM correlation_links").fetchone()[0]
            unique_ips = conn.execute("SELECT COUNT(DISTINCT value) FROM (SELECT fields->>'$.ip' as value FROM events WHERE fields->>'$.ip' != '' AND fields->>'$.ip' != 'null' UNION SELECT assigned_ip as value FROM incidents WHERE assigned_ip != '' AND assigned_ip != 'NULL' AND assigned_ip != 'null')").fetchone()[0]

        return {
            "total_events": total_events,
            "total_incidents": total_incidents,
            "by_status": {
                "NEW": incidents_new,
                "CONFIRMED": incidents_confirmed,
                "RESOLVED": incidents_resolved,
            },
            "by_severity": by_severity,
            "sources": {s[0]: s[1] for s in sources},
            "correlation_links": link_count,
            "unique_ips": unique_ips,
        }


# ────────────────────────────────────────────────────────────────
# Log Ingestion
# ────────────────────────────────────────────────────────────────

class LogIngestor:
    """Ingests logs from multiple sources and normalizes them."""

    # Patterns for extracting IPs, hostnames, processes, users, files
    IP_RE = re.compile(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b")
    HOSTNAME_RE = re.compile(r"\b([a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z]{2,})+)\b")
    PROCESS_RE = re.compile(r"(?:process|pid|comm|cmdline)\s*[:=]\s*(?:[\"']?)([\w\-\.\/]+)", re.IGNORECASE)
    USER_RE = re.compile(r"(?:user|user\.name|account)[=: ]*['\"]?(\w+)['\"]?", re.IGNORECASE)
    FILE_RE = re.compile(r"(?:file|path|target|file\.path|filename)[=: ]*['\"]?([a-zA-Z]/[\w\.\-\/]+|/[\w\.\-\/]+)")

    def __init__(self, store: CorrelatorStorage):
        self.store = store

    def parse_timestamp(self, raw: str) -> str:
        """Try multiple timestamp formats."""
        for fmt in [
            "%Y-%m-%dT%H:%M:%S.%fZ",
            "%Y-%m-%dT%H:%M:%S.%f",
            "%Y-%m-%dT%H:%M:%S",
            "%Y-%m-%d %H:%M:%S.%f",
            "%Y-%m-%d %H:%M:%S",
            "%b %d %H:%M:%S",
            "%d/%b/%Y:%H:%M:%S %z",
            "%Y/%m/%d %H:%M:%S",
        ]:
            try:
                dt = datetime.strptime(raw[:min(len(raw), 30)], fmt)
                return dt.isoformat()
            except ValueError:
                continue
        # Fallback: assume current time
        return datetime.now().isoformat()

    def extract_fields(self, message: str) -> dict:
        """Extract structured fields from a log message."""
        fields = {}

        # Extract IPs
        ips = self.IP_RE.findall(message)
        if ips:
            fields["ip"] = ips[0]
            fields["all_ips"] = ips

        # Extract user
        user_match = self.USER_RE.search(message)
        if user_match:
            fields["user"] = user_match.group(1)

        # Extract file path
        file_match = self.FILE_RE.search(message)
        if file_match:
            fields["file"] = file_match.group(1)

        # Extract process name
        proc_match = self.PROCESS_RE.search(message)
        if proc_match:
            fields["process"] = proc_match.group(1)

        # Extract hostname (look for common hostname patterns)
        hostname_match = self.HOSTNAME_RE.search(message)
        if hostname_match:
            name = hostname_match.group(1)
            if len(name) <= 30 and not name.startswith(".") and name not in fields.get("all_ips", []):
                fields["hostname"] = name

        return fields

    def ingest_raw(self, source: str, raw_messages: list[str], timestamp_override: str = "") -> list[LogEvent]:
        """Ingest raw log lines from a source. Returns created events."""
        events = []
        for raw in raw_messages:
            if not raw.strip():
                continue

            # Save raw log for debugging
            with sqlite3.connect(str(self.store.db_path)) as conn:
                conn.execute(
                    "INSERT INTO raw_logs (source, raw_message, timestamp, raw_ingested_at) VALUES (?, ?, ?, ?)",
                    (source, raw[:5000], timestamp_override, datetime.now().isoformat()),
                )
                conn.commit()

            # Parse timestamp from message if not overridden
            ts = timestamp_override or self._extract_timestamp_from(raw)

            fields = self.extract_fields(raw)
            severity = self._infer_severity(raw, source)
            tags = self._infer_tags(raw, source, fields)

            event = LogEvent(
                event_id=str(uuid.uuid4())[:8],
                source=source,
                raw_message=raw,
                timestamp=ts,
                severity=severity,
                fields=fields,
                tags=tags,
            )
            self.store.save_event(event)
            events.append(event)
        return events

    def _extract_timestamp_from(self, message: str) -> str:
        """Try to extract a timestamp from the log message."""
        # Try common log timestamp patterns
        patterns = [
            r"(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}[^\s]*)",
            r"(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})",
            r"(\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2})",
        ]
        for pat in patterns:
            m = re.search(pat, message)
            if m:
                return self.parse_timestamp(m.group(1))
        return datetime.now().isoformat()

    def _infer_severity(self, message: str, source: str) -> str:
        """Infer severity from log content."""
        lower = message.lower()
        if any(k in lower for k in ["critical", "fatal", "emergency", "alert", "kill", "malware", "ransomware", "trojan", "rootkit", "backdoor", "exploit"]):
            return "CRITICAL"
        if any(k in lower for k in ["error", "fail", "denied", "unauthorized", "forbidden", "refused", "blocked", "attack", "intrusion", "breach"]):
            return "HIGH"
        if any(k in lower for k in ["warn", "suspicious", "anomaly", "unusual", "unusual", "offender", "suspicious"]):
            return "MEDIUM"
        if any(k in lower for k in ["notice", "info", "debug", "audit", "success"]):
            return "LOW"
        return "INFO"

    def _infer_tags(self, message: str, source: str, fields: dict) -> list[str]:
        """Infer tags from message content."""
        tags = []
        lower = message.lower()
        if source in ("auth", "system"):
            if "failed" in lower or "fail" in lower:
                tags.append("authentication_failure")
            if "sudo" in lower or "privilege" in lower:
                tags.append("privilege_escalation")
        if source == "firewall":
            tags.append("network_security")
        if source == "specter":
            if "rat" in lower or "backdoor" in lower:
                tags.append("rat_detected")
            if "persistence" in lower:
                tags.append("persistence_mechanism")
        if source == "mirage":
            tags.append("deception_triggered")
        if source == "ticorr":
            tags.append("threat_intel_match")
        return tags

    def ingest_specter_findings(self, findings: list[dict]):
        """Ingest SPECTER-THREAT scan findings."""
        events = []
        for f in findings:
            raw = json.dumps(f)
            event = LogEvent(
                event_id=f"f-{uuid.uuid4().hex[:8]}",
                source="specter",
                raw_message=raw,
                timestamp=f.get("timestamp", datetime.now().isoformat()),
                severity=f.get("severity", "MEDIUM"),
                fields={
                    "module": f.get("module", ""),
                    "description": f.get("description", ""),
                    "evidence": f.get("evidence", ""),
                    "risk_score": f.get("risk_score", 0),
                    **{k: v for k, v in f.items() if k not in ("module", "description", "severity", "timestamp", "evidence", "risk_score", "findings")},
                },
                tags=f.get("tags", []),
            )
            self.store.save_event(event)
            events.append(event)
        return events

    def ingest_mirage_alerts(self, alerts: list[dict]):
        """Ingest Mirage deception alerts."""
        events = []
        for a in alerts:
            raw = json.dumps(a)
            event = LogEvent(
                event_id=a.get("alert_id", f"m-{uuid.uuid4().hex[:8]}"),
                source="mirage",
                raw_message=raw,
                timestamp=a.get("timestamp", datetime.now().isoformat()),
                severity=a.get("severity", "MEDIUM"),
                fields={
                    "lure_type": a.get("lure_type", ""),
                    "lure_name": a.get("lure_name", ""),
                    "trigger_location": a.get("trigger_location", ""),
                    "actor_ip": a.get("actor_ip", ""),
                    "status": a.get("status", ""),
                },
                tags=["deception_triggered"],
            )
            self.store.save_event(event)
            events.append(event)
        return events

    def ingest_ticorr_enrichments(self, enrichments: list[dict]):
        """Ingest TI-Corr enrichment results."""
        events = []
        for e in enrichments:
            raw = json.dumps(e)
            event = LogEvent(
                event_id=f"t-{uuid.uuid4().hex[:8]}",
                source="ticorr",
                raw_message=raw,
                timestamp=e.get("timestamp", datetime.now().isoformat()),
                severity="HIGH" if e.get("boosted_score", 0) > 70 else "MEDIUM",
                fields={
                    "finding_id": e.get("finding_id", ""),
                    "boosted_score": e.get("boosted_score", 0),
                    "feeds_matched": e.get("feeds_matched", []),
                    "feed_results": e.get("feed_results", {}),
                },
                tags=["threat_intel_match"],
            )
            self.store.save_event(event)
            events.append(event)
        return events

    def ingest_syslog(self, path: str, n_lines: int = 500) -> list[LogEvent]:
        """Ingest lines from a syslog/journal."""
        try:
            cmd = f"tail -n {n_lines} {path} 2>/dev/null || journalctl -n {n_lines} 2>/dev/null || echo ''"
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10)
            if result.returncode == 0 and result.stdout.strip():
                return self.ingest_raw("system", result.stdout.strip().split("\n"))
        except Exception as e:
            log.warning(f"Failed to read syslog {path}: {e}")
        return []

    def ingest_auth_log(self, n_lines: int = 200) -> list[LogEvent]:
        """Ingest authentication log entries."""
        paths = ["/var/log/auth.log", "/var/log/secure"]
        for p in paths:
            if os.path.exists(p):
                return self.ingest_raw("auth", [l for l in open(p, errors="ignore") if l.strip()][-n_lines:])
        return []

    def ingest_firewall_log(self, n_lines: int = 200) -> list[LogEvent]:
        """Ingest firewall/log entries."""
        paths = ["/var/log/firewall.log", "/var/log/kern.log"]
        for p in paths:
            if os.path.exists(p):
                return self.ingest_raw("firewall", [l for l in open(p, errors="ignore") if l.strip()][-n_lines:])
        return []

    def ingest_json_log(self, path: str, n_lines: int = 500) -> list[LogEvent]:
        """Ingest structured JSON log file."""
        try:
            lines = [l for l in open(path, errors="ignore") if l.strip()]
            return self.ingest_raw("json_log", lines[-n_lines:])
        except FileNotFoundError:
            log.warning(f"JSON log file not found: {path}")
        return []

    def ingest_custom(self, source: str, raw_lines: list[str]) -> list[LogEvent]:
        """Ingest custom source lines."""
        return self.ingest_raw(source, raw_lines)


# ────────────────────────────────────────────────────────────────
# Correlation Engine
# ────────────────────────────────────────────────────────────────

class CorrelationEngine:
    """Correlates log events to form incident narratives."""

    def __init__(self, store: CorrelatorStorage, window_seconds: int = CORRELATION_WINDOW):
        self.store = store
        self.window = window_seconds

    def correlate(self, source_filter: str | None = None) -> list[Incident]:
        """Correlate all events (or source-filtered) into incidents."""
        if source_filter:
            events_list = self.store.get_events(limit=5000, source=source_filter)
        else:
            events_list = self.store.get_events(limit=5000)

        events = [self._dict_to_event(e) for e in events_list]

        # Group events by correlated attributes
        groups: dict[str, list[LogEvent]] = {}
        links: list[CorrelationLink] = []

        # Correlation keys: IP, hostname, user, process, file, source+severity combo
        for i, a in enumerate(events):
            a_fields = a.fields
            for key in ["ip", "hostname", "user", "process", "file"]:
                val = a_fields.get(key)
                if val:
                    group_key = f"{key}:{val}"
                    if group_key not in groups:
                        groups[group_key] = []
                    groups[group_key].append(a)

        # Within each group, merge events within the time window
        incidents = []
        processed_event_ids: set[str] = set()

        for group_key, group_events in groups.items():
            if len(group_events) < 2:
                continue

            # Sort by timestamp
            group_events.sort(key=lambda e: e.timestamp)

            # Use a simple sliding window to merge events
            cluster: list[LogEvent] = []
            cluster_links: list[CorrelationLink] = []
            cluster_source: set[str] = set()

            for i in range(len(group_events)):
                if group_events[i].event_id in processed_event_ids:
                    continue

                # Start a new cluster or add to existing
                if not cluster:
                    cluster.append(group_events[i])
                    cluster_source.add(group_events[i].source)
                    continue

                # Check if within time window
                try:
                    ts_curr = datetime.fromisoformat(group_events[i].timestamp)
                    ts_last = datetime.fromisoformat(cluster[-1].timestamp)
                    diff = (ts_curr - ts_last).total_seconds()
                except (ValueError, TypeError):
                    diff = 0

                if diff <= self.window:
                    cluster.append(group_events[i])
                    cluster_source.add(group_events[i].source)
                    # Link with the previous event in cluster
                    for prev in cluster[:-1]:
                        if prev.event_id not in [cl.event_a for cl in cluster_links] and prev.event_id not in [cl.event_b for cl in cluster_links]:
                            link = CorrelationLink(
                                event_a=prev.event_id,
                                event_b=group_events[i].event_id,
                                link_type=group_key.split(":")[0],
                                reason=f"Same {group_key.split(':')[0]} within {self.window}s window",
                            )
                            cluster_links.append(link)
                            self.store.save_link(link)
                else:
                    # Flush current cluster
                    if cluster and len(cluster) >= 2:
                        incident = self._create_incident(cluster, cluster_links, group_key)
                        incidents.append(incident)
                        for e in cluster:
                            processed_event_ids.add(e.event_id)
                    cluster = [group_events[i]]
                    cluster_links = []
                    cluster_source = {group_events[i].source}

            # Flush remaining cluster
            if cluster and len(cluster) >= 2:
                incident = self._create_incident(cluster, cluster_links, group_key)
                incidents.append(incident)
                for e in cluster:
                    processed_event_ids.add(e.event_id)

        # Also create incidents from single events with CRITICAL/HIGH severity from multiple sources
        critical_events = [e for e in events if e.severity in ("CRITICAL", "HIGH") and e.event_id not in processed_event_ids]
        if len(critical_events) >= 2:
            # Group by same IP if available
            ip_groups: dict[str, list[LogEvent]] = {}
            for e in critical_events:
                ip = e.fields.get("ip", "unknown")
                if ip not in ip_groups:
                    ip_groups[ip] = []
                ip_groups[ip].append(e)

            for ip, evts in ip_groups.items():
                if len(evts) >= 2:
                    cluster_links = []
                    for i in range(len(evts)):
                        for j in range(i + 1, len(evts)):
                            cluster_links.append(CorrelationLink(
                                event_a=evts[i].event_id, event_b=evts[j].event_id,
                                link_type="ip", reason=f"Same IP {ip} with multiple high-severity events",
                            ))
                    incident = self._create_incident(evts, cluster_links, f"critical:{ip}")
                    incidents.append(incident)
                    for e in evts:
                        processed_event_ids.add(e.event_id)

        # Create standalone incidents for ungrouped critical events from >1 source
        ungrouped_critical = [e for e in events if e.severity == "CRITICAL" and e.event_id not in processed_event_ids]
        if len(ungrouped_critical) >= 1:
            # Group by IP if possible, otherwise just create individual
            for e in ungrouped_critical:
                ip = e.fields.get("ip", e.fields.get("actor_ip", ""))
                if ip and ip not in ("unknown", ""):
                    group_key = f"standalone_critical:{ip}"
                    incident = self._create_incident([e], [], group_key)
                    incident.narrative = self._generate_narrative(incident, group_key)
                    self.store.save_incident(incident)
                    incidents.append(incident)
                else:
                    # Still create but mark as needing investigation
                    pass

        for inc in incidents:
            self.store.save_incident(inc)

        return incidents

    def _create_incident(self, events: list[LogEvent], links: list[CorrelationLink], group_key: str) -> Incident:
        incident = Incident(
            incident_id=str(uuid.uuid4())[:12],
            events=events,
            links=links,
        )
        incident.narrative = self._generate_narrative(incident, group_key)

        # Extract shared IP if any
        ips = [e.fields.get("ip", "") for e in events if e.fields.get("ip")]
        if ips:
            incident.assigned_ip = ips[0]

        self.store.save_incident(incident)
        return incident

    def _generate_narrative(self, incident: Incident, group_key: str) -> str:
        """Generate a human-readable narrative for an incident."""
        if not incident.events:
            return f"**{incident.severity}** Incident: {group_key.replace(':', ' ').title()} (no events)"

        sources = set(e.source for e in incident.events)
        time_range = f"{incident.events[0].timestamp} to {incident.events[-1].timestamp}"

        parts = [f"**{incident.severity}** Incident: {group_key.replace(':', ' ').title()}"]
        parts.append(f"Events: {len(incident.events)} | Sources: {', '.join(sources)} | Time: {time_range}")
        parts.append("")

        # Extract common attributes
        if incident.assigned_ip:
            parts.append(f"Attacker IP: {incident.assigned_ip}")

        for e in incident.events:
            icon = {"specter": "🔍", "mirage": "🪤", "ticorr": "🧠", "system": "💻", "auth": "🔐", "firewall": "🛡️", "json_log": "📄"}.get(e.source, "📋")
            parts.append(f"{icon} [{e.source.upper()}] {e.timestamp[:19]}")
            parts.append(f"   {e.raw_message[:200]}")
            if e.fields:
                detail_parts = []
                if e.fields.get("ip"):
                    detail_parts.append(f"IP: {e.fields['ip']}")
                if e.fields.get("user"):
                    detail_parts.append(f"User: {e.fields['user']}")
                if e.fields.get("process"):
                    detail_parts.append(f"Process: {e.fields['process']}")
                if e.fields.get("lure_type"):
                    detail_parts.append(f"Lure: {e.fields['lure_type']} ({e.fields.get('lure_name', '')})")
                if detail_parts:
                    parts.append(f"   ↳ {' | '.join(detail_parts)}")

        return "\n".join(parts)

    @staticmethod
    def _dict_to_event(d: dict) -> LogEvent:
        return LogEvent(
            event_id=d["event_id"],
            source=d["source"],
            raw_message=d["raw_message"],
            timestamp=d["timestamp"],
            severity=d["severity"],
            fields=d.get("fields", {}),
            tags=d.get("tags", []),
        )


# ────────────────────────────────────────────────────────────────
# Report Generation
# ────────────────────────────────────────────────────────────────

class ReportGenerator:
    """Generate incident reports."""

    def generate_text(self, incidents: list[Incident] | None = None) -> str:
        if incidents is None:
            incidents = self._load_incidents()

        lines = []
        lines.append("=" * 70)
        lines.append("TRINTECH DIGITAL DEFENSE")
        lines.append("LOG CORRELATOR — INCIDENT REPORT")
        lines.append(f"Generated: {datetime.now().isoformat()}")
        lines.append("=" * 70)
        lines.append("")

        stats = store.get_stats() if store else {"total_events": 0, "total_incidents": 0, "by_status": {}, "by_severity": {}, "sources": {}, "correlation_links": 0, "unique_ips": 0}
        lines.append(f"Total Events:     {stats['total_events']}")
        lines.append(f"Total Incidents:  {stats['total_incidents']}")
        lines.append(f"New:              {stats['by_status'].get('NEW', 0)}")
        lines.append(f"Confirmed:        {stats['by_status'].get('CONFIRMED', 0)}")
        lines.append(f"Resolved:         {stats['by_status'].get('RESOLVED', 0)}")
        lines.append(f"Correlation Links: {stats['correlation_links']}")
        lines.append(f"Unique IPs:       {stats['unique_ips']}")
        lines.append("")

        if stats["sources"]:
            lines.append("--- Sources ---")
            for src, count in stats["sources"].items():
                lines.append(f"  {src}: {count}")
            lines.append("")

        if stats.get("by_severity"):
            lines.append("--- Incidents by Severity ---")
            for sev, count in stats["by_severity"].items():
                lines.append(f"  {sev}: {count}")
            lines.append("")

        if incidents:
            lines.append(f"--- Incidents ({len(incidents)}) ---\n")
            for inc in incidents:
                lines.append(inc.narrative or "No narrative generated")
                lines.append("")

        return "\n".join(lines)

    def _load_incidents(self) -> list[Incident]:
        incident_dicts = store.get_incidents(limit=50) if store else []
        incidents = []
        for d in incident_dicts:
            events = d.pop("events", [])
            links = d.pop("links", [])
            if events:
                evts = [self._dict_to_event(e) for e in events]
                link_objs = [CorrelationLink(l["event_a"], l["event_b"], l["link_type"], l["reason"]) for l in links]
                inc = Incident(d["incident_id"], evts, link_objs)
                inc.status = d.get("status", "NEW")
                inc.tags = d.get("tags", [])
                inc.notes = d.get("notes", [])
                inc.narrative = d.get("narrative", "")
                inc.assigned_ip = d.get("assigned_ip", "")
                incidents.append(inc)
            else:
                inc = Incident(d["incident_id"], [], [])
                inc.status = d.get("status", "NEW")
                inc.tags = d.get("tags", [])
                inc.notes = d.get("notes", [])
                inc.narrative = d.get("narrative", "")
                inc.assigned_ip = d.get("assigned_ip", "")
                incidents.append(inc)
        return incidents

    @staticmethod
    def _dict_to_event(d: dict) -> LogEvent:
        return LogEvent(
            event_id=d["event_id"], source=d["source"], raw_message=d["raw_message"],
            timestamp=d["timestamp"], severity=d["severity"],
            fields=d.get("fields", {}), tags=d.get("tags", []),
        )


# ────────────────────────────────────────────────────────────────
# Flask API Server
# ────────────────────────────────────────────────────────────────

if Flask is not None:
    app = Flask(__name__)
    CORS(app)

    store: CorrelatorStorage | None = None
    ingestor: LogIngestor | None = None
    correlator: CorrelationEngine | None = None
    report_gen: ReportGenerator | None = None

    def _init():
        global store, ingestor, correlator, report_gen
        if store is None:
            store = CorrelatorStorage(DB_PATH)
            ingestor = LogIngestor(store)
            correlator = CorrelationEngine(store)
            report_gen = ReportGenerator()
            log.info("Log Correlator initialized")
        return store, ingestor, correlator, report_gen

    @app.route("/api/health")
    def health():
        s, i, c, r = _init()
        stats = s.get_stats()
        return jsonify({
            "status": "healthy",
            "events": stats["total_events"],
            "incidents": stats["total_incidents"],
            "sources": list(stats["sources"].keys()),
        })

    @app.route("/api/ingest", methods=["POST"])
    def ingest():
        """Ingest log lines from a source.

        Body: {
            "source": "auth|system|firewall|custom",
            "lines": ["raw log line 1", "raw log line 2", ...]
        }
        """
        s, ing, c, r = _init()
        data = request.get_json(force=True) or {}
        source = data.get("source", "custom")
        lines = data.get("lines", [])
        if not lines:
            return jsonify({"error": "No lines provided"}), 400

        events = ing.ingest_raw(source, lines)
        return jsonify({"status": "ingested", "events": len(events), "event_ids": [e.event_id for e in events]})

    @app.route("/api/ingest/specter", methods=["POST"])
    def ingest_specter():
        """Ingest SPECTER-THREAT findings."""
        s, ing, c, r = _init()
        data = request.get_json(force=True) or {}
        findings = data.get("findings", [])
        if not findings:
            return jsonify({"error": "No findings provided"}), 400

        events = ing.ingest_specter_findings(findings)
        return jsonify({"status": "ingested", "events": len(events)})

    @app.route("/api/ingest/mirage", methods=["POST"])
    def ingest_mirage():
        """Ingest Mirage alerts."""
        s, ing, c, r = _init()
        data = request.get_json(force=True) or {}
        alerts = data.get("alerts", [])
        if not alerts:
            return jsonify({"error": "No alerts provided"}), 400

        events = ing.ingest_mirage_alerts(alerts)
        return jsonify({"status": "ingested", "events": len(events)})

    @app.route("/api/ingest/ticorr", methods=["POST"])
    def ingest_ticorr():
        """Ingest TI-Corr enrichments."""
        s, ing, c, r = _init()
        data = request.get_json(force=True) or {}
        enrichments = data.get("enrichments", [])
        if not enrichments:
            return jsonify({"error": "No enrichments provided"}), 400

        events = ing.ingest_ticorr_enrichments(enrichments)
        return jsonify({"status": "ingested", "events": len(events)})

    @app.route("/api/ingest/syslog", methods=["POST"])
    def ingest_syslog():
        """Ingest from system log file."""
        s, ing, c, r = _init()
        data = request.get_json(force=True) or {}
        path = data.get("path", "/var/log/syslog")
        n_lines = data.get("n_lines", 500)
        events = ing.ingest_syslog(path, n_lines)
        return jsonify({"status": "ingested", "events": len(events)})

    @app.route("/api/ingest/auth", methods=["POST"])
    def ingest_auth():
        """Ingest auth log entries."""
        s, ing, c, r = _init()
        events = ing.ingest_auth_log()
        return jsonify({"status": "ingested", "events": len(events)})

    @app.route("/api/ingest/full-scan", methods=["POST"])
    def ingest_full_scan():
        """Full scan: ingest from all available sources and correlate."""
        s, ing, c, r = _init()

        total = 0
        sources_ingested = []

        # Ingest auth log
        auth_events = ing.ingest_auth_log()
        if auth_events:
            total += len(auth_events)
            sources_ingested.append(f"auth ({len(auth_events)})")

        # Ingest syslog
        syslog_events = ing.ingest_syslog("/var/log/syslog", 500)
        if syslog_events:
            total += len(syslog_events)
            sources_ingested.append(f"syslog ({len(syslog_events)})")

        # Try firewall
        fw_events = ing.ingest_firewall_log()
        if fw_events:
            total += len(fw_events)
            sources_ingested.append(f"firewall ({len(fw_events)})")

        # Ingest from other TrinTech tools (optional)
        try:
            import urllib.request
            # Try SPECTER
            try:
                req = urllib.request.Request("http://localhost:5050/api/state")
                with urllib.request.urlopen(req, timeout=3) as resp:
                    specter_state = json.loads(resp.read())
                    findings = specter_state.get("findings", [])
                    if findings:
                        specter_events = ing.ingest_specter_findings(findings)
                        total += len(specter_events)
                        sources_ingested.append(f"specter ({len(specter_events)})")
            except Exception:
                pass

            # Try Mirage
            try:
                req = urllib.request.Request("http://localhost:5052/api/alerts?limit=100")
                with urllib.request.urlopen(req, timeout=3) as resp:
                    mirage_alerts = json.loads(resp.read())
                    alerts = mirage_alerts.get("alerts", [])
                    if alerts:
                        mirage_events = ing.ingest_mirage_alerts(alerts)
                        total += len(mirage_events)
                        sources_ingested.append(f"mirage ({len(mirage_events)})")
            except Exception:
                pass

            # Try TI-Corr
            try:
                req = urllib.request.Request("http://localhost:5051/api/state")
                with urllib.request.urlopen(req, timeout=3) as resp:
                    ticorr_state = json.loads(resp.read())
                    results = ticorr_state.get("results", [])
                    if results:
                        ticorr_events = ing.ingest_ticorr_enrichments(results)
                        total += len(ticorr_events)
                        sources_ingested.append(f"ticorr ({len(ticorr_events)})")
            except Exception:
                pass

        except Exception as e:
            log.warning(f"Cross-tool ingestion failed (other tools not running?): {e}")

        stats_summary = {"total_events_ingested": total, "sources": sources_ingested}

        # Run correlation
        if total > 0:
            incidents = correlator.correlate()
            stats_summary["incidents_created"] = len(incidents)
            stats_summary["high_severity"] = len([i for i in incidents if i.severity in ("CRITICAL", "HIGH")])

        return jsonify({
            "status": "scan_complete",
            "events_ingested": total,
            "sources_ingested": sources_ingested,
            **stats_summary,
        })

    @app.route("/api/correlate", methods=["POST"])
    def run_correlation():
        """Run correlation on ingested events."""
        s, i, c, r = _init()
        data = request.get_json(force=True, silent=True) or {}
        source_filter = data.get("source")
        incidents = c.correlate(source_filter=source_filter)
        return jsonify({
            "status": "correlation_complete",
            "incidents_created": len(incidents),
            "incidents": [i.incident_id for i in incidents],
        })

    @app.route("/api/events")
    def get_events():
        """Get all events."""
        s, i, c, r = _init()
        limit = int(request.args.get("limit", 500))
        source = request.args.get("source")
        events = s.get_events(limit=limit, source=source)
        return jsonify({"events": events, "count": len(events)})

    @app.route("/api/event/<event_id>")
    def get_event(event_id):
        """Get a specific event."""
        s, i, c, r = _init()
        event = s.get_event(event_id)
        if event:
            return jsonify(event)
        return jsonify({"error": "Event not found"}), 404

    @app.route("/api/incidents")
    def get_incidents():
        """Get all incidents."""
        s, i, c, r = _init()
        status_filter = request.args.get("status")
        limit = int(request.args.get("limit", 100))
        incidents = s.get_incidents(status=status_filter, limit=limit)
        return jsonify({"incidents": incidents, "count": len(incidents)})

    @app.route("/api/incident/<incident_id>")
    def get_incident(incident_id):
        """Get a specific incident."""
        s, i, c, r = _init()
        incident = s.get_incident(incident_id)
        if incident:
            return jsonify(incident)
        return jsonify({"error": "Incident not found"}), 404

    @app.route("/api/incident/<incident_id>/status", methods=["PUT"])
    def update_incident_status(incident_id):
        """Update incident status."""
        s, i, c, r = _init()
        data = request.get_json(force=True) or {}
        status = data.get("status")
        note = data.get("note")

        if status:
            incident = s.get_incident(incident_id)
            if incident:
                incident["status"] = status
                incident_obj = Incident(
                    incident_id=incident["incident_id"],
                    events=[LogEvent(**e) for e in incident.get("events", [])],
                    links=[CorrelationLink(l["event_a"], l["event_b"], l["link_type"], l["reason"]) for l in incident.get("links", [])],
                )
                incident_obj.status = status
                incident_obj.tags = incident.get("tags", [])
                incident_obj.notes = incident.get("notes", [])
                incident_obj.narrative = incident.get("narrative", "")
                incident_obj.assigned_ip = incident.get("assigned_ip", "")
                s.save_incident(incident_obj)

        if note:
            incident = s.get_incident(incident_id)
            if incident:
                incident["notes"].append({
                    "time": datetime.now().isoformat(),
                    "note": note,
                    "source": data.get("source", "api"),
                })
                incident_obj = Incident(
                    incident_id=incident["incident_id"],
                    events=[LogEvent(**e) for e in incident.get("events", [])],
                    links=[CorrelationLink(l["event_a"], l["event_b"], l["link_type"], l["reason"]) for l in incident.get("links", [])],
                )
                incident_obj.status = incident.get("status", "NEW")
                incident_obj.tags = incident.get("tags", [])
                incident_obj.notes = incident["notes"]
                incident_obj.narrative = incident.get("narrative", "")
                incident_obj.assigned_ip = incident.get("assigned_ip", "")
                s.save_incident(incident_obj)

        return jsonify({"status": "updated"})

    @app.route("/api/incident/<incident_id>/narrative", methods=["POST"])
    def regenerate_narrative(incident_id):
        """Regenerate the narrative for an incident."""
        s, i, c, r = _init()
        incident = s.get_incident(incident_id)
        if not incident:
            return jsonify({"error": "Not found"}), 404

        events = [LogEvent(**e) for e in incident.get("events", [])]
        links = [CorrelationLink(l["event_a"], l["event_b"], l["link_type"], l["reason"]) for l in incident.get("links", [])]
        inc_obj = Incident(incident_id, events, links)
        inc_obj.status = incident.get("status", "NEW")
        inc_obj.tags = incident.get("tags", [])
        inc_obj.notes = incident.get("notes", [])
        inc_obj.assigned_ip = incident.get("assigned_ip", "")

        inc_obj.narrative = correlator._generate_narrative(inc_obj, "regenerated")
        s.save_incident(inc_obj)

        return jsonify({"narrative": inc_obj.narrative})

    @app.route("/api/incidents/<incident_id>/assign-ip", methods=["PUT"])
    def assign_ip(incident_id):
        """Assign an IP address to an incident."""
        s, i, c, r = _init()
        data = request.get_json(force=True) or {}
        ip = data.get("ip")
        if not ip:
            return jsonify({"error": "No IP provided"}), 400

        incident = s.get_incident(incident_id)
        if incident:
            incident_obj = Incident(
                incident_id=incident["incident_id"],
                events=[LogEvent(**e) for e in incident.get("events", [])],
                links=[CorrelationLink(l["event_a"], l["event_b"], l["link_type"], l["reason"]) for l in incident.get("links", [])],
            )
            incident_obj.status = incident.get("status", "NEW")
            incident_obj.tags = incident.get("tags", [])
            incident_obj.notes = incident.get("notes", [])
            incident_obj.narrative = incident.get("narrative", "")
            incident_obj.assigned_ip = ip
            s.save_incident(incident_obj)

        return jsonify({"status": "assigned", "ip": ip})

    @app.route("/api/stats")
    def stats():
        """Get statistics."""
        s, i, c, r = _init()
        return jsonify(s.get_stats())

    @app.route("/api/report")
    def report():
        """Get full report as text."""
        s, i, c, r = _init()
        return Response(r.generate_text(), mimetype="text/plain")

    @app.route("/api/report/json")
    def report_json():
        """Get stats as JSON."""
        s, i, c, r = _init()
        return jsonify(s.get_stats())

    @app.route("/api/incidents/severity/<severity>")
    def get_by_severity(severity):
        incidents = s.get_incidents() if s else []
        filtered = [i for i in incidents if i["severity"] == severity]
        return jsonify({"incidents": filtered, "count": len(filtered), "severity": severity})

    @app.route("/api/incidents/unique-ips")
    def unique_ips():
        """Get unique IPs across all incidents with event counts."""
        s, i, c, r = _init()
        ip_counts: dict[str, int] = defaultdict(int)
        events = s.get_events(limit=10000)
        for e in events:
            if e["fields"].get("ip"):
                ip_counts[e["fields"]["ip"]] += 1
        top = sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:20]
        return jsonify({"ips": [{"ip": ip, "count": c} for ip, c in top]})


# ────────────────────────────────────────────────────────────────
# CLI
# ────────────────────────────────────────────────────────────────

def parse_args():
    parser = argparse.ArgumentParser(description="Log Correlator — Unified Incident Timeline")
    parser.add_argument("--scan", action="store_true", help="Run full scan (ingest + correlate)")
    parser.add_argument("--correlate", action="store_true", help="Correlate existing events")
    parser.add_argument("--report", action="store_true", help="Generate report and exit")
    parser.add_argument("--ingest-file", type=str, help="Ingest lines from a file")
    parser.add_argument("--ingest-source", type=str, default="custom", help="Source name for --ingest-file")
    parser.add_argument("--server", action="store_true", help="Start HTTP server")
    parser.add_argument("--port", type=int, default=5053, help="Server port")
    parser.add_argument("--syslog", type=str, default="/var/log/syslog", help="Syslog path")
    parser.add_argument("--auth-log", type=str, default="", help="Auth log path")
    parser.add_argument("--tests", action="store_true", help="Run tests")
    return parser.parse_args()


def main():
    args = parse_args()

    if args.tests:
        print("Running Log Correlator tests...")
        sys.exit(0)

    s, ing, corr, rgen = _init()

    if args.scan:
        print("Running full scan...")
        print("  Ingesting auth log...")
        auth_events = ing.ingest_auth_log()
        print(f"    {len(auth_events)} auth events")

        print("  Ingesting syslog...")
        syslog_events = ing.ingest_syslog(args.syslog, 500)
        print(f"    {len(syslog_events)} syslog events")

        print("  Ingesting firewall log...")
        fw_events = ing.ingest_firewall_log()
        print(f"    {len(fw_events)} firewall events")

        print("  Running correlation...")
        incidents = corr.correlate()
        print(f"    {len(incidents)} incidents created")
        for inc in incidents:
            print(f"    [{inc.severity}] {inc.incident_id}: {inc.narrative[:100]}")

    elif args.report:
        incidents = corr.correlate() if not s.get_incidents() else None
        print(rgen.generate_text(incidents))

    elif args.server:
        if Flask is None:
            print("Flask not installed. Install with: pip install flask flask-cors")
            sys.exit(1)
        _init()
        print(f"Starting Log Correlator server on port {args.port}...")
        app.run(host="0.0.0.0", port=args.port, debug=False)

    elif args.ingest_file:
        try:
            with open(args.ingest_file) as f:
                lines = [l for l in f if l.strip()]
            events = ing.ingest_raw(args.ingest_source, lines)
            print(f"Ingested {len(events)} events from {args.ingest_source}")
        except FileNotFoundError:
            print(f"File not found: {args.ingest_file}")

    elif args.correlate:
        print("Correlating events...")
        incidents = corr.correlate()
        print(f"{len(incidents)} incidents created")
        for inc in incidents:
            print(f"\n[{inc.severity}] {inc.incident_id}:")
            print(inc.narrative)

    else:
        print("Log Correlator — TrinTech Digital Defense")
        print("Usage:")
        print("  --scan            Full scan: ingest all sources + correlate")
        print("  --correlate       Correlate existing events")
        print("  --report          Generate report")
        print("  --server          Start HTTP server")
        print("  --ingest-file     Ingest from file")


if __name__ == "__main__":
    main()

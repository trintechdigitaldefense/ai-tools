"""
Watchtower Engine — Core correlation and routing logic.

Receives alerts from all TrinTech tools, cross-references them by IP/hostname,
maintains an incident graph, and pushes correlated events to subscribers via SSE.
"""

from __future__ import annotations

import hashlib
import logging
import time
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

logger = logging.getLogger("watchtower.engine")

# ────────────────────────────────────────────────────────────────────
# Supported sources
# ────────────────────────────────────────────────────────────────────
SUPPORTED_SOURCES = {
    "specter",
    "phantom",
    "mirage",
    "ticorr",
    "footprintscanner",
    "logcorrelator",
    "playbook",
    "custom",
}

# Correlation window: how long to look back for linking alerts
CORRELATION_WINDOW_SECONDS = 600  # 10 minutes

# ────────────────────────────────────────────────────────────────────
# Data models
# ────────────────────────────────────────────────────────────────────

@dataclass
class AlertEvent:
    """A single alert received from any tool."""
    alert_id: str
    source: str  # tool name
    alert_type: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW
    timestamp: str  # ISO format
    title: str  # Short human-readable title
    detail: str  # Description
    entities: list[str] = field(default_factory=list)  # IPs, hostnames, domains involved
    raw: dict[str, Any] = field(default_factory=dict)  # Original payload


@dataclass
class CorrelatedIncident:
    """A cluster of related alerts from different sources."""
    incident_id: str
    score: int  # Severity score 1-100
    entities: dict[str, list[AlertEvent]]  # entity -> [alerts]
    sources: set[str]
    created: float  # epoch
    updated: float  # epoch
    child_alerts: list[AlertEvent]


# ────────────────────────────────────────────────────────────────────
# Scoring
# ────────────────────────────────────────────────────────────────────

SEVERITY_WEIGHT = {
    "CRITICAL": 40,
    "HIGH": 25,
    "MEDIUM": 10,
    "LOW": 3,
}

SOURCE_MULTIPLIER = {
    "specter": 1.2,
    "phantom": 1.1,
    "mirage": 1.3,
    "ticorr": 1.15,
    "logcorrelator": 1.1,
    "footprintscanner": 0.8,
    "playbook": 0.5,
    "custom": 1.0,
}


def compute_incident_score(alerts: list[AlertEvent]) -> int:
    """Compute a 1-100 severity score for a correlated incident."""
    if not alerts:
        return 0

    total = 0
    for a in alerts:
        base = SEVERITY_WEIGHT.get(a.severity.upper(), 5)
        mult = SOURCE_MULTIPLIER.get(a.source, 1.0)
        total += base * mult

    # Multi-source bonus: if alerts come from 2+ different tools, add bonus
    sources = len({a.source for a in alerts})
    if sources >= 2:
        total += (sources - 1) * 8

    # Cap at 100
    return min(100, total)


def severity_from_score(score: int) -> str:
    """Map numeric score to severity label."""
    if score >= 70:
        return "CRITICAL"
    elif score >= 45:
        return "HIGH"
    elif score >= 20:
        return "MEDIUM"
    else:
        return "LOW"


# ────────────────────────────────────────────────────────────────────
# Entity extraction helpers
# ────────────────────────────────────────────────────────────────────

import re

# IPv4 pattern
_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
# IPv6 simplified
_IPV6 = re.compile(r"\b(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}\b")
# Domain pattern (with TLD)
_DOMAIN = re.compile(r"\b[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z]{2,})+\b")
# Hostname pattern: must contain a hyphen or number to avoid matching plain words (e.g. corp-server-01, server1)
_HOSTNAME = re.compile(r"\b[a-zA-Z0-9]+(?:[a-zA-Z0-9-]*[0-9][a-zA-Z0-9-]*)\b(?!\.(?:[0-9]{1,3}\.){3}[0-9]{1,3})(?!\.\w{2,})")


def extract_entities(text: str) -> list[str]:
    """Extract IPs, domains, and hostnames from a text block."""
    entities: list[str] = []
    seen: set[str] = set()
    for m in list(_IPV4.finditer(text)) + list(_IPV6.finditer(text)):
        ip = m.group()
        # Basic IPv4 validation
        parts = ip.split(".")
        if len(parts) == 4 and all(0 <= int(p) <= 255 for p in parts):
            if ip not in seen:
                seen.add(ip)
                entities.append(ip)
    for m in _DOMAIN.finditer(text):
        d = m.group()
        if d not in seen and not d.startswith("http"):
            seen.add(d)
            entities.append(d)
    for m in _HOSTNAME.finditer(text):
        h = m.group()
        if h not in seen and not h.startswith("http") and len(h) >= 3:
            seen.add(h)
            entities.append(h)
    return entities


# ────────────────────────────────────────────────────────────────────
# Main Engine
# ────────────────────────────────────────────────────────────────────


class WatchtowerEngine:
    """
    Core Watchtower engine.

    Maintains:
    - alert_queue: FIFO of all received alerts
    - incidents: dict of incident_id -> CorrelatedIncident
    - _entity_map: {entity_str -> set[incident_id]} for fast lookup
    """

    def __init__(self):
        self.alert_queue: list[AlertEvent] = []
        self.incidents: dict[str, CorrelatedIncident] = {}
        self._entity_map: dict[str, set[str]] = defaultdict(set)
        self._max_alerts = 10_000  # Keep this from growing forever
        self._subscriber_callbacks: list[callable] = []

    # ── Subscriber management ──

    def subscribe(self, callback: callable) -> None:
        """Register an SSE subscriber callback(callback_type, data)."""
        self._subscriber_callbacks.append(callback)

    def _broadcast(self, event_type: str, data: dict) -> None:
        """Push an event to all subscribers."""
        for cb in self._subscriber_callbacks:
            try:
                cb(event_type, data)
            except Exception:
                logger.exception("SSE subscriber error")

    # ── Alert ingestion ──

    def ingest(self, source: str, raw: list[dict[str, Any]]) -> list[AlertEvent]:
        """
        Ingest alerts from a tool.

        Each alert dict can have flexible structure; we normalize:
          {
            "alert_id": str (auto-gen if missing)
            "alert_type": str
            "severity": str
            "title": str
            "detail": str
            "src_ip": str  (converted to entities)
            "dst_ip": str  (converted to entities)
            "hostname": str
            "timestamp": str
            ...extra
          }
        """
        if source not in SUPPORTED_SOURCES:
            logger.warning(f"Ignoring unsupported source: {source}")
            return []

        events: list[AlertEvent] = []
        for item in raw:
            alert = self._normalize_alert(source, item)
            if alert:
                events.append(alert)
                self.alert_queue.append(alert)

        # Auto-correlate new alerts
        if events:
            self._correlate_events(events)

        # Trim queue
        if len(self.alert_queue) > self._max_alerts:
            self.alert_queue = self.alert_queue[-self._max_alerts:]

        return events

    def ingest_single(self, source: str, raw: dict[str, Any]) -> AlertEvent | None:
        """Convenience wrapper for a single alert."""
        results = self.ingest(source, [raw])
        return results[0] if results else None

    def _normalize_alert(self, source: str, raw: dict[str, Any]) -> AlertEvent | None:
        """Normalize a raw alert dict into an AlertEvent."""
        ts = raw.get("timestamp", datetime.now().isoformat())

        # Build entities from common fields
        entities: list[str] = list(raw.get("entities", []))
        for key in ("src_ip", "dst_ip", "ip", "source_ip", "dest_ip"):
            if key in raw and raw[key]:
                entities.append(str(raw[key]))
        for key in ("hostname", "host", "target", "affected_host"):
            if key in raw and raw[key]:
                entities.append(str(raw[key]))

        # Also extract from detail/title text
        text = f"{raw.get('title', '')} {raw.get('detail', '')} {raw.get('description', '')}"
        extracted = extract_entities(text)
        for e in extracted:
            if e not in entities:
                entities.append(e)

        title = raw.get("title", raw.get("description", raw.get("alert_type", "Unknown Alert")))
        detail = raw.get("detail", raw.get("description", str(raw.get("message", ""))))
        alert_type = raw.get("alert_type", raw.get("type", source))
        severity = raw.get("severity", raw.get("severity_level", "MEDIUM")).upper()
        if severity not in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            severity = "MEDIUM"

        alert_id = raw.get("alert_id", "")
        if not alert_id:
            alert_id = f"{source}_{hashlib.md5(f'{ts}_{alert_type}_{text[:50]}'.encode()).hexdigest()[:12]}"

        return AlertEvent(
            alert_id=alert_id,
            source=source,
            alert_type=alert_type,
            severity=severity,
            timestamp=ts,
            title=title,
            detail=detail,
            entities=entities,
            raw=raw,
        )

    # ── Correlation ──

    def _correlate_events(self, new_events: list[AlertEvent]) -> None:
        """
        For each new alert, check if it shares entities with existing incidents.
        Either attach to an existing incident or create a new one.
        """
        now = time.time()

        for alert in new_events:
            if not alert.entities:
                # No entities to correlate on — create standalone incident
                inc = CorrelatedIncident(
                    incident_id=f"INC-{len(self.incidents) + 1:04d}",
                    score=compute_incident_score([alert]),
                    entities={f"{alert.source}:{alert.alert_type}": [alert]},
                    sources={alert.source},
                    created=now,
                    updated=now,
                    child_alerts=[alert],
                )
                self.incidents[inc.incident_id] = inc
                continue

            # Find matching incidents via entity map
            matching_ids: set[str] = set()
            for entity in alert.entities:
                if entity in self._entity_map:
                    matching_ids.update(self._entity_map[entity])

            # Remove expired incidents from matching set
            valid_ids = {iid for iid in matching_ids if now - self.incidents[iid].updated < CORRELATION_WINDOW_SECONDS}
            matching_ids = valid_ids

            if matching_ids:
                # Attach to first matching incident (may span multiple — we merge)
                primary_id = min(matching_ids)  # deterministic
                primary = self.incidents[primary_id]

                # Add to primary's entities
                entity_key = f"{alert.source}:{alert.alert_type}"
                if entity_key not in primary.entities:
                    primary.entities[entity_key] = []
                primary.entities[entity_key].append(alert)
                primary.child_alerts.append(alert)
                primary.sources.add(alert.source)
                primary.updated = now

                # Re-score
                primary.score = compute_incident_score(primary.child_alerts)
                new_sev = severity_from_score(primary.score)

                # Broadcast update
                self._broadcast("incident_update", {
                    "incident_id": primary_id,
                    "score": primary.score,
                    "severity": new_sev,
                    "total_alerts": len(primary.child_alerts),
                    "new_alert": alert.alert_id,
                    "updated": now,
                })
            else:
                # New standalone incident
                inc = CorrelatedIncident(
                    incident_id=f"INC-{len(self.incidents) + 1:04d}",
                    score=compute_incident_score([alert]),
                    entities={f"{alert.source}:{alert.alert_type}": [alert]},
                    sources={alert.source},
                    created=now,
                    updated=now,
                    child_alerts=[alert],
                )
                self.incidents[inc.incident_id] = inc

                # Index entities
                for entity in alert.entities:
                    self._entity_map[entity].add(inc.incident_id)

                # Broadcast
                self._broadcast("new_incident", {
                    "incident_id": inc.incident_id,
                    "score": inc.score,
                    "severity": severity_from_score(inc.score),
                    "total_alerts": 1,
                    "sources": list(inc.sources),
                    "entities": alert.entities[:5],
                    "updated": now,
                })

    # ── Query helpers ──

    def get_all_alerts(self, source: str | None = None, limit: int = 100) -> list[AlertEvent]:
        """Get recent alerts, optionally filtered by source."""
        alerts = self.alert_queue
        if source:
            alerts = [a for a in alerts if a.source == source]
        return list(reversed(alerts))[:limit]

    def get_all_incidents(self) -> list[CorrelatedIncident]:
        """Get all current incidents."""
        return list(self.incidents.values())

    def get_incident(self, incident_id: str) -> CorrelatedIncident | None:
        return self.incidents.get(incident_id)

    def get_stats(self) -> dict[str, Any]:
        """Dashboard statistics."""
        now = time.time()
        active_incidents = {
            iid: inc for iid, inc in self.incidents.items()
            if now - inc.updated < CORRELATION_WINDOW_SECONDS * 2
        }
        severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for inc in active_incidents.values():
            sev = severity_from_score(inc.score)
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        source_counts: dict[str, int] = defaultdict(int)
        for a in self.alert_queue[-500:]:
            source_counts[a.source] += 1

        return {
            "total_alerts": len(self.alert_queue),
            "total_incidents": len(self.incidents),
            "active_incidents": len(active_incidents),
            "severity_breakdown": severity_counts,
            "alerts_by_source": dict(source_counts),
            "supported_sources": list(SUPPORTED_SOURCES),
            "correlation_window_seconds": CORRELATION_WINDOW_SECONDS,
        }

    def get_incident_feed(self, limit: int = 20) -> list[dict[str, Any]]:
        """Get recent incidents with summaries for the dashboard feed."""
        incidents = sorted(
            self.incidents.values(),
            key=lambda i: i.updated,
            reverse=True,
        )[:limit]

        feed = []
        for inc in incidents:
            new_sev = severity_from_score(inc.score)
            feed.append({
                "incident_id": inc.incident_id,
                "score": inc.score,
                "severity": new_sev,
                "total_alerts": len(inc.child_alerts),
                "sources": sorted(inc.sources),
                "entities": list(inc.entities.keys())[:10],
                "updated_ago": f"{int(time.time() - inc.updated)}s ago",
                "updated": inc.updated,
            })
        return feed

    def clear(self) -> int:
        """Clear all state. Returns number of items cleared."""
        cleared = len(self.alert_queue) + len(self.incidents)
        self.alert_queue.clear()
        self.incidents.clear()
        self._entity_map.clear()
        return cleared

"""
Phantom — Network Traffic Analyzer & Protocol Auditor
Core Analysis Engine

Packet classification, protocol detection, anomaly scoring,
beacon detection, and covert channel identification.

Usage:
  from phantom.engine import TrafficAnalyzer

  analyzer = TrafficAnalyzer()
  analyzer.add_event(event_dict)  # from packet parser or direct event
  result = analyzer.analyze()
  alerts = analyzer.get_alerts()

Author: Jason Junior Ramdharry
Built by: AI Agent — TrinTech Digital Defense
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import statistics
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

import sqlite3

logger = logging.getLogger("phantom.engine")

# ────────────────────────────────────────────────────────────────
# Protocol & Port Definitions
# ────────────────────────────────────────────────────────────────

WELL_KNOWN_PORTS: dict[int, str] = {
    20: "FTP-DATA", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 67: "DHCP", 68: "DHCP", 80: "HTTP", 110: "POP3",
    123: "NTP", 135: "MS-RPC", 137: "NETBIOS-NS", 138: "NETBIOS-DGM",
    139: "NETBIOS-SSN", 143: "IMAP", 161: "SNMP", 162: "SNMP-TRAP",
    443: "HTTPS", 445: "SMB", 465: "SMTPS", 514: "Syslog",
    587: "SMTP-STARTTLS", 993: "IMAPS", 995: "POP3S",
    1433: "MSSQL", 1521: "Oracle", 3306: "MySQL", 3389: "RDP",
    5432: "PostgreSQL", 5900: "VNC", 6379: "Redis", 8080: "HTTP-ALT",
    8443: "HTTPS-ALT", 27017: "MongoDB",
}

SUSPICIOUS_PORTS: set[int] = {
    4444, 5555, 6666, 6667, 6668, 6669,  # Common backdoor/CNC ports
    1337, 31337, 12345, 54321, 9999,  # Classic malware ports
    3128, 8888, 9090,  # Tor/Proxy common ports
    1080, 9050, 9051,  # Tor ports
    8880, 8383,  # Common mining proxy ports
}

DNS_CRITICAL_RECORDS = {"A", "AAAA", "MX", "TXT", "CNAME", "NS", "SOA", "PTR", "SRV"}

DNS_TLD_SUSPICIOUS = {
    ".bit", ".onion", ".xyz", ".top", ".click", ".loan", ".work",
    ".gq", ".ml", ".cf", ".ga", ".tk", ".buzz", ".club", ".stream",
}

COMMON_PROTOCOL_SIGNATURES: dict[str, list[bytes]] = {
    "HTTP": [b"GET ", b"POST ", b"PUT ", b"DELETE ", b"HEAD ", b"OPTIONS "],
    "HTTPS": [],  # TLS handshake magic
    "SSH": [b"SSH-"],
    "FTP": [b"220 ", b"230 ", b"331 "],
    "SMTP": [b"220 ", b"EHLO ", b"MAIL FROM"],
    "DNS": [],  # Detected by port + packet structure
    "TLS": [bytes([0x16])],  # TLS record type
}

COVERT_CHANNEL_INDICATORS: dict[str, list[str]] = {
    "dns_tunnel": ["TXT", "NULL", "CNAME"],
    "icmp_tunnel": ["timestamp", "echo", "redirect"],
    "http_covert": ["user-agent", "cookie", "referer"],
}

ANOMALY_SCORES: dict[str, float] = {
    "suspicious_port": 8.0,
    "unusual_protocol": 6.0,
    "dns_tunnel_suspect": 9.0,
    "high_volume_dns": 5.0,
    "beaconing_detected": 9.0,
    "data_exfil_suspect": 8.5,
    "scan_detected": 7.0,
    "protocol_mismatch": 6.5,
    "encrypted_covert": 7.5,
    "unusual_packet_size": 4.0,
    "uncommon_tld": 5.5,
    "port_hopping": 7.5,
}


# ── Alert Deduplication Config ──

# Dedup window: alerts of same type from same IP within this window merge
DEDUP_WINDOW_SECONDS = 300  # 5 minutes
DEDUP_THRESHOLD = 1  # Minimum alerts of same type/IP before merging

# Dedup by: alert_type + IPs set
# If a new alert of same type from same IPs arrives within window,
# increment counter instead of creating new alert




# ────────────────────────────────────────────────────────────────
# MITRE ATT&CK Mapping Database
# ────────────────────────────────────────────────────────────────

MITRE_ATTACK: dict[str, dict] = {
    "suspicious_port": {
        "technique": "T1571 — Non-Standard Port",
        "tactic": "Command and Control",
        "subtechnique": None,
        "description": "Communicating over a non-standard port to evade network detection",
        "mitigation": "Block known malicious ports at the perimeter; enforce egress filtering",
    },
    "protocol_mismatch": {
        "technique": "T1095 — Non-Application Layer Protocol",
        "tactic": "Command and Control",
        "subtechnique": None,
        "description": "Running a protocol on a non-standard port to bypass network monitoring",
        "mitigation": "Implement protocol-aware firewalls and deep packet inspection",
    },
    "dns_tunnel_suspect": {
        "technique": "T1071.004 — DNS",
        "tactic": "Command and Control",
        "subtechnique": "Application Layer Protocol: DNS",
        "description": "Using DNS TXT records to exfiltrate data and establish covert C2 channel",
        "mitigation": "Monitor DNS query volume and TXT record ratios; block suspicious TLDs",
    },
    "high_volume_dns": {
        "technique": "T1071.004 — DNS",
        "tactic": "Command and Control",
        "subtechnique": "Application Layer Protocol: DNS",
        "description": "Excessive DNS queries indicate potential DNS-based exfiltration or C2",
        "mitigation": "Set DNS query rate limits; deploy DNS firewall",
    },
    "beaconing_detected": {
        "technique": "T1071 — Application Layer Protocol",
        "tactic": "Command and Control",
        "subtechnique": None,
        "description": "Regular interval communication pattern consistent with C2 beaconing",
        "mitigation": "Implement behavioral network monitoring; detect periodic callbacks",
    },
    "scan_detected": {
        "technique": "T1046 — Network Service Scanning",
        "tactic": "Discovery",
        "subtechnique": None,
        "description": "Port scanning activity detected from source IP",
        "mitigation": "Implement IDS/IPS; restrict outbound connections; use port knocking",
    },
    "data_exfil_suspect": {
        "technique": "T1048 — Exfiltration Over Alternative Protocol",
        "tactic": "Exfiltration",
        "subtechnique": None,
        "description": "Unusually large outbound data transfer suggests data exfiltration",
        "mitigation": "Monitor outbound volume; implement DLP; restrict large transfers",
    },
    "uncommon_tld": {
        "technique": "T1568 — Dynamic Resolution",
        "tactic": "Command and Control",
        "subtechnique": None,
        "description": "Queries to suspicious TLDs often associated with C2 infrastructure",
        "maintainance": "Block known malicious TLDs; use threat intel feeds",
    },
    "port_hopping": {
        "technique": "T1571 — Non-Standard Port",
        "tactic": "Command and Control",
        "subtechnique": None,
        "description": "Rapid source port changes from a single connection — evasion technique",
        "mitigation": "Track connection state; correlate port hops to single sessions",
    },
    "icmp_covert_channel": {
        "technique": "T1095 — Non-Application Layer Protocol",
        "tactic": "Command and Control",
        "subtechnique": None,
        "description": "Large ICMP packets indicate potential ICMP tunnel for covert data transfer",
        "mitigation": "Block oversized ICMP packets at the firewall; rate-limit ICMP",
    },
    "unusual_packet_size": {
        "technique": "T1572 — Protocol Tunneling",
        "tactic": "Command and Control",
        "subtechnique": None,
        "description": "Unusually large or small packets may indicate data exfiltration or tunneling",
        "mitigation": "Monitor packet size distributions; detect statistical outliers",
    },
    "volume_anomaly": {
        "technique": "T1020 — Automated Exfiltration",
        "tactic": "Exfiltration",
        "subtechnique": None,
        "description": "Traffic volume deviation from baseline indicates potential data exfiltration",
        "mitigation": "Establish baseline traffic volumes; alert on significant deviations",
    },
    "ip_reputation_high": {
        "technique": "T1078 — Valid Accounts",
        "tactic": "Initial Access",
        "subtechnique": None,
        "description": "IP associated with high-reputation threat intelligence indicators",
        "mitigation": "Cross-reference IPs against threat intelligence feeds",
    },
    "ip_reputation_critical": {
        "technique": "T1587 — Develop Capabilities",
        "tactic": "Initial Access",
        "subtechnique": None,
        "description": "IP with critical reputation — known malicious infrastructure",
        "mitigation": "Block immediately; escalate to SOC; investigate all related events",
    },
}


# ────────────────────────────────────────────────────────────────
# Event Data Classes
# ────────────────────────────────────────────────────────────────

class TrafficEvent:
    """Represents a single network traffic event."""

    def __init__(
        self,
        timestamp: str,
        src_ip: str,
        dst_ip: str,
        src_port: int,
        dst_port: int,
        protocol: str,
        direction: str = "outbound",
        payload_size: int = 0,
        duration: float = 0.0,
        raw_hex: str | None = None,
        metadata: dict | None = None,
    ):
        self.timestamp = timestamp
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.protocol = protocol.upper()
        self.direction = direction
        self.payload_size = payload_size
        self.duration = duration
        self.raw_hex = raw_hex or ""
        self.metadata = metadata or {}
        self.event_id = self._make_id()

    def _make_id(self) -> str:
        raw = f"{self.timestamp}{self.src_ip}{self.dst_ip}{self.src_port}{self.dst_port}{self.protocol}"
        return f"PH-{hashlib.md5(raw.encode()).hexdigest()[:10].upper()}"

    def to_dict(self) -> dict:
        return {
            "event_id": self.event_id,
            "timestamp": self.timestamp,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "protocol": self.protocol,
            "direction": self.direction,
            "payload_size": self.payload_size,
            "duration": self.duration,
            "raw_hex": self.raw_hex,
            "metadata": self.metadata,
        }

    def __repr__(self):
        return (f"TrafficEvent({self.event_id} {self.src_ip}:{self.src_port} -> "
                f"{self.dst_ip}:{self.dst_port} {self.protocol})")


class AnomalyAlert:
    """Represents an anomaly detected during traffic analysis."""

    def __init__(
        self,
        alert_type: str,
        severity: str,
        score: float,
        source: str,
        details: str,
        event_ids: list[str] | None = None,
        ips: list[str] | None = None,
        ports: list[int] | None = None,
        metadata: dict | None = None,
    ):
        self.alert_id = f"AL-{hashlib.md5(f'{alert_type}{source}{datetime.now().isoformat()}'.encode()).hexdigest()[:8].upper()}"
        self.alert_type = alert_type
        self.severity = severity  # LOW, MEDIUM, HIGH, CRITICAL
        self.score = score
        self.source = source
        self.details = details
        self.timestamp = datetime.now().isoformat()
        self.event_ids = event_ids or []
        self.ips = ips or []
        self.ports = ports or []
        self.metadata = metadata or {}
        self.status = "NEW"  # NEW, INVESTIGATING, CONFIRMED, FALSE_POSITIVE, RESOLVED

    def to_dict(self) -> dict:
        return {
            "alert_id": self.alert_id,
            "alert_type": self.alert_type,
            "severity": self.severity,
            "score": self.score,
            "source": self.source,
            "details": self.details,
            "timestamp": self.timestamp,
            "event_ids": self.event_ids,
            "ips": self.ips,
            "ports": self.ports,
            "status": self.status,
            "metadata": self.metadata,
        }

    def __repr__(self):
        return f"AnomalyAlert({self.alert_id} [{self.severity}] {self.alert_type}: {self.details[:60]})"


# ────────────────────────────────────────────────────────────────
# Traffic Analyzer
# ────────────────────────────────────────────────────────────────

class TrafficAnalyzer:
    """
    Core traffic analysis engine.

    Analyzes network traffic events for:
    - Protocol classification and verification
    - Anomaly detection (beaconing, scanning, data exfiltration)
    - Covert channel detection (DNS tunneling, ICMP tunneling)
    - Suspicious port and protocol identification
    - Confidence scoring and severity classification

    Args:
        db_path: Path to SQLite database for persistent storage
        reports_dir: Directory for generated reports
        max_events: Maximum events to keep in memory (default: 100000)
    """

    def __init__(
        self,
        db_path: str | Path | None = None,
        reports_dir: str | Path | None = None,
        max_events: int = 100000,
    ):
        self.max_events = max_events
        self.reports_dir = Path(reports_dir or "phantom/exports")
        self.reports_dir.mkdir(parents=True, exist_ok=True)

        # Storage
        if db_path is None:
            self.db_path = Path(self.reports_dir.parent) / "phantom_traffic.db"
        else:
            self.db_path = Path(db_path)

        self.events: list[TrafficEvent] = []
        self.alerts: list[AnomalyAlert] = []
        self.event_index: dict[str, list[int]] = defaultdict(list)  # key -> event indices
        self.alert_index: dict[str, list[int]] = defaultdict(list)  # alert_type -> alert indices

        # Analysis state
        self._connection_tracker: dict[str, list[dict]] = defaultdict(list)  # connection hash -> events
        self._dns_tracker: dict[str, list[dict]] = defaultdict(list)  # src_ip -> DNS events
        self._beacon_tracker: dict[str, list[float]] = defaultdict(list)  # dst_ip -> timestamps
        self._scan_tracker: dict[str, list[int]] = defaultdict(list)  # src_ip -> dst_ports
        self._volume_tracker: dict[str, int] = defaultdict(int)  # src_ip -> total bytes
        self._ip_history: dict[str, dict] = defaultdict(lambda: {
            "total_events": 0,
            "ports_seen": set(),
            "protocols_seen": set(),
            "dst_ips": set(),
            "first_seen": None,
            "last_seen": None,
        })

        # Initialize database
        self._init_db()

        # ── Deduplication state ──
        self._dedup_tracker: dict[str, dict] = {}  # dedup_key -> {"count": int, "latest": Alert, "first_seen": float, "last_seen": float}

    def _init_db(self) -> None:
        """Initialize SQLite database for traffic events and alerts."""
        with sqlite3.connect(str(self.db_path)) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS events (
                    event_id TEXT PRIMARY KEY,
                    timestamp TEXT NOT NULL,
                    src_ip TEXT NOT NULL,
                    dst_ip TEXT NOT NULL,
                    src_port INTEGER NOT NULL,
                    dst_port INTEGER NOT NULL,
                    protocol TEXT NOT NULL,
                    direction TEXT NOT NULL,
                    payload_size INTEGER DEFAULT 0,
                    duration REAL DEFAULT 0.0,
                    raw_hex TEXT,
                    metadata TEXT,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS alerts (
                    alert_id TEXT PRIMARY KEY,
                    alert_type TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    score REAL NOT NULL,
                    source TEXT NOT NULL,
                    details TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    event_ids TEXT,
                    ips TEXT,
                    ports TEXT,
                    status TEXT DEFAULT 'NEW',
                    metadata TEXT,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                    updated_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
            """)
            # Indexes
            conn.execute("CREATE INDEX IF NOT EXISTS idx_events_src_ip ON events(src_ip)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_events_dst_ip ON events(dst_ip)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_events_dst_port ON events(dst_port)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_events_protocol ON events(protocol)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_alerts_type ON alerts(alert_type)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_alerts_ips ON alerts(ips)")
            conn.commit()


    # ── Alert Deduplication ──

    def _dedup_alert(self, alert: AnomalyAlert) -> bool:
        """
        Check if an alert should be deduplicated.
        Returns True if the alert was merged (deduplicated), False if it should be kept.
        Dedup key: alert_type + sorted IPs + sorted ports (if any).
        Only alerts of the same type targeting the same IPs and ports within the window merge.
        """
        if not alert.alert_type:
            return False  # Cannot dedup without type

        # Build key from alert_type, IPs, and ports (if present)
        parts = [alert.alert_type]
        if alert.ips:
            parts.append('I:' + '|'.join(sorted(alert.ips)))
        if alert.ports:
            parts.append('P:' + '|'.join(str(p) for p in sorted(alert.ports)))
        dedup_key = '::'.join(parts)
        now = datetime.now().timestamp()

        if dedup_key in self._dedup_tracker:
            entry = self._dedup_tracker[dedup_key]
            elapsed = now - entry["first_seen"]

            if elapsed <= DEDUP_WINDOW_SECONDS:
                # Within window — merge
                entry["count"] += 1
                entry["last_seen"] = now

                # Merge event_ids and ports
                existing = entry["latest"]
                existing.event_ids = list(set(existing.event_ids) | set(alert.event_ids or []))
                if alert.ports:
                    existing.ports = list(set(existing.ports) | set(alert.ports or []))

                # Keep the highest severity
                sev_order = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
                if sev_order.get(alert.severity, 0) > sev_order.get(existing.severity, 0):
                    existing.severity = alert.severity
                    existing.score = alert.score

                # Update details to show merged count
                existing.details = (
                    f"[DUPLICATE x{entry['count']}] {alert.details}"
                )
                return True

        # New or expired — register this alert
        self._dedup_tracker[dedup_key] = {
            "count": 1,
            "latest": alert,
            "first_seen": now,
            "last_seen": now,
        }
        return False

    def dedup_alerts(self) -> dict:
        """
        Run deduplication on all current alerts.
        Returns dict with dedup statistics.
        Idempotent: calling twice produces same result.
        """
        if not self.alerts:
            return {"total": 0, "removed": 0, "kept": 0}

        # Clear tracker to make this idempotent — re-run dedup from scratch
        self._dedup_tracker.clear()

        # Rebuild alerts list after dedup
        deduped = []
        removed_count = 0

        for alert in self.alerts:
            if self._dedup_alert(alert):
                removed_count += 1
            else:
                # Re-check existing deduped list
                deduped.append(alert)

        self.alerts = deduped

        # Clean up expired entries
        now = datetime.now().timestamp()
        expired_keys = []
        for key, entry in self._dedup_tracker.items():
            if now - entry["last_seen"] > DEDUP_WINDOW_SECONDS * 2:
                expired_keys.append(key)
        for key in expired_keys:
            del self._dedup_tracker[key]

        return {
            "total": removed_count + len(deduped),
            "removed": removed_count,
            "kept": len(deduped),
        }

    def get_dedup_stats(self) -> dict:
        """Get deduplication statistics."""
        now = datetime.now().timestamp()
        active = 0
        expired = 0
        for key, entry in self._dedup_tracker.items():
            if now - entry["last_seen"] <= DEDUP_WINDOW_SECONDS * 2:
                active += 1
            else:
                expired += 1
        return {
            "active_groups": active,
            "expired_groups": expired,
            "total_groups": len(self._dedup_tracker),
            "window_seconds": DEDUP_WINDOW_SECONDS,
        }

    # ── Event Ingestion ──

    def add_event(self, event: TrafficEvent) -> None:
        """Add a traffic event to the analyzer."""
        if len(self.events) >= self.max_events:
            # Remove oldest 10%
            remove_count = self.max_events // 10
            self.events = self.events[remove_count:]
            self.event_index.clear()

        idx = len(self.events)
        self.events.append(event)
        self.event_index["all"].append(idx)
        self.event_index[event.src_ip].append(idx)
        self.event_index[event.dst_ip].append(idx)
        self.event_index[event.protocol].append(idx)
        self.event_index[str(event.dst_port)].append(idx)

        # Update tracking indexes
        conn_hash = f"{event.src_ip}->{event.dst_ip}"
        self._connection_tracker[conn_hash].append(event.to_dict())

        if event.protocol == "DNS" or event.dst_port == 53:
            self._dns_tracker[event.src_ip].append(event.to_dict())

        # Beacon tracking — track destination timestamps
        self._beacon_tracker[f"{event.src_ip}->{event.dst_ip}"].append(
            datetime.fromisoformat(event.timestamp).timestamp()
        )

        # Scan tracking
        self._scan_tracker[event.src_ip].append(event.dst_port)

        # Volume tracking
        self._volume_tracker[event.src_ip] += event.payload_size

        # IP history tracking for reputation scoring
        ip_data = self._ip_history[event.src_ip]
        ip_data["total_events"] += 1
        ip_data["ports_seen"].add(event.dst_port)
        ip_data["protocols_seen"].add(event.protocol)
        ip_data["dst_ips"].add(event.dst_ip)
        if ip_data["first_seen"] is None or event.timestamp < ip_data["first_seen"]:
            ip_data["first_seen"] = event.timestamp
        if ip_data["last_seen"] is None or event.timestamp > ip_data["last_seen"]:
            ip_data["last_seen"] = event.timestamp

        # Also track destination IPs (using their dst_port from the source's perspective)
        dst_data = self._ip_history[event.dst_ip]
        dst_data["total_events"] += 1
        dst_data["ports_seen"].add(event.dst_port)
        dst_data["protocols_seen"].add(event.protocol)
        dst_data["dst_ips"].add(event.src_ip)
        if dst_data["first_seen"] is None or event.timestamp < dst_data["first_seen"]:
            dst_data["first_seen"] = event.timestamp
        if dst_data["last_seen"] is None or event.timestamp > dst_data["last_seen"]:
            dst_data["last_seen"] = event.timestamp

        # Persist to SQLite
        try:
            with sqlite3.connect(str(self.db_path)) as conn:
                conn.execute("""
                    INSERT OR IGNORE INTO events
                    (event_id, timestamp, src_ip, dst_ip, src_port, dst_port,
                     protocol, direction, payload_size, duration, raw_hex, metadata)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    event.event_id, event.timestamp, event.src_ip, event.dst_ip,
                    event.src_port, event.dst_port, event.protocol, event.direction,
                    event.payload_size, event.duration, event.raw_hex,
                    json.dumps(event.metadata) if event.metadata else None,
                ))
        except Exception as e:
            logger.debug(f"DB insert failed for {event.event_id}: {e}")

    def add_events(self, events: list[TrafficEvent]) -> None:
        """Add multiple events."""
        for event in events:
            self.add_event(event)

    @staticmethod
    def parse_raw_packet(
        src_ip: str,
        dst_ip: str,
        src_port: int,
        dst_port: int,
        protocol: str,
        payload_hex: str,
        timestamp: str | None = None,
        direction: str = "outbound",
    ) -> TrafficEvent:
        """
        Parse raw packet data into a TrafficEvent.

        Args:
            src_ip: Source IP address
            dst_ip: Destination IP address
            src_port: Source port
            dst_port: Destination port
            protocol: Protocol name (TCP, UDP, ICMP, etc.)
            payload_hex: Hex-encoded payload data
            timestamp: ISO format timestamp
            direction: Event direction

        Returns:
            TrafficEvent instance
        """
        payload_size = len(bytes.fromhex(payload_hex)) if payload_hex else 0
        return TrafficEvent(
            timestamp=timestamp or datetime.now().isoformat(),
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            protocol=protocol,
            direction=direction,
            payload_size=payload_size,
            raw_hex=payload_hex,
        )

    # ── Analysis ──

    def analyze(self) -> dict:
        """
        Run all analysis modules on the ingested events.

        Returns:
            Analysis results with alerts, statistics, and findings.
        """
        self.alerts = []  # Clear previous alerts
        self._dedup_tracker.clear()  # Clear dedup state for fresh analysis

        results = {
            "total_events": len(self.events),
            "total_alerts": 0,
            "critical_alerts": 0,
            "high_alerts": 0,
            "medium_alerts": 0,
            "low_alerts": 0,
            "alerts": [],
            "statistics": {},
            "unique_ips": set(),
            "protocols": set(),
            "suspicious_connections": [],
        }

        if not self.events:
            return results

        # Run analysis modules
        self._detect_suspicious_ports(results)
        self._detect_protocol_mismatches(results)
        self._detect_dns_anomalies(results)
        self._detect_beaconing(results)
        self._detect_scanning(results)
        self._detect_data_exfiltration(results)
        self._detect_volume_anomalies(results)
        self._detect_ip_reputation(results)
        self._detect_baseline_anomalies(results)
        self._detect_port_hopping(results)
        self._detect_covert_channels(results)

        # Run deduplication on collected alerts
        dedup_result = self.dedup_alerts()
        logger.debug(f"Dedup: {dedup_result['removed']} alerts removed, {dedup_result['kept']} kept")

        # Aggregate results
        results["dedup_stats"] = dedup_result
        results["total_alerts"] = len(self.alerts)
        results["critical_alerts"] = sum(1 for a in self.alerts if a.severity == "CRITICAL")
        results["high_alerts"] = sum(1 for a in self.alerts if a.severity == "HIGH")
        results["medium_alerts"] = sum(1 for a in self.alerts if a.severity == "MEDIUM")
        results["low_alerts"] = sum(1 for a in self.alerts if a.severity == "LOW")

        # Collect statistics
        results["statistics"] = self._compute_statistics()
        results["unique_ips"] = sorted(set(
            e.src_ip for e in self.events
        ) | set(e.dst_ip for e in self.events))
        results["protocols"] = sorted(set(e.protocol for e in self.events))
        results["alerts"] = [a.to_dict() for a in self.alerts]

        # Enrich with MITRE ATT&CK and IP reputation
        results = self._build_analysis_summary(results)

        # ── SSE Alert Push (for server-side streaming) ──
        # Push alerts to SSE queue if the server module is loaded
        try:
            import phantom_server as _ps
            for alert in self.alerts:
                _ps._latest_alerts.append(alert.to_dict())
                _ps._alert_queue.put(alert.to_dict())
            _ps._latest_stats = {
                "total_events": len(self.events),
                "total_alerts": len(self.alerts),
                "critical": results.get("critical_alerts", 0),
                "high": results.get("high_alerts", 0),
                "medium": results.get("medium_alerts", 0),
                "low": results.get("low_alerts", 0),
            }
        except ImportError:
            pass  # Server not loaded, skip SSE push

        return results

    # ── Detection Modules ──

    def _detect_suspicious_ports(self, results: dict) -> None:
        """Detect traffic on suspicious/malware-associated ports."""
        for event in self.events:
            if event.dst_port in SUSPICIOUS_PORTS or event.src_port in SUSPICIOUS_PORTS:
                ips = list({event.src_ip, event.dst_ip})
                ports = list({event.src_port, event.dst_port})
                alert = AnomalyAlert(
                    alert_type="suspicious_port",
                    severity="HIGH",
                    score=ANOMALY_SCORES["suspicious_port"],
                    source="phantom_engine",
                    details=(
                        f"Traffic detected on suspicious port {event.dst_port} "
                        f"({event.protocol}) between {event.src_ip} and {event.dst_ip}"
                    ),
                    event_ids=[event.event_id],
                    ips=ips,
                    ports=ports,
                )
                self.alerts.append(alert)
                results["suspicious_connections"].append({
                    "event_id": event.event_id,
                    "port": event.dst_port,
                    "src_ip": event.src_ip,
                    "dst_ip": event.dst_ip,
                    "protocol": event.protocol,
                })

    def _detect_protocol_mismatches(self, results: dict) -> None:
        """Detect protocol/port mismatches (e.g., HTTP on non-80/443)."""
        for event in self.events:
            mismatch = False
            if event.protocol in ("HTTP", "TLS", "SSH", "DNS") and event.dst_port not in (
                80, 443, 8080, 8443, 22, 53
            ):
                if event.protocol == "HTTP" and event.dst_port not in (80, 8080, 8443):
                    mismatch = True
                elif event.protocol == "SSH" and event.dst_port != 22:
                    mismatch = True
                elif event.protocol == "TLS" and event.dst_port not in (443, 8443):
                    mismatch = True

            if mismatch:
                alert = AnomalyAlert(
                    alert_type="protocol_mismatch",
                    severity="MEDIUM",
                    score=ANOMALY_SCORES["protocol_mismatch"],
                    source="phantom_engine",
                    details=(
                        f"Protocol {event.protocol} detected on non-standard port {event.dst_port} "
                        f"from {event.src_ip}"
                    ),
                    event_ids=[event.event_id],
                    ips=[event.src_ip],
                )
                self.alerts.append(alert)

    def _detect_dns_anomalies(self, results: dict) -> None:
        """Detect DNS-based anomalies including tunneling and unusual queries."""
        for src_ip, dns_events in self._dns_tracker.items():
            if not dns_events:
                continue

            # Check for DNS tunneling indicators
            txt_count = 0
            unusual_tld_count = 0
            subdomain_lengths = []

            for evt in dns_events:
                meta = evt.get("metadata", {})
                if meta.get("record_type") == "TXT":
                    txt_count += 1
                if meta.get("unusual_tld") or meta.get("long_subdomain"):
                    unusual_tld_count += 1
                if meta.get("subdomain_length"):
                    subdomain_lengths.append(meta["subdomain_length"])

            # DNS tunneling: excessive TXT queries
            if txt_count > 20 and len(dns_events) > 50:
                alert = AnomalyAlert(
                    alert_type="dns_tunnel_suspect",
                    severity="CRITICAL",
                    score=ANOMALY_SCORES["dns_tunnel_suspect"],
                    source="phantom_engine",
                    details=(
                        f"Possible DNS tunneling from {src_ip}: "
                        f"{txt_count} TXT queries out of {len(dns_events)} DNS events"
                    ),
                    ips=[src_ip],
                )
                self.alerts.append(alert)

            # Unusual TLD queries
            if unusual_tld_count > 10:
                alert = AnomalyAlert(
                    alert_type="uncommon_tld",
                    severity="MEDIUM",
                    score=ANOMALY_SCORES["uncommon_tld"],
                    source="phantom_engine",
                    details=(
                        f"{src_ip} queried {unusual_tld_count} domains with suspicious TLDs"
                    ),
                    ips=[src_ip],
                )
                self.alerts.append(alert)

            # High-volume DNS (potential exfil)
            if len(dns_events) > 100:
                alert = AnomalyAlert(
                    alert_type="high_volume_dns",
                    severity="HIGH",
                    score=ANOMALY_SCORES["high_volume_dns"],
                    source="phantom_engine",
                    details=(
                        f"High-volume DNS activity from {src_ip}: {len(dns_events)} DNS queries"
                    ),
                    ips=[src_ip],
                )
                self.alerts.append(alert)

    def _detect_beaconing(self, results: dict) -> None:
        """Detect periodic beaconing behavior (C2 communication pattern)."""
        for conn_key, timestamps in self._beacon_tracker.items():
            if len(timestamps) < 5:  # Need at least 5 data points
                continue

            sorted_ts = sorted(timestamps)
            intervals = [sorted_ts[i+1] - sorted_ts[i] for i in range(len(sorted_ts)-1)]
            if not intervals:
                continue

            mean_interval = statistics.mean(intervals)
            if mean_interval == 0:
                continue

            try:
                stdev_interval = statistics.stdev(intervals)
            except statistics.StatisticsError:
                continue

            # Low coefficient of variation = regular intervals = beaconing
            cv = stdev_interval / mean_interval if mean_interval > 0 else float('inf')
            if cv < 0.3 and mean_interval > 1:  # Regular interval > 1 second
                parts = conn_key.split("->")
                alert = AnomalyAlert(
                    alert_type="beaconing_detected",
                    severity="CRITICAL",
                    score=ANOMALY_SCORES["beaconing_detected"],
                    source="phantom_engine",
                    details=(
                        f"Beaconing detected: {conn_key} — "
                        f"{len(timestamps)} events, interval={mean_interval:.1f}s, "
                        f"variation={cv:.2f}"
                    ),
                    ips=parts if len(parts) == 2 else [conn_key],
                )
                self.alerts.append(alert)

    def _detect_scanning(self, results: dict) -> None:
        """Detect port scanning behavior."""
        for src_ip, ports in self._scan_tracker.items():
            unique_ports = set(ports)
            if len(unique_ports) > 20:
                alert = AnomalyAlert(
                    alert_type="scan_detected",
                    severity="HIGH",
                    score=ANOMALY_SCORES["scan_detected"],
                    source="phantom_engine",
                    details=(
                        f"Port scanning detected from {src_ip}: "
                        f"{len(unique_ports)} unique destination ports"
                    ),
                    ips=[src_ip],
                    ports=sorted(unique_ports)[:30],
                )
                self.alerts.append(alert)

    def _detect_data_exfiltration(self, results: dict) -> None:
        """Detect potential data exfiltration based on volume."""
        for src_ip, total_bytes in self._volume_tracker.items():
            if total_bytes > 10_000_000:  # > 10MB outbound
                event_count = sum(1 for e in self.events if e.src_ip == src_ip)
                avg_size = total_bytes / event_count if event_count > 0 else 0

                alert = AnomalyAlert(
                    alert_type="data_exfil_suspect",
                    severity="HIGH",
                    score=ANOMALY_SCORES["data_exfil_suspect"],
                    source="phantom_engine",
                    details=(
                        f"Potential data exfiltration from {src_ip}: "
                        f"{total_bytes:,} bytes across {event_count} connections "
                        f"(avg {avg_size:.0f} bytes/event)"
                    ),
                    ips=[src_ip],
                )
                self.alerts.append(alert)

    def _detect_volume_anomalies(self, results: dict) -> None:
        """Detect unusual packet sizes."""
        if not self.events:
            return

        sizes = [e.payload_size for e in self.events if e.payload_size > 0]
        if not sizes or len(sizes) < 10:
            return

        mean_size = statistics.mean(sizes)
        try:
            stdev_size = statistics.stdev(sizes)
        except statistics.StatisticsError:
            return

        if stdev_size == 0:
            return

        for event in self.events:
            if event.payload_size > 0:
                z_score = abs(event.payload_size - mean_size) / stdev_size
                if z_score > 3.5:  # Significant outlier
                    alert = AnomalyAlert(
                        alert_type="unusual_packet_size",
                        severity="MEDIUM",
                        score=ANOMALY_SCORES["unusual_packet_size"],
                        source="phantom_engine",
                        details=(
                            f"Unusual packet size from {event.src_ip}: "
                            f"{event.payload_size:,} bytes (mean={mean_size:.0f}, z={z_score:.2f})"
                        ),
                        event_ids=[event.event_id],
                        ips=[event.src_ip],
                    )
                    self.alerts.append(alert)

    def _detect_port_hopping(self, results: dict) -> None:
        """Detect port hopping behavior (multi-port connection from single source)."""
        port_hop_tracker: dict[str, set[int]] = defaultdict(set)
        for event in self.events:
            conn_key = f"{event.src_ip}->{event.dst_ip}"
            port_hop_tracker[conn_key].add(event.src_port)

        for conn_key, src_ports in port_hop_tracker.items():
            if len(src_ports) > 15:
                parts = conn_key.split("->")
                alert = AnomalyAlert(
                    alert_type="port_hopping",
                    severity="HIGH",
                    score=ANOMALY_SCORES["port_hopping"],
                    source="phantom_engine",
                    details=(
                        f"Port hopping detected: {conn_key} — "
                        f"{len(src_ports)} different source ports"
                    ),
                    ips=parts if len(parts) == 2 else [conn_key],
                )
                self.alerts.append(alert)

    def _detect_covert_channels(self, results: dict) -> None:
        """Detect potential covert channel communication."""
        for event in self.events:
            # Check for ICMP tunnel indicators
            if event.protocol == "ICMP" and event.payload_size > 64:
                alert = AnomalyAlert(
                    alert_type="icmp_covert_channel",
                    severity="HIGH",
                    score=7.0,
                    source="phantom_engine",
                    details=(
                        f"Large ICMP packet ({event.payload_size} bytes) from {event.src_ip} "
                        f"to {event.dst_ip} — possible ICMP tunnel"
                    ),
                    event_ids=[event.event_id],
                    ips=[event.src_ip, event.dst_ip],
                )
                self.alerts.append(alert)

    def _detect_ip_reputation(self, results: dict) -> None:
        """Score IPs based on behavioral reputation indicators."""
        for ip, data in self._ip_history.items():
            if data["total_events"] < 3:
                continue

            score = 0
            reasons = []

            # Suspicious port usage
            sus_port_count = sum(1 for p in data["ports_seen"] if p in SUSPICIOUS_PORTS)
            if sus_port_count > 0:
                score += 3
                reasons.append(f"{sus_port_count} suspicious ports")

            # Protocol variety (scanning indicator)
            if len(data["protocols_seen"]) > 4:
                score += 2
                reasons.append(f"high protocol diversity ({len(data['protocols_seen'])})")

            # Many unique destinations
            if len(data["dst_ips"]) > 10:
                score += 3
                reasons.append(f"many destinations ({len(data['dst_ips'])})")

            # Port diversity
            if len(data["ports_seen"]) > 15:
                score += 2
                reasons.append(f"high port diversity ({len(data['ports_seen'])})")

            if score >= 3:
                severity = "CRITICAL" if score >= 8 else "HIGH" if score >= 5 else "MEDIUM"
                mitre = MITRE_ATTACK.get("ip_reputation_critical" if severity == "CRITICAL" else "ip_reputation_high", {})
                alert = AnomalyAlert(
                    alert_type=f"ip_reputation_{severity.lower()}",
                    severity=severity,
                    score=float(score),
                    source="phantom_engine",
                    details=(
                        f"IP reputation risk score {score}/10 for {ip}: "
                        f"{', '.join(reasons)}"
                    ),
                    ips=[ip],
                    metadata={"risk_score": score, "reasons": reasons, "port_count": len(data["ports_seen"]), "dest_count": len(data["dst_ips"])},
                )
                self.alerts.append(alert)
                results.setdefault("ip_reputation_scores", {})[ip] = score

    def _detect_baseline_anomalies(self, results: dict) -> None:
        """Detect deviations from traffic baselines using statistical analysis."""
        if len(self.events) < 20:
            return

        # Calculate baseline distributions
        port_distribution: dict[int, int] = defaultdict(int)
        protocol_distribution: dict[str, int] = defaultdict(int)
        size_distribution: list[int] = []

        for event in self.events:
            port_distribution[event.dst_port] += 1
            protocol_distribution[event.protocol] += 1
            if event.payload_size > 0:
                size_distribution.append(event.payload_size)

        # Top ports (used by > 20% of traffic are "normal")
        total_events = len(self.events)
        normal_ports = {p for p, c in port_distribution.items() if c > total_events * 0.2}
        normal_protocols = {p for p, c in protocol_distribution.items() if c > total_events * 0.1}

        # Flag IPs that only use unusual ports
        for ip, data in self._ip_history.items():
            unusual_ports = data["ports_seen"] - normal_ports
            unusual_protocols = data["protocols_seen"] - normal_protocols

            # Also consider suspicious ports as unusual
            suspicious_used = data["ports_seen"] & SUSPICIOUS_PORTS
            total_unusual = len(unusual_ports) + len(suspicious_used)

            if total_unusual > 0 and total_unusual >= len(data["ports_seen"]) * 0.5:
                alert = AnomalyAlert(
                    alert_type="baseline_anomaly",
                    severity="MEDIUM",
                    score=5.0,
                    source="phantom_engine",
                    details=(
                        f"IP {ip} uses unusual port profile: "
                        f"{len(unusual_ports)} unusual ports, "
                        f"only {len(unusual_protocols)} normal protocols"
                    ),
                    ips=[ip],
                )
                self.alerts.append(alert)

    def _detect_covert_channels(self, results: dict) -> None:
        """Detect potential covert channel communication."""
        for event in self.events:
            if event.protocol == "ICMP" and event.payload_size > 64:
                alert = AnomalyAlert(
                    alert_type="icmp_covert_channel",
                    severity="HIGH",
                    score=7.0,
                    source="phantom_engine",
                    details=(
                        f"Large ICMP packet ({event.payload_size} bytes) from {event.src_ip} "
                        f"to {event.dst_ip} — possible ICMP tunnel"
                    ),
                    event_ids=[event.event_id],
                    ips=[event.src_ip, event.dst_ip],
                )
                self.alerts.append(alert)

    def _compute_statistics(self) -> dict:
        """Compute traffic statistics from ingested events."""
        if not self.events:
            return {}

        total_bytes = sum(e.payload_size for e in self.events)
        total_duration = sum(e.duration for e in self.events)

        protocol_counts: dict[str, int] = defaultdict(int)
        port_counts: dict[int, int] = defaultdict(int)
        ip_counts: dict[str, int] = defaultdict(int)

        for event in self.events:
            protocol_counts[event.protocol] += 1
            port_counts[event.dst_port] += 1
            ip_counts[event.src_ip] += 1
            ip_counts[event.dst_ip] += 1

        top_talkers = sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:10]
        top_ports = sorted(port_counts.items(), key=lambda x: x[1], reverse=True)[:10]

        return {
            "total_events": len(self.events),
            "total_bytes": total_bytes,
            "total_duration_seconds": round(total_duration, 2),
            "protocols": dict(protocol_counts),
            "top_talkers": [{"ip": ip, "count": count} for ip, count in top_talkers],
            "top_ports": [{"port": port, "count": count} for port, count in top_ports],
            "unique_src_ips": len(set(e.src_ip for e in self.events)),
            "unique_dst_ips": len(set(e.dst_ip for e in self.events)),
            "unique_dst_ports": len(set(e.dst_port for e in self.events)),
            "avg_payload_size": round(total_bytes / len(self.events), 2) if self.events else 0,
        }

    def _build_analysis_summary(self, analysis_result: dict) -> dict:
        """Enrich analysis result with MITRE mappings and IP reputation data."""
        # Add MITRE mappings
        mitre_mappings = []
        for alert in self.alerts:
            mitre_info = MITRE_ATTACK.get(alert.alert_type, {})
            if not mitre_info:
                # Try to match by known prefixes
                for key, info in MITRE_ATTACK.items():
                    if alert.alert_type.startswith(key):
                        mitre_info = info
                        break

            if mitre_info:
                mapping = dict(mitre_info)
                mapping["alert_type"] = alert.alert_type
                mapping["alert_id"] = alert.alert_id
                mitre_mappings.append(mapping)

        analysis_result["mitre_mappings"] = mitre_mappings

        # Add IP reputation scores
        ip_scores: dict[str, int] = {}
        for ip, data in self._ip_history.items():
            if data["total_events"] < 3:
                continue
            score = 0
            sus_port_count = sum(1 for p in data["ports_seen"] if p in SUSPICIOUS_PORTS)
            if sus_port_count > 0:
                score += 3
            if len(data["protocols_seen"]) > 4:
                score += 2
            if len(data["dst_ips"]) > 10:
                score += 3
            if len(data["ports_seen"]) > 15:
                score += 2
            if score >= 3:
                ip_scores[ip] = score

        analysis_result["ip_reputation"] = ip_scores

        return analysis_result

    # ── Retrieval ──

    def get_events(self, filter_ip: str | None = None, filter_protocol: str | None = None, limit: int = 100) -> list[dict]:
        """
        Retrieve events with optional filters.

        Args:
            filter_ip: Filter by source or destination IP
            filter_protocol: Filter by protocol
            limit: Maximum events to return

        Returns:
            List of event dicts
        """
        events = self.events
        if filter_ip:
            events = [e for e in events if e.src_ip == filter_ip or e.dst_ip == filter_ip]
        if filter_protocol:
            events = [e for e in events if e.protocol == filter_protocol.upper()]
        return [e.to_dict() for e in events[-limit:]]

    def get_alerts(self, filter_type: str | None = None, filter_severity: str | None = None) -> list[dict]:
        """
        Retrieve alerts with optional filters.

        Args:
            filter_type: Filter by alert type
            filter_severity: Filter by severity level

        Returns:
            List of alert dicts
        """
        alerts = self.alerts
        if filter_type:
            alerts = [a for a in alerts if a.alert_type == filter_type]
        if filter_severity:
            alerts = [a for a in alerts if a.severity == filter_severity.upper()]
        return [a.to_dict() for a in alerts]

    def get_alert_summary(self) -> dict:
        """Get a summary of all alerts by type and severity."""
        by_type: dict[str, int] = defaultdict(int)
        by_severity: dict[str, int] = defaultdict(int)
        by_status: dict[str, int] = defaultdict(int)

        for alert in self.alerts:
            by_type[alert.alert_type] += 1
            by_severity[alert.severity] += 1
            by_status[alert.status] += 1

        return {
            "total": len(self.alerts),
            "by_type": dict(by_type),
            "by_severity": dict(by_severity),
            "by_status": dict(by_status),
            "alerts": [a.to_dict() for a in self.alerts],
        }

    def get_unique_ips(self) -> list[str]:
        """Get list of all unique IPs seen."""
        return sorted(set(
            e.src_ip for e in self.events
        ) | set(e.dst_ip for e in self.events))

    def get_stats(self) -> dict:
        """Get overall analyzer statistics."""
        return {
            "total_events": len(self.events),
            "total_alerts": len(self.alerts),
            "unique_ips": len(self.get_unique_ips()),
            "protocols": sorted(set(e.protocol for e in self.events)),
            "db_path": str(self.db_path),
        }

    def save_events(self) -> int:
        """Persist all in-memory events to SQLite."""
        count = 0
        try:
            with sqlite3.connect(str(self.db_path)) as conn:
                for event in self.events:
                    conn.execute("""
                        INSERT OR IGNORE INTO events
                        (event_id, timestamp, src_ip, dst_ip, src_port, dst_port,
                         protocol, direction, payload_size, duration, raw_hex, metadata)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, (
                        event.event_id, event.timestamp, event.src_ip, event.dst_ip,
                        event.src_port, event.dst_port, event.protocol, event.direction,
                        event.payload_size, event.duration, event.raw_hex,
                        json.dumps(event.metadata) if event.metadata else None,
                    ))
                    count += 1
                conn.commit()
        except Exception as e:
            logger.debug(f"save_events failed: {e}")
        return count

    # ── Report Generation ──

    def generate_report(self, output_dir: str | Path | None = None) -> str:
        """
        Generate an HTML traffic analysis report.

        Args:
            output_dir: Directory to write the report (default: self.reports_dir)

        Returns:
            Path to the generated report file
        """
        output_dir = Path(output_dir or self.reports_dir)
        output_dir.mkdir(parents=True, exist_ok=True)

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"phantom_report_{timestamp}.html"
        filepath = output_dir / filename

        stats = self._compute_statistics()
        alert_summary = self.get_alert_summary()
        protocols = stats.get('protocols') or {}
        top_talkers = stats.get('top_talkers') or []
        alerts_list = alert_summary.get('alerts') or []
        by_sev = alert_summary.get('by_severity') or {}
        ip_scores = stats.get('ip_reputation') or {}

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Phantom — Traffic Analysis Report</title>
<style>
*{{margin:0;padding:0;box-sizing:border-box}}
body{{font-family:'Courier New',monospace;background:#0a0a0f;color:#e0e0e8}}
.container{{max-width:1200px;margin:0 auto;padding:2rem}}
h1{{color:#4ade80;font-size:1.8rem;margin-bottom:0.5rem}}
h2{{color:#60a5fa;font-size:1.3rem;margin:2rem 0 1rem}}
.subtitle{{color:#8888a0;margin-bottom:2rem}}
.grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:1rem;margin:1rem 0}}
.card{{background:#12121a;border:1px solid #2a2a3a;border-radius:8px;padding:1rem}}
.card-title{{color:#a78bfa;font-size:0.8rem;margin-bottom:0.5rem}}
.card-value{{font-size:1.8rem;font-weight:bold;color:#4ade80}}
.card-unit{{font-size:0.8rem;color:#8888a0}}
table{{width:100%;border-collapse:collapse;margin:1rem 0}}
th{{background:#1a1a2e;color:#4ade80;padding:0.75rem;text-align:left;font-size:0.85rem}}
td{{padding:0.6rem;border-bottom:1px solid #1a1a2e;font-size:0.85rem}}
tr:hover{{background:#1a1a2e}}
.severity-CRITICAL{{color:#ff4444}}
.severity-HIGH{{color:#ff8800}}
.severity-MEDIUM{{color:#ffcc00}}
.severity-LOW{{color:#4ade80}}
.status-NEW{{color:#60a5fa}}
.status-CONFIRMED{{color:#ff8800}}
.status-RESOLVED{{color:#4ade80}}
</style>
</head>
<body>
<div class="container">
<h1>Phantom — Traffic Analysis Report</h1>
<p class="subtitle">Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | TrinTech Digital Defense</p>

<h2>Overview</h2>
<div class="grid">
<div class="card"><div class="card-title">Total Events</div><div class="card-value">{stats.get('total_events', 0):,}</div></div>
<div class="card"><div class="card-title">Total Alerts</div><div class="card-value">{alert_summary['total']}</div></div>
<div class="card"><div class="card-title">Critical</div><div class="card-value">{by_sev.get('CRITICAL', 0)}</div></div>
<div class="card"><div class="card-title">Unique IPs</div><div class="card-value">{stats.get('unique_src_ips', 0) + stats.get('unique_dst_ips', 0):,}</div></div>
<div class="card"><div class="card-title">Total Data</div><div class="card-value">{stats.get('total_bytes', 0):,}</div><div class="card-unit">bytes</div></div>
<div class="card"><div class="card-title">Protocols</div><div class="card-value">{len(protocols)}</div></div>
</div>

<h2>Protocols</h2>
<table><tr><th>Protocol</th><th>Count</th></tr>
{"".join(f"<tr><td>{proto}</td><td>{count:,}</td></tr>" for proto, count in protocols.items()) if protocols else '<tr><td colspan="2">No data</td></tr>'}
</table>

<h2>Top Talkers</h2>
<table><tr><th>IP</th><th>Events</th></tr>
{"".join(f"<tr><td>{t['ip']}</td><td>{t['count']:,}</td></tr>" for t in top_talkers) if top_talkers else '<tr><td colspan="2">No data</td></tr>'}
</table>

{f"""
<h2>IP Reputation Scores</h2>
<table><tr><th>IP</th><th>Score</th><th>Events</th><th>Ports</th><th>Destinations</th></tr>
{"".join(f"<tr><td>{ip}</td><td class='severity-{'CRITICAL' if s>=8 else 'HIGH' if s>=5 else 'MEDIUM'}'>{s}/10</td><td>{d.get('events',0):,}</td><td>{d.get('ports',0)}</td><td>{d.get('dests',0)}</td></tr>" for ip, s in sorted(ip_scores.items(), key=lambda x: x[1], reverse=True))}
</table>
""" if ip_scores else ""}

<h2>MITRE ATT&CK Mappings</h2>
<table><tr><th>Technique</th><th>Tactic</th><th>Alert Type</th><th>Description</th></tr>
{"".join(f"<tr><td>{m['technique']}</td><td>{m.get('tactic','N/A')}</td><td>{m.get('alert_type','N/A')}</td><td>{m.get('description','N/A')[:80]}</td></tr>" for m in stats.get('mitre_mappings',[])[:10]) if stats.get('mitre_mappings') else '<tr><td colspan="4">No MITRE mappings</td></tr>'}
</table>

<h2>Alerts ({alert_summary['total']})</h2>
<table><tr><th>Type</th><th>Severity</th><th>Score</th><th>Details</th><th>Status</th></tr>
{"".join(f"<tr><td>{a['alert_type']}</td><td class='severity-{a['severity']}'>{a['severity']}</td><td>{a['score']:.0f}</td><td>{a['details'][:100]}</td><td class='status-{a['status']}'>{a['status']}</td></tr>" for a in alerts_list) if alerts_list else '<tr><td colspan="5">No alerts</td></tr>'}
</table>

<p style="color:#8888a0;margin-top:2rem">// Phantom Network Traffic Analyzer — TrinTech Digital Defense</p>
</div>
</body>
</html>"""

        filepath.write_text(html)
        return str(filepath)

    def generate_pdf_report(self, output_dir: str | Path | None = None) -> str:
        """Generate a PDF traffic analysis report using reportlab."""
        from reportlab.lib.pagesizes import letter
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import inch
        from reportlab.lib.colors import HexColor
        from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, KeepTogether
        from reportlab.lib.enums import TA_LEFT, TA_CENTER

        output_dir = Path(output_dir or self.reports_dir)
        output_dir.mkdir(parents=True, exist_ok=True)

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"phantom_report_{timestamp}.pdf"
        filepath = output_dir / filename

        doc = SimpleDocTemplate(str(filepath), pagesize=letter)
        styles = getSampleStyleSheet()
        elements = []

        # Custom styles
        title_style = ParagraphStyle('CustomTitle', parent=styles['Title'], fontSize=20, textColor=HexColor('#22c55e'), spaceAfter=20)
        heading_style = ParagraphStyle('Heading2', parent=styles['Heading2'], fontSize=14, textColor=HexColor('#3b82f6'), spaceBefore=16, spaceAfter=8)
        body_style = ParagraphStyle('Body', parent=styles['Normal'], fontSize=9, textColor=HexColor('#d4d4d8'))
        bold_style = ParagraphStyle('Bold', parent=styles['Normal'], fontSize=9, textColor=HexColor('#ffffff'))

        elements.append(Paragraph("Phantom — Traffic Analysis Report", title_style))
        elements.append(Paragraph(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | TrinTech Digital Defense", body_style))
        elements.append(Spacer(1, 12))

        stats = self._compute_statistics()
        alert_summary = self.get_alert_summary()

        # Overview table
        elements.append(Paragraph("Overview", heading_style))
        overview_data = [
            [Paragraph("<b>Metric</b>", bold_style), Paragraph("<b>Value</b>", bold_style)],
            [Paragraph("Total Events", body_style), Paragraph(f"{stats.get('total_events', 0):,}", body_style)],
            [Paragraph("Total Alerts", body_style), Paragraph(f"{alert_summary['total']}", body_style)],
            [Paragraph("Critical Alerts", body_style), Paragraph(f"{alert_summary.get('by_severity', {}).get('CRITICAL', 0)}", body_style)],
            [Paragraph("High Alerts", body_style), Paragraph(f"{alert_summary.get('by_severity', {}).get('HIGH', 0)}", body_style)],
            [Paragraph("Unique IPs", body_style), Paragraph(f"{stats.get('unique_src_ips', 0) + stats.get('unique_dst_ips', 0)}", body_style)],
            [Paragraph("Total Data", body_style), Paragraph(f"{stats.get('total_bytes', 0):,} bytes", body_style)],
        ]
        t = Table(overview_data, colWidths=[2.5*inch, 3.5*inch])
        t.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), HexColor('#1a1a2e')),
            ('TEXTCOLOR', (0, 0), (-1, 0), HexColor('#4ade80')),
            ('BOX', (0, 0), (-1, -1), 1, HexColor('#2a2a3a')),
            ('GRID', (0, 0), (-1, -1), 0.5, HexColor('#2a2a3a')),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('TOPPADDING', (0, 0), (-1, -1), 6),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ]))
        elements.append(t)

        # MITRE ATT&CK Mappings
        mitre_mappings = stats.get('mitre_mappings', [])
        if mitre_mappings:
            elements.append(Spacer(1, 12))
            elements.append(Paragraph("MITRE ATT&CK Mappings", heading_style))
            mitre_data = [
                [Paragraph("<b>Technique</b>", bold_style), Paragraph("<b>Tactic</b>", bold_style), Paragraph("<b>Description</b>", bold_style)],
            ]
            for m in mitre_mappings[:15]:
                mitre_data.append([
                    Paragraph(m.get('technique', 'N/A'), body_style),
                    Paragraph(m.get('tactic', 'N/A'), body_style),
                    Paragraph(m.get('description', 'N/A')[:80], body_style),
                ])
            t = Table(mitre_data, colWidths=[2.5*inch, 1.5*inch, 3*inch])
            t.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), HexColor('#1a1a2e')),
                ('TEXTCOLOR', (0, 0), (-1, 0), HexColor('#4ade80')),
                ('BOX', (0, 0), (-1, -1), 1, HexColor('#2a2a3a')),
                ('GRID', (0, 0), (-1, -1), 0.5, HexColor('#2a2a3a')),
                ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                ('TOPPADDING', (0, 0), (-1, -1), 4),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
            ]))
            elements.append(t)

        # Alerts table
        alerts_list = alert_summary.get('alerts', [])
        if alerts_list:
            elements.append(Spacer(1, 12))
            elements.append(Paragraph(f"Alerts ({alert_summary['total']})", heading_style))
            alert_data = [
                [Paragraph("<b>Type</b>", bold_style), Paragraph("<b>Severity</b>", bold_style), Paragraph("<b>Score</b>", bold_style), Paragraph("<b>Details</b>", bold_style)],
            ]
            for a in alerts_list[:30]:
                alert_data.append([
                    Paragraph(a.get('alert_type', ''), body_style),
                    Paragraph(a.get('severity', ''), body_style),
                    Paragraph(f"{a.get('score', 0):.0f}", body_style),
                    Paragraph(a.get('details', '')[:60], body_style),
                ])
            t = Table(alert_data, colWidths=[1.5*inch, 1*inch, 0.7*inch, 3.8*inch])
            t.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), HexColor('#1a1a2e')),
                ('TEXTCOLOR', (0, 0), (-1, 0), HexColor('#4ade80')),
                ('BOX', (0, 0), (-1, -1), 1, HexColor('#2a2a3a')),
                ('GRID', (0, 0), (-1, -1), 0.5, HexColor('#2a2a3a')),
                ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                ('TOPPADDING', (0, 0), (-1, -1), 4),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
            ]))
            elements.append(t)

        elements.append(Spacer(1, 24))
        elements.append(Paragraph("// Phantom Network Traffic Analyzer — TrinTech Digital Defense", body_style))

        doc.build(elements)
        return str(filepath)

    def export_csv(self, output_file: str | Path | None = None) -> str:
        """Export events and alerts to CSV files."""
        import csv

        output_dir = Path(output_file).parent if output_file else self.reports_dir
        output_dir.mkdir(parents=True, exist_ok=True)

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        # Events CSV
        if output_file:
            events_path = Path(output_file) if Path(output_file).suffix == '.csv' else Path(str(output_file) + '.csv')
        else:
            events_path = output_dir / f"phantom_events_{timestamp}.csv"

        with open(events_path, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['event_id', 'timestamp', 'src_ip', 'dst_ip', 'src_port', 'dst_port', 'protocol', 'direction', 'payload_size', 'duration', 'metadata'])
            for event in self.events:
                writer.writerow([
                    event.event_id, event.timestamp, event.src_ip, event.dst_ip,
                    event.src_port, event.dst_port, event.protocol, event.direction,
                    event.payload_size, event.duration, json.dumps(event.metadata) if event.metadata else ''
                ])

        # Alerts CSV
        alerts_path = output_dir / f"phantom_alerts_{timestamp}.csv"
        with open(alerts_path, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['alert_id', 'alert_type', 'severity', 'score', 'source', 'details', 'timestamp', 'event_ids', 'ips', 'status'])
            for alert in self.alerts:
                writer.writerow([
                    alert.alert_id, alert.alert_type, alert.severity, alert.score,
                    alert.source, alert.details, alert.timestamp,
                    json.dumps(alert.event_ids), json.dumps(alert.ips), alert.status
                ])

        return str(events_path)

"""
TrinTech Digital Defense
Mirage: Network Deception Framework

Generates decoy resources (files, credentials, network services, database entries)
to detect and track attackers who move laterally through a network.

Architecture:
  - Lures: Fake assets planted across the network (fake SSH keys, dummy DBs, 
    fake config files, honeypot services)
  - Deciders: Logic that evaluates alert context and classifies severity
  - Correlator: Links Mirage alerts with SPECTER-THREAT findings for unified threat view
"""

import abc
import hashlib
import json
import logging
import os
import sqlite3
import time
import threading
from datetime import datetime
from pathlib import Path
from typing import Any

log = logging.getLogger("mirage")


# ────────────────────────────────────────────────────────────────
# Alert Data Model
# ────────────────────────────────────────────────────────────────

class Alert:
    """Represents a deception alert triggered by a lure touch."""

    def __init__(
        self,
        alert_id: str,
        lure_type: str,
        lure_name: str,
        trigger_location: str,
        actor_ip: str,
        actor_detail: str = "",
        timestamp: str = None,
        severity: str = "MEDIUM",
        status: str = "NEW",
    ):
        self.alert_id = alert_id
        self.lure_type = lure_type        # ssh_key, db_credential, fake_file, fake_service, api_key, config
        self.lure_name = lure_name         # human-readable name
        self.trigger_location = trigger_location  # where it was touched
        self.actor_ip = actor_ip
        self.actor_detail = actor_detail
        self.timestamp = timestamp or datetime.now().isoformat()
        self.severity = severity
        self.status = status               # NEW, INVESTIGATING, CONFIRMED, FALSE_POSITIVE, RESOLVED
        self.notes: list[dict] = []
        self.tags: list[str] = []

    def add_note(self, note: str, source: str = "system"):
        self.notes.append({"time": datetime.now().isoformat(), "note": note, "source": source})

    def to_dict(self) -> dict:
        return {
            "alert_id": self.alert_id,
            "lure_type": self.lure_type,
            "lure_name": self.lure_name,
            "trigger_location": self.trigger_location,
            "actor_ip": self.actor_ip,
            "actor_detail": self.actor_detail,
            "timestamp": self.timestamp,
            "severity": self.severity,
            "status": self.status,
            "notes": self.notes,
            "tags": self.tags,
        }


# ────────────────────────────────────────────────────────────────
# Alert Storage (SQLite)
# ────────────────────────────────────────────────────────────────

class AlertStore:
    """Persistent storage for Mirage alerts."""

    def __init__(self, db_path: str | Path):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _init_db(self):
        with sqlite3.connect(str(self.db_path)) as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS alerts (
                    alert_id TEXT PRIMARY KEY,
                    lure_type TEXT NOT NULL,
                    lure_name TEXT NOT NULL,
                    trigger_location TEXT NOT NULL,
                    actor_ip TEXT NOT NULL,
                    actor_detail TEXT DEFAULT '',
                    timestamp TEXT NOT NULL,
                    severity TEXT DEFAULT 'MEDIUM',
                    status TEXT DEFAULT 'NEW',
                    notes TEXT DEFAULT '[]',
                    tags TEXT DEFAULT '[]',
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status);
                CREATE INDEX IF NOT EXISTS idx_alerts_ip ON alerts(actor_ip);
                CREATE INDEX IF NOT EXISTS idx_alerts_type ON alerts(lure_type);
                CREATE INDEX IF NOT EXISTS idx_alerts_time ON alerts(timestamp);
            """)

    def save(self, alert: Alert):
        with sqlite3.connect(str(self.db_path)) as conn:
            conn.execute(
                """INSERT OR REPLACE INTO alerts
                   (alert_id, lure_type, lure_name, trigger_location, actor_ip,
                    actor_detail, timestamp, severity, status, notes, tags,
                    created_at, updated_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    alert.alert_id, alert.lure_type, alert.lure_name,
                    alert.trigger_location, alert.actor_ip, alert.actor_detail,
                    alert.timestamp, alert.severity, alert.status,
                    json.dumps(alert.notes), json.dumps(alert.tags),
                    datetime.now().isoformat(),
                    datetime.now().isoformat(),
                ),
            )

    def get_alert(self, alert_id: str) -> dict | None:
        with sqlite3.connect(str(self.db_path)) as conn:
            row = conn.execute(
                "SELECT * FROM alerts WHERE alert_id = ?", (alert_id,)
            ).fetchone()
            if row:
                return {
                    "alert_id": row[0], "lure_type": row[1], "lure_name": row[2],
                    "trigger_location": row[3], "actor_ip": row[4],
                    "actor_detail": row[5], "timestamp": row[6],
                    "severity": row[7], "status": row[8],
                    "notes": json.loads(row[9]), "tags": json.loads(row[10]),
                }
            return None

    def get_all(self, status_filter: str = None, limit: int = 100) -> list[dict]:
        query = "SELECT * FROM alerts"
        params = []
        if status_filter:
            query += " WHERE status = ?"
            params.append(status_filter)
        query += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)

        with sqlite3.connect(str(self.db_path)) as conn:
            rows = conn.execute(query, params).fetchall()
            return [
                {
                    "alert_id": r[0], "lure_type": r[1], "lure_name": r[2],
                    "trigger_location": r[3], "actor_ip": r[4],
                    "actor_detail": r[5], "timestamp": r[6],
                    "severity": r[7], "status": r[8],
                    "notes": json.loads(r[9]), "tags": json.loads(r[10]),
                }
                for r in rows
            ]

    def get_stats(self) -> dict:
        with sqlite3.connect(str(self.db_path)) as conn:
            stats = {}
            rows = conn.execute(
                "SELECT status, COUNT(*) FROM alerts GROUP BY status"
            ).fetchall()
            stats["by_status"] = {r[0]: r[1] for r in rows}

            rows = conn.execute(
                "SELECT lure_type, COUNT(*) FROM alerts GROUP BY lure_type"
            ).fetchall()
            stats["by_lure_type"] = {r[0]: r[1] for r in rows}

            rows = conn.execute(
                "SELECT actor_ip, COUNT(*) FROM alerts GROUP BY actor_ip ORDER BY COUNT(*) DESC"
            ).fetchall()
            stats["top_actors"] = [{"ip": r[0], "count": r[1]} for r in rows[:10]]

            rows = conn.execute(
                "SELECT severity, COUNT(*) FROM alerts GROUP BY severity"
            ).fetchall()
            stats["by_severity"] = {r[0]: r[1] for r in rows}

            stats["total"] = conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
            return stats

    def get_unique_ips(self) -> list[str]:
        with sqlite3.connect(str(self.db_path)) as conn:
            rows = conn.execute(
                "SELECT DISTINCT actor_ip FROM alerts ORDER BY actor_ip"
            ).fetchall()
            return [r[0] for r in rows]


# ────────────────────────────────────────────────────────────────
# Lure Types
# ────────────────────────────────────────────────────────────────

class Lure(abc.ABC):
    """Base class for deception lures."""

    @property
    @abc.abstractmethod
    def lure_type(self) -> str:
        """Lure type identifier."""

    @property
    @abc.abstractmethod
    def description(self) -> str:
        """Human-readable description."""

    @abc.abstractmethod
    def deploy(self, target_path: str, store: AlertStore) -> str:
        """
        Deploy the lure. Returns the alert_id if planted successfully.
        
        Args:
            target_path: Where to plant the lure
            store: Alert store for recording alerts
            
        Returns:
            alert_id of the planted lure, or None on failure
        """

    @abc.abstractmethod
    def check_trigger(self, event: dict) -> Alert | None:
        """
        Check if an event triggers this lure.
        
        Args:
            event: Dict describing the observed event (read, execute, connect, etc.)
            
        Returns:
            Alert if triggered, None otherwise
        """


class FakeSSHKeyLure(Lure):
    """
    Plants fake SSH private keys that look real but have known backdoor passwords.
    When accessed, alerts the team and tracks the actor.
    """

    @property
    def lure_type(self) -> str:
        return "ssh_key"

    @property
    def description(self) -> str:
        return "Fake SSH private key with known backdoor password"

    def deploy(self, target_path: str, store: AlertStore) -> str:
        import os
        from pathlib import Path

        lure_file = Path(target_path) / "id_rsa_decoy"
        lure_file.parent.mkdir(parents=True, exist_ok=True)

        # Generate a fake SSH key with known passphrase
        passphrase = "decoy_password_2024_trintech"
        
        # Write a fake private key (looks real to automated scanners)
        fake_key = f"""-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACDmKGMoHjBBMvFqHjNlHjNlHjNlHjNlHjNlHjNlHjNlHjNlHAAAAJh
dXRoQG1hY2hpbmUwMQ==
-----END OPENSSH PRIVATE KEY-----
"""
        # Add a comment that makes it look like it has a real passphrase hint
        fake_key += f"# passphrase: {passphrase}\n"

        lure_file.write_text(fake_key)
        os.chmod(str(lure_file), 0o600)

        alert_id = self._generate_alert_id("ssh_key")
        alert = Alert(
            alert_id=alert_id,
            lure_type="ssh_key",
            lure_name=f"SSH Key: {lure_file.name}",
            trigger_location=str(lure_file.parent),
            actor_ip="PENDING",
            severity="HIGH",
        )
        alert.add_note(f"Planted at {lure_file}", "deploy")
        store.save(alert)

        log.info(f"Deployed SSH key decoy: {lure_file}")
        return alert_id

    def check_trigger(self, event: dict) -> Alert | None:
        if event.get("action") in ("read", "copy", "scp", "rsync", "cat", "head", "tail"):
            if "id_rsa_decoy" in str(event.get("path", "")):
                from datetime import datetime
                alert_id = event.get("alert_id", self._generate_alert_id("ssh_key"))
                return Alert(
                    alert_id=alert_id,
                    lure_type="ssh_key",
                    lure_name=event.get("lure_name", "SSH Key Decoy"),
                    trigger_location=str(event.get("path", "unknown")),
                    actor_ip=event.get("actor_ip", "unknown"),
                    actor_detail=event.get("detail", ""),
                    severity="HIGH",
                )
        return None

    def _generate_alert_id(self, prefix: str) -> str:
        return f"{prefix}_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{hashlib.md5(str(time.time()).encode()).hexdigest()[:8]}"


class FakeDBCredentialsLure(Lure):
    """Plants fake database credential files in common config locations."""

    @property
    def lure_type(self) -> str:
        return "db_credential"

    @property
    def description(self) -> str:
        return "Fake database credentials in common config locations"

    def deploy(self, target_path: str, store: AlertStore) -> str:
        from pathlib import Path

        lure_file = Path(target_path) / ".env.decoy"
        lure_file.parent.mkdir(parents=True, exist_ok=True)

        fake_env = """# Database Configuration
DB_HOST=10.0.0.50
DB_PORT=3306
DB_NAME=production_users
DB_USER=admin
DB_PASSWORD=Sup3rS3cretP@ssw0rd!
DB_ROOT_PASSWORD=R00t#Tr1nT3ch2024
"""
        lure_file.write_text(fake_env)

        alert_id = self._generate_alert_id("db_cred")
        alert = Alert(
            alert_id=alert_id,
            lure_type="db_credential",
            lure_name=f"DB Creds: {lure_file.name}",
            trigger_location=str(lure_file.parent),
            actor_ip="PENDING",
            severity="CRITICAL",
        )
        alert.add_note(f"Planted at {lure_file}", "deploy")
        store.save(alert)

        log.info(f"Deployed DB credential decoy: {lure_file}")
        return alert_id

    def check_trigger(self, event: dict) -> Alert | None:
        if event.get("action") in ("read", "copy", "cat", "head", "tail", "grep"):
            if ".env" in str(event.get("path", "")) or "password" in str(event.get("path", "")).lower():
                if "decoy" in str(event.get("path", "")).lower():
                    alert_id = event.get("alert_id", self._generate_alert_id("db_cred"))
                    return Alert(
                        alert_id=alert_id,
                        lure_type="db_credential",
                        lure_name=event.get("lure_name", "DB Credential Decoy"),
                        trigger_location=str(event.get("path", "unknown")),
                        actor_ip=event.get("actor_ip", "unknown"),
                        severity="CRITICAL",
                    )
        return None

    def _generate_alert_id(self, prefix: str) -> str:
        return f"{prefix}_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{hashlib.md5(str(time.time()).encode()).hexdigest()[:8]}"


class FakeConfigFileLure(Lure):
    """Plants fake AWS/GCP/Azure credential files."""

    @property
    def lure_type(self) -> str:
        return "cloud_credential"

    @property
    def description(self) -> str:
        return "Fake cloud provider credential file (AWS/GCP/Azure)"

    def deploy(self, target_path: str, store: AlertStore) -> str:
        from pathlib import Path

        aws_dir = Path(target_path) / ".aws"
        aws_dir.mkdir(parents=True, exist_ok=True)

        creds_file = aws_dir / "credentials_decoy"
        creds = """[default_decoy]
aws_access_key_id = AKIAIOSFODNN7DECOYKEY
aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYDECOYKEY
region = us-east-1

[admin_decoy]
aws_access_key_id = AKIAIOSFODNN7ADMNDECOY
aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYADMNDECOY
region = us-west-2
"""
        creds_file.write_text(creds)

        alert_id = self._generate_alert_id("cloud_cred")
        alert = Alert(
            alert_id=alert_id,
            lure_type="cloud_credential",
            lure_name=f"AWS Creds: {creds_file}",
            trigger_location=str(aws_dir),
            actor_ip="PENDING",
            severity="CRITICAL",
        )
        alert.add_note(f"Planted at {creds_file}", "deploy")
        store.save(alert)

        log.info(f"Deployed cloud credential decoy: {creds_file}")
        return alert_id

    def check_trigger(self, event: dict) -> Alert | None:
        if event.get("action") in ("read", "copy", "cat", "head", "tail"):
            if ".aws" in str(event.get("path", "")) and "credentials" in str(event.get("path", "")):
                if "decoy" in str(event.get("path", "")).lower():
                    alert_id = event.get("alert_id", self._generate_alert_id("cloud_cred"))
                    return Alert(
                        alert_id=alert_id,
                        lure_type="cloud_credential",
                        lure_name=event.get("lure_name", "Cloud Credential Decoy"),
                        trigger_location=str(event.get("path", "unknown")),
                        actor_ip=event.get("actor_ip", "unknown"),
                        severity="CRITICAL",
                    )
        return None

    def _generate_alert_id(self, prefix: str) -> str:
        return f"{prefix}_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{hashlib.md5(str(time.time()).encode()).hexdigest()[:8]}"


class FakeServiceLure(Lure):
    """Creates fake services that trigger alerts when accessed."""

    @property
    def lure_type(self) -> str:
        return "fake_service"

    @property
    def description(self) -> str:
        return "Fake network service (HTTP/SSH/FTP/Redis) that logs all access"

    def deploy(self, target_path: str, store: AlertStore) -> str:
        # Store config for service tracking
        config_path = Path(target_path) / "decoy_service.json"
        config = {
            "port": 8080,
            "protocol": "http",
            "decoy_type": "web_app",
            "decoy_response": "Internal Dashboard v0.1.0 (DECOY)",
            "created": datetime.now().isoformat(),
        }
        config_path.write_text(json.dumps(config, indent=2))

        alert_id = self._generate_alert_id("fake_svc")
        alert = Alert(
            alert_id=alert_id,
            lure_type="fake_service",
            lure_name=f"Fake Service: port {config['port']}",
            trigger_location=f"{config['protocol']}://{config['port']}",
            actor_ip="PENDING",
            severity="HIGH",
        )
        alert.add_note(f"Service decoy configured on port {config['port']}", "deploy")
        store.save(alert)

        log.info(f"Deployed service decoy: port {config['port']}")
        return alert_id

    def check_trigger(self, event: dict) -> Alert | None:
        if event.get("action") in ("connect", "request", "browse", "scan"):
            if event.get("port") and event.get("service") == "decoy":
                alert_id = event.get("alert_id", self._generate_alert_id("fake_svc"))
                return Alert(
                    alert_id=alert_id,
                    lure_type="fake_service",
                    lure_name=event.get("lure_name", "Fake Service"),
                    trigger_location=event.get("location", "unknown"),
                    actor_ip=event.get("actor_ip", "unknown"),
                    severity="HIGH",
                )
        return None

    def _generate_alert_id(self, prefix: str) -> str:
        return f"{prefix}_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{hashlib.md5(str(time.time()).encode()).hexdigest()[:8]}"


# ────────────────────────────────────────────────────────────────
# Mirage Controller
# ────────────────────────────────────────────────────────────────

class MirageController:
    """
    Central controller for the Mirage deception framework.
    Manages lure deployment, alert monitoring, and correlation with SPECTER.
    """

    LURE_REGISTRY = {
        "ssh_key": FakeSSHKeyLure,
        "db_credential": FakeDBCredentialsLure,
        "cloud_credential": FakeConfigFileLure,
        "fake_service": FakeServiceLure,
    }

    def __init__(self, reports_dir: str | Path = None):
        self.reports_dir = Path(reports_dir or "/tmp/mirage_reports")
        self.reports_dir.mkdir(exist_ok=True)

        db_path = self.reports_dir / "mirage_alerts.db"
        self.store = AlertStore(db_path)
        self.active_lures: dict[str, Any] = {}  # alert_id -> lure
        self.alert_counter = 0

    def create_lure(self, lure_type: str, target_path: str = None) -> str:
        """Create and deploy a deception lure."""
        lure_cls = self.LURE_REGISTRY.get(lure_type)
        if not lure_cls:
            raise ValueError(f"Unknown lure type: {lure_type}. Available: {list(self.LURE_REGISTRY.keys())}")

        target = target_path or str(self.reports_dir / "planted")

        lure = lure_cls()
        alert_id = lure.deploy(target, self.store)

        self.active_lures[alert_id] = {
            "lure": lure,
            "type": lure.lure_type,
            "description": lure.description,
            "deployed_at": datetime.now().isoformat(),
        }

        return alert_id

    def trigger_lure(self, event: dict) -> Alert | None:
        """
        Check if an event triggers any active lure.
        
        Args:
            event: Dict with keys: action, path, actor_ip, alert_id, etc.
        """
        for alert_id, lure_info in self.active_lures.items():
            alert = lure_info["lure"].check_trigger(event)
            if alert:
                alert.alert_id = alert_id  # Use existing alert_id
                alert.status = "NEW"
                alert.add_note(
                    f"Triggered: {event.get('action', 'unknown')} at {event.get('path', 'unknown')}",
                    "lure",
                )
                alert.add_note(f"Event details: {json.dumps(event)}", "system")
                self.store.save(alert)
                
                # Correlate with TI-Corr if available
                if event.get("actor_ip") != "PENDING" and event.get("actor_ip") != "unknown":
                    alert.tags.append("needs_correlation")
                    alert.add_note(f"Actor IP {event['actor_ip']} — correlates with TI-Corr", "correlator")

                log.info(f"🚨 ALERT: {alert.severity} - {alert.lure_type} triggered by {alert.actor_ip}")
                return alert
        return None

    def get_alerts(self, status_filter: str = None, limit: int = 50) -> list[dict]:
        return self.store.get_all(status_filter, limit)

    def get_stats(self) -> dict:
        stats = self.store.get_stats()
        stats["active_lures"] = len(self.active_lures)
        stats["unique_ips"] = len(self.store.get_unique_ips())
        return stats

    def deploy_all_decoys(self, target_base: str = None) -> list[str]:
        """Deploy all available decoy types to a target directory."""
        target = target_base or str(self.reports_dir / "planted")
        results = []

        for lure_type in self.LURE_REGISTRY.keys():
            try:
                alert_id = self.create_lure(lure_type, target)
                results.append({"lure_type": lure_type, "alert_id": alert_id, "status": "deployed"})
            except Exception as e:
                results.append({"lure_type": lure_type, "error": str(e), "status": "failed"})
                log.error(f"Failed to deploy {lure_type}: {e}")

        return results

    def generate_report(self) -> str:
        """Generate a human-readable deception report."""
        stats = self.get_stats()
        alerts = self.store.get_all("NEW", limit=20)

        lines = []
        lines.append("=" * 60)
        lines.append("MIRAGE DECEPTION FRAMEWORK — REPORT")
        lines.append(f"TrinTech Digital Defense")
        lines.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append("=" * 60)
        lines.append("")
        lines.append(f"Total Alerts:     {stats['total']}")
        lines.append(f"Active Lures:     {stats['active_lures']}")
        lines.append(f"Unique IPs:       {stats['unique_ips']}")
        lines.append("")
        lines.append("--- By Status ---")
        for status, count in stats.get("by_status", {}).items():
            lines.append(f"  {status}: {count}")
        lines.append("")
        lines.append("--- By Lure Type ---")
        for ltype, count in stats.get("by_lure_type", {}).items():
            lines.append(f"  {ltype}: {count}")
        lines.append("")
        lines.append("--- By Severity ---")
        for sev, count in stats.get("by_severity", {}).items():
            lines.append(f"  {sev}: {count}")
        lines.append("")
        lines.append("--- Top Attacker IPs ---")
        for actor in stats.get("top_actors", [])[:5]:
            lines.append(f"  {actor['ip']}: {actor['count']} hits")
        lines.append("")

        if alerts:
            lines.append("--- Recent New Alerts ---")
            for alert in alerts:
                lines.append(f"  [{alert['severity']}] {alert['lure_type']}: {alert['lure_name']}")
                lines.append(f"    Triggered by {alert['actor_ip']} at {alert['trigger_location']}")
                lines.append(f"    At {alert['timestamp']}")
                lines.append("")

        report_text = "\n".join(lines)

        report_path = self.reports_dir / f"mirage_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        report_path.write_text(report_text)

        return report_text

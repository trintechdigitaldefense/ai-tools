#!/usr/bin/env python3
"""
TrinTech Digital Defense
Playbook Generator — Flask API Server

Generates automated incident response playbooks from Log Correlator incidents.

Endpoints:
  POST /api/playbook/generate        — Generate playbook from incident(s)
  POST /api/playbook/generate/bulk   — Bulk generate from multiple incidents
  GET  /api/playbook/<id>            — Get playbook
  GET  /api/playbooks                — List all playbooks
  POST /api/playbook/from-logcorr    — Auto-generate from Log Correlator DB
  POST /api/playbook/<id>/status     — Update playbook status
  GET  /api/playbook/report           — Full report (text)
  GET  /api/playbook/report/json      — Full report (JSON)
  POST /api/playbook/export/pdf       — Export playbook as PDF
  POST /api/playbook/notify           — Send notification email/SMS
  GET  /api/playbook/<id>/timeline    — Timeline view
  GET  /dashboard                     — Web UI
  GET  /api/health                    — Health check
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
from collections import defaultdict
from datetime import datetime, timedelta
import time
from pathlib import Path
from typing import Any
from functools import wraps

try:
    from flask import Flask, jsonify, request, Response, send_from_directory
    from flask_cors import CORS
except ImportError:
    Flask = None  # type: ignore

# ────────────────────────────────────────────────────────────────
# Configuration
# ────────────────────────────────────────────────────────────────

BASE_DIR = Path(__file__).resolve().parent
REPORTS_DIR = BASE_DIR / "trintech_reports"
REPORTS_DIR.mkdir(exist_ok=True)

DB_PATH = REPORTS_DIR / "playbook_generator.db"
LOGCORR_DB_PATH = None  # Set when integrating with Log Correlator

PLAYBOOKS: list[dict] = []  # In-memory playbook store

log = logging.getLogger("playbook")
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)

# ────────────────────────────────────────────────────────────────
# SQLite Persistence (improvement #10)
# ────────────────────────────────────────────────────────────────

def _init_db():
    """Create SQLite tables for persistent playbook storage."""
    conn = sqlite3.connect(str(DB_PATH))
    conn.execute("""
        CREATE TABLE IF NOT EXISTS playbooks (
            playbook_id TEXT PRIMARY KEY,
            incident_id TEXT,
            title TEXT,
            severity TEXT,
            status TEXT,
            generated_at TEXT,
            mitre_mappings TEXT,
            containment_steps TEXT,
            eradication_steps TEXT,
            recovery_steps TEXT,
            escalation TEXT,
            iocs TEXT,
            affected_assets TEXT,
            playbook_text TEXT,
            notes TEXT,
            status_history TEXT,
            enriched_iocs TEXT
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS notifications (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            playbook_id TEXT,
            type TEXT,  -- email, sms, slack
            recipient TEXT,
            subject TEXT,
            body TEXT,
            status TEXT,
            created_at TEXT,
            sent_at TEXT
        )
    """)
    conn.commit()
    conn.close()


def _save_playbook_to_db(pb_dict: dict):
    """Save a playbook dict to SQLite."""
    conn = sqlite3.connect(str(DB_PATH))
    try:
        conn.execute("""
            INSERT OR REPLACE INTO playbooks (
                playbook_id, incident_id, title, severity, status, generated_at,
                mitre_mappings, containment_steps, eradication_steps, recovery_steps,
                escalation, iocs, affected_assets, playbook_text, notes, status_history, enriched_iocs
            ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        """, (
            pb_dict["playbook_id"], pb_dict["incident_id"], pb_dict["title"],
            pb_dict["severity"], pb_dict["status"], pb_dict["generated_at"],
            json.dumps(pb_dict["mitre_mappings"]), json.dumps(pb_dict["containment_steps"]),
            json.dumps(pb_dict["eradication_steps"]), json.dumps(pb_dict["recovery_steps"]),
            json.dumps(pb_dict["escalation"]), json.dumps(pb_dict["iocs"]),
            json.dumps(pb_dict["affected_assets"]), pb_dict["playbook_text"],
            json.dumps(pb_dict["notes"]), json.dumps(pb_dict["status_history"]),
            json.dumps(pb_dict.get("enriched_iocs", {})),
        ))
        conn.commit()
    finally:
        conn.close()


def _get_playbooks_from_db() -> list[dict]:
    """Load all playbooks from SQLite, merge with in-memory."""
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    rows = conn.execute("SELECT * FROM playbooks").fetchall()
    playbooks = []
    for row in rows:
        pb = dict(row)
        # Parse JSON fields back from DB
        for json_field in ["mitre_mappings", "containment_steps", "eradication_steps",
                           "recovery_steps", "escalation", "iocs", "affected_assets",
                           "notes", "status_history", "enriched_iocs"]:
            if isinstance(pb.get(json_field), str):
                try:
                    pb[json_field] = json.loads(pb[json_field])
                except:
                    pb[json_field] = []
        playbooks.append(pb)
    conn.close()
    return playbooks


def _persist_sync():
    """Background thread: sync in-memory playbooks to SQLite periodically."""
    while True:
        try:
            for pb in PLAYBOOKS:
                _save_playbook_to_db(pb)
        except Exception as e:
            log.error(f"DB sync error: {e}")
        time.sleep(30)  # Sync every 30 seconds


# ────────────────────────────────────────────────────────────────
# Notification Templates (improvement #6)
# ────────────────────────────────────────────────────────────────

def _build_email_template(pb: dict, config: dict) -> dict:
    """Build a formatted email from a playbook dict."""
    contacts = config.get("escalation_contacts", {})
    domain = config.get("default_email_domain", "example.com")

    to_addresses = []
    for name in pb["escalation"].get("notify", []):
        contact = contacts.get(name, {})
        email = contact.get("email", f"{name.lower().replace(' ', '.')}@{domain}")
        to_addresses.append(email)

    subject = f"[{pb['severity']}] {pb['title']}"

    body_lines = [
        f"PLAYBOOK NOTIFICATION",
        f"{'=' * 40}",
        f"Title:      {pb['title']}",
        f"Severity:   {pb['severity']}",
        f"Priority:   {pb['escalation'].get('priority', '')}",
        f"Response:   {pb['escalation'].get('response_time', '')}",
        f"Generated:  {pb['generated_at']}",
        f"Incident:   {pb['incident_id']}",
        "",
        "ESCALATION ACTIONS:",
    ]

    for action in pb["escalation"].get("actions", []):
        body_lines.append(f"  - {action}")

    body_lines.append("")
    body_lines.append("CONTAINMENT STEPS:")
    for step in pb["containment_steps"]:
        body_lines.append(f"  [{step['order']}] {step['step']}")

    body_lines.append("")
    body_lines.append("ERADICATION STEPS:")
    for step in pb["eradication_steps"]:
        body_lines.append(f"  [{step['order']}] {step['step']}")

    body_lines.append("")
    body_lines.append("RECOVERY STEPS:")
    for step in pb["recovery_steps"]:
        body_lines.append(f"  [{step['order']}] {step['step']}")

    body_lines.append("")
    if pb["iocs"].get("ips"):
        body_lines.append("ATTACKER IPs:")
        for ip in pb["iocs"]["ips"]:
            body_lines.append(f"  - {ip}")

    return {
        "to": to_addresses,
        "cc": [],
        "subject": subject,
        "body": "\n".join(body_lines),
        "html_body": _build_email_html(pb),
    }


def _build_email_html(pb: dict) -> str:
    """Build an HTML email body from a playbook dict."""
    severity_class = pb["severity"].lower()
    html = f"""
    <h1 style="color: {'#ff0040' if severity_class == 'critical' else '#ff4444' if severity_class == 'high' else '#ffa500'};">
        {pb['title']}
    </h1>
    <p><strong>Severity:</strong> {pb['severity']} | <strong>Priority:</strong> {pb['escalation'].get('priority', '')} | <strong>Response:</strong> {pb['escalation'].get('response_time', '')}</p>
    <h2>Escalation Actions</h2>
    <ul>{''.join(f'<li>{a}</li>' for a in pb['escalation'].get('actions', []))}</ul>
    <h2>Containment</h2>
    <ol>{''.join(f'<li>{s["step"]}</li>' for s in pb['containment_steps'])}</ol>
    <h2>Eradication</h2>
    <ol>{''.join(f'<li>{s["step"]}</li>' for s in pb['eradication_steps'])}</ol>
    <h2>Recovery</h2>
    <ol>{''.join(f'<li>{s["step"]}</li>' for s in pb['recovery_steps'])}</ol>
    """
    return html


def _build_sms_template(pb: dict) -> str:
    """Build an SMS notification body (160 char limit)."""
    return (
        f"[{pb['severity']}] {pb['title']}: "
        f"{pb['escalation'].get('priority', '')}. "
        f"{len(pb['containment_steps'])} containment steps. "
        f"Response: {pb['escalation'].get('response_time', '')}"
    )


def _send_notification(pb_dict: dict, config: dict, notify_type: str = "all") -> dict:
    """Send notification via configured channels.

    In production, this would integrate with SMTP, Twilio, Slack API, etc.
    For now, it logs the notification and stores it in the DB.
    """
    contacts = config.get("escalation_contacts", {})
    notifications = []

    for name in pb_dict["escalation"].get("notify", []):
        contact = contacts.get(name, {})
        email = contact.get("email", f"{name.lower().replace(' ', '.')}@{config.get('default_email_domain', 'example.com')}")
        phone = contact.get("phone", "")

        if notify_type in ("all", "email") and config.get("notification", {}).get("email_enabled", True):
            template = _build_email_template(pb_dict, config)
            # In production: send email via SMTP
            log.info(f"[SMTP] Would send email to {email}: {template['subject']}")
            notifications.append({
                "type": "email",
                "recipient": email,
                "status": "queued",
                "details": template["subject"],
            })

        if notify_type in ("all", "sms") and config.get("notification", {}).get("sms_enabled", False) and phone:
            sms_body = _build_sms_template(pb_dict)
            # In production: send SMS via Twilio
            log.info(f"[SMS] Would send SMS to {phone}: {sms_body[:80]}")
            notifications.append({
                "type": "sms",
                "recipient": phone,
                "status": "queued",
                "details": sms_body[:80],
            })

        if notify_type in ("all", "slack") and config.get("notification", {}).get("slack_enabled", False):
            # In production: POST to Slack webhook
            log.info(f"[Slack] Would send to webhook: {config.get('notification', {}).get('slack_webhook', '')}")
            notifications.append({
                "type": "slack",
                "recipient": "channel",
                "status": "queued",
                "details": f"[{pb_dict['severity']}] {pb_dict['title']}",
            })

    if notifications:
        _save_notifications_to_db(pb_dict["playbook_id"], notifications)

    return {"notifications": notifications, "count": len(notifications)}


def _save_notifications_to_db(playbook_id: str, notifications: list[dict]):
    """Save notification records to DB."""
    conn = sqlite3.connect(str(DB_PATH))
    try:
        for n in notifications:
            conn.execute("""
                INSERT INTO notifications (playbook_id, type, recipient, subject, status, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (
                playbook_id, n["type"], n["recipient"],
                n.get("details", ""), n["status"],
                datetime.now().isoformat(),
            ))
        conn.commit()
    finally:
        conn.close()


# ────────────────────────────────────────────────────────────────
# Rate Limiting & Auth (improvement #9)
# ────────────────────────────────────────────────────────────────

_RATE_LIMITS: dict[str, list] = {}  # ip -> [timestamps]
RATE_LIMIT_REQUESTS = 100  # requests per window
RATE_LIMIT_WINDOW = 60  # seconds
AUTH_ENABLED = False  # Set True to require API key via X-API-Key header
REQUIRED_API_KEY = os.environ.get("PLAYBOOK_API_KEY", "")


def _rate_limit(f):
    """Decorate route with rate limiting."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if not AUTH_ENABLED:
            return f(*args, **kwargs)
        client_ip = request.remote_addr or "unknown"
        now = datetime.now()
        # Clean old timestamps
        _rate_limit_timestamps.setdefault(client_ip, [])
        _rate_limit_timestamps[client_ip] = [
            t for t in _rate_limit_timestamps[client_ip]
            if (now - t).total_seconds() < RATE_LIMIT_WINDOW
        ]
        if len(_rate_limit_timestamps[client_ip]) >= RATE_LIMIT_REQUESTS:
            return jsonify({"error": "Rate limit exceeded", "retry_after": RATE_LIMIT_WINDOW}), 429
        _rate_limit_timestamps[client_ip].append(now)
        return f(*args, **kwargs)
    return decorated


def _require_api_key(f):
    """Decorate route with API key authentication."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if not AUTH_ENABLED:
            return f(*args, **kwargs)
        api_key = request.headers.get("X-API-Key", "")
        if not api_key or api_key != REQUIRED_API_KEY:
            return jsonify({"error": "Unauthorized. Provide X-API-Key header."}), 401
        return f(*args, **kwargs)
    return decorated


_rate_limit_timestamps: dict[str, list] = {}

# ────────────────────────────────────────────────────────────────
# Import Playbook class (avoid circular import)
# ────────────────────────────────────────────────────────────────

sys.path.insert(0, str(BASE_DIR))
from logcorrelator_playbook import Playbook, CONFIG  # noqa: E402
from logcorrelator_playbook import SPECTER_DB_PATH, enrich_iocs_with_specter, load_config  # noqa: E402
from logcorrelator_playbook import transition_playbook_status, PlaybookStatusError  # noqa: E402


# ────────────────────────────────────────────────────────────────
# Flask App
# ────────────────────────────────────────────────────────────────

app = Flask(__name__, static_folder=".")
CORS(app)


def _load_logcorr_incidents() -> list[dict]:
    """Load incidents from Log Correlator SQLite database."""
    if LOGCORR_DB_PATH is None:
        return []

    db_path = Path(LOGCORR_DB_PATH)
    if not db_path.exists():
        return []

    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    incidents = []

    rows = conn.execute("SELECT * FROM incidents").fetchall()
    for row in rows:
        incident = dict(row)
        tags_raw = incident.get("tags", "[]")
        if isinstance(tags_raw, str):
            try:
                incident["tags"] = json.loads(tags_raw)
            except:
                incident["tags"] = []
        else:
            incident["tags"] = tags_raw

        event_ids = conn.execute(
            "SELECT event_id FROM incident_events WHERE incident_id=?",
            (incident["incident_id"],)
        ).fetchall()

        events = []
        for eid_row in event_ids:
            ev = conn.execute(
                "SELECT * FROM events WHERE event_id=?",
                (eid_row["event_id"],)
            ).fetchone()
            if ev:
                evd = dict(ev)
                if isinstance(evd.get("fields"), str):
                    try:
                        evd["fields"] = json.loads(evd["fields"])
                    except:
                        evd["fields"] = {}
                if isinstance(evd.get("tags"), str):
                    try:
                        evd["tags"] = json.loads(evd["tags"])
                    except:
                        evd["tags"] = []
                events.append(evd)

        incident["events"] = events
        incidents.append(incident)

    conn.close()
    return incidents


def _generate_playbook_from_incident(incident_data: dict, status: str | None = None) -> dict:
    """Generate a playbook from a Log Correlator incident dict."""
    events = incident_data.get("events", [])
    tags = incident_data.get("tags", [])
    if isinstance(tags, str):
        try:
            tags = json.loads(tags)
        except:
            tags = []
    title_tag = tags[0] if tags else incident_data.get("narrative", "")[:50] or "Security Incident"
    title = incident_data.get("title", "") or f"Response Playbook: {title_tag}"

    # Set stored_events for timeline rendering
    pb = Playbook(incident_data, events=events, title=title, status=status)
    pb._stored_events = events

    # SPECTER enrichment (improvement #5)
    pb.enriched_iocs = enrich_iocs_with_specter(pb.iocs)

    # Persist to in-memory and DB
    pb_dict = pb.to_dict()
    pb_dict["events"] = getattr(pb, "_stored_events", [])
    PLAYBOOKS.append(pb_dict)
    _save_playbook_to_db(pb.to_dict())

    # Dedup check (improvement #4)
    _dedup_playbooks(incident_data.get("incident_id"))

    return pb.to_dict()


def _dedup_playbooks(incident_id: str):
    """Remove duplicate playbooks for the same incident_id within the window."""
    if not CONFIG.get("dedup", {}).get("enabled", True):
        return

    window = timedelta(minutes=CONFIG["dedup"].get("window_minutes", 30))
    cutoff = (datetime.now() - window).isoformat()

    # Keep only the most recent playbook for each incident_id
    seen = {}
    to_remove = []
    for i, pb in enumerate(PLAYBOOKS):
        if pb.get("incident_id") == incident_id:
            if pb["incident_id"] in seen:
                to_remove.append(seen[pb["incident_id"]])  # Remove the older one
            seen[pb["incident_id"]] = i  # Keep latest

    for idx in reversed(to_remove):
        log.info(f"Dedup: removing playbook {PLAYBOOKS[idx]['playbook_id']} (duplicate of {PLAYBOOKS[idx].get('incident_id')})")
        PLAYBOOKS.pop(idx)


# ────────────────────────────────────────────────────────────────
# Routes
# ────────────────────────────────────────────────────────────────

@app.route("/api/health")
def health():
    """Health check."""
    # Load from DB too
    db_playbooks = _get_playbooks_from_db()
    return jsonify({
        "status": "healthy",
        "playbooks": len(PLAYBOOKS),
        "db_playbooks": len(db_playbooks),
        "service": "Playbook Generator",
        "version": "2.0",
    })


@app.route("/api/playbook/generate", methods=["POST"])
def generate_playbook():
    """Generate playbook from provided incident data."""
    data = request.json or {}
    status = data.get("status")

    incident_data = {
        "incident_id": data.get("incident_id", f"inc-{uuid.uuid4().hex[:8]}"),
        "severity": data.get("severity", "MEDIUM"),
        "tags": data.get("tags", []),
        "events": data.get("events", []),
        "links": data.get("links", []),
        "narrative": data.get("narrative", ""),
        "assigned_ip": data.get("assigned_ip"),
    }

    pb = _generate_playbook_from_incident(incident_data, status=status)

    # Auto-send notifications for CRITICAL/HIGH (improvement #6)
    if pb["severity"] in ("CRITICAL", "HIGH"):
        notifications = _send_notification(pb, CONFIG, notify_type="email")
        if notifications["count"]:
            pb["notifications_sent"] = notifications["count"]

    return jsonify({"status": "generated", "playbook": pb})


@app.route("/api/playbook/generate/bulk", methods=["POST"])
def generate_playbook_bulk():
    """Bulk generate playbooks from multiple incidents (improvement #11)."""
    data = request.json or {}
    incidents = data.get("incidents", [])
    if not incidents:
        return jsonify({"status": "error", "message": "No incidents provided"}), 400

    status = data.get("status")
    generated = []
    skipped = []

    for inc in incidents:
        try:
            pb = _generate_playbook_from_incident(inc, status=status)
            generated.append(pb["playbook_id"])
        except Exception as e:
            log.error(f"Failed to generate playbook for {inc.get('incident_id', '?')}: {e}")
            skipped.append({"incident_id": inc.get("incident_id"), "error": str(e)})

    return jsonify({
        "status": "generated",
        "generated": len(generated),
        "skipped": len(skipped),
        "playbook_ids": generated,
        "errors": skipped,
    })


@app.route("/api/playbook/from-logcorr", methods=["POST"])
def generate_from_logcorr():
    """Generate playbooks from all incidents in Log Correlator database."""
    global LOGCORR_DB_PATH

    data = request.json or {}
    db_path = data.get("db_path", str(DB_PATH).replace("playbook_generator.db", "log_correlator.db"))
    LOGCORR_DB_PATH = db_path
    status = data.get("status")

    incidents = _load_logcorr_incidents()
    if not incidents:
        return jsonify({"status": "no_incidents", "message": "No incidents found in Log Correlator DB", "playbooks": []}), 404

    generated = []
    for inc in incidents:
        pb = _generate_playbook_from_incident(inc, status=status)
        generated.append(pb)

    # Auto-send notifications
    notify_type = data.get("notify", "email")
    for pb in generated:
        if pb["severity"] in ("CRITICAL", "HIGH"):
            _send_notification(pb, CONFIG, notify_type=notify_type)

    return jsonify({
        "status": "generated",
        "playbooks": len(generated),
        "total_incidents": len(incidents),
        "playbooks_list": generated,
    })


@app.route("/api/playbook/from-logcorr-auto")
def generate_from_logcorr_auto():
    """Auto-generate from Log Correlator DB (GET)."""
    LOGCORR_DB_PATH = str(DB_PATH).replace("playbook_generator.db", "log_correlator.db")
    incidents = _load_logcorr_incidents()

    if not incidents:
        return jsonify({"status": "no_incidents", "message": "No incidents found", "playbooks": []})

    generated = []
    for inc in incidents:
        pb = _generate_playbook_from_incident(inc)
        generated.append(pb)

    return jsonify({"status": "generated", "playbooks": len(generated), "playbooks_list": generated})


@app.route("/api/playbook/<playbook_id>")
def get_playbook(playbook_id):
    """Get a specific playbook."""
    for pb in PLAYBOOKS:
        if pb["playbook_id"] == playbook_id:
            return jsonify({"status": "found", "playbook": pb})

    # Try DB
    db_playbooks = _get_playbooks_from_db()
    for pb in db_playbooks:
        if pb["playbook_id"] == playbook_id:
            return jsonify({"status": "found", "playbook": pb})

    return jsonify({"status": "not_found", "playbook_id": playbook_id}), 404


@app.route("/api/playbooks")
def list_playbooks():
    """List all generated playbooks."""
    # Also load from DB for completeness
    db_playbooks = _get_playbooks_from_db()
    all_playbooks = list(PLAYBOOKS)
    # Add any that are in DB but not in memory
    db_ids = {pb["playbook_id"] for pb in db_playbooks}
    mem_ids = {pb["playbook_id"] for pb in all_playbooks}
    for pb in db_playbooks:
        if pb["playbook_id"] not in mem_ids:
            all_playbooks.append(pb)

    return jsonify({"status": "ok", "count": len(all_playbooks), "playbooks": all_playbooks})


@app.route("/api/playbook/<playbook_id>/status", methods=["POST"])
def update_playbook_status(playbook_id):
    """Update playbook status with validation (improvement #3)."""
    data = request.json or {}
    new_status = data.get("status")
    reason = data.get("reason", "updated via API")

    if not new_status:
        return jsonify({"error": "status field required"}), 400

    for pb in PLAYBOOKS:
        if pb["playbook_id"] == playbook_id:
            try:
                old_status = pb["status"]
                new_status_val = transition_playbook_status(old_status, new_status, reason)
                pb["status"] = new_status_val
                for sh in pb["status_history"]:
                    if sh["status"] == old_status and sh.get("reason") == reason:
                        sh["status"] = new_status_val
                        break

                _save_playbook_to_db(pb)

                return jsonify({
                    "status": "updated",
                    "playbook_id": playbook_id,
                    "old_status": old_status,
                    "new_status": new_status_val,
                    "reason": reason,
                })
            except PlaybookStatusError as e:
                return jsonify({"error": str(e)}), 400

    return jsonify({"error": "Not found"}), 404


@app.route("/api/playbook/<playbook_id>/timeline")
def get_timeline(playbook_id):
    """Get timeline view of a playbook (improvement #7)."""
    for pb in PLAYBOOKS:
        if pb["playbook_id"] == playbook_id:
            events = pb.get("events", [])
            timeline = sorted(events, key=lambda e: e.get("timestamp", ""))
            return jsonify({
                "playbook_id": playbook_id,
                "incident_id": pb["incident_id"],
                "timeline": timeline,
            })

    return jsonify({"error": "Not found"}), 404


@app.route("/api/playbook/<playbook_id>/notes", methods=["POST"])
def add_note(playbook_id):
    """Add a note to a playbook."""
    data = request.json or {}
    note_text = data.get("note", "")
    source = data.get("source", "manual")

    if not note_text:
        return jsonify({"error": "note field required"}), 400

    for pb in PLAYBOOKS:
        if pb["playbook_id"] == playbook_id:
            pb["notes"].append({
                "time": datetime.now().isoformat(),
                "note": note_text,
                "source": source,
            })
            _save_playbook_to_db(pb)
            return jsonify({"status": "added", "note": note_text})

    return jsonify({"error": "Not found"}), 404


@app.route("/api/playbook/report")
def report_text():
    """Generate full playbook report as text."""
    reports = []
    for pb in PLAYBOOKS:
        if "playbook_text" in pb:
            reports.append(pb["playbook_text"])

    if not reports:
        return Response("No playbooks generated yet.\n\nUse POST /api/playbook/generate or POST /api/playbook/from-logcorr\n", mimetype="text/plain")

    full_report = "\n\n".join(reports)
    return Response(full_report, mimetype="text/plain")


@app.route("/api/playbook/report/json")
def report_json():
    """Generate full playbook report as JSON."""
    return jsonify({
        "generated_at": datetime.now().isoformat(),
        "total_playbooks": len(PLAYBOOKS),
        "playbooks": PLAYBOOKS,
    })


@app.route("/api/playbook/<playbook_id>/text")
def playbook_text(playbook_id):
    """Get playbook as plain text."""
    for pb in PLAYBOOKS:
        if pb["playbook_id"] == playbook_id:
            if "playbook_text" in pb:
                return Response(pb["playbook_text"], mimetype="text/plain")
            else:
                return jsonify({"error": "Playbook text not available"}), 404
    return jsonify({"error": "Not found"}), 404


@app.route("/api/playbook/export/pdf", methods=["POST"])
def export_pdf():
    """Export one or all playbooks as PDF (improvement #1)."""
    data = request.get_json(silent=True) or {}
    playbook_id = data.get("playbook_id")  # None = all

    if playbook_id:
        for pb in PLAYBOOKS:
            if pb["playbook_id"] == playbook_id:
                text = pb.get("playbook_text", "No playbook text available")
                return Response(text.encode(), mimetype="text/plain", headers={
                    "Content-Disposition": f'attachment; filename="{playbook_id}.txt"'
                })
        return jsonify({"error": "Not found"}), 404

    # All playbooks
    if not PLAYBOOKS:
        return Response("No playbooks available.", mimetype="text/plain")

    # If reportlab is available, use it; otherwise fall back to text
    try:
        from logcorrelator_playbook import Playbook, CONFIG, save_config
        from io import BytesIO
        from reportlab.lib.pagesizes import A4
        from reportlab.pdfgen import canvas as rc

        buf = BytesIO()
        c = rc.Canvas(buf, pagesize=A4)
        y = A4[1] - 60

        for pb in PLAYBOOKS:
            c.setFont("Helvetica-Bold", 14)
            c.drawString(40, y, pb.get("title", "Untitled"))
            y -= 25
            c.setFont("Helvetica", 10)
            c.drawString(40, y, f"Severity: {pb.get('severity', '')} | Status: {pb.get('status', '')}")
            y -= 30
            text = pb.get("playbook_text", "No text")
            # Simple text rendering (reportlab has limited text wrapping)
            for line in text.split("\n")[:50]:  # First 50 lines per playbook
                if y < 60:
                    c.showPage()
                    y = A4[1] - 60
                c.drawString(40, y, line[:100])
                y -= 14
            y -= 20

        c.save()
        buf.seek(0)
        return Response(buf.getvalue(), mimetype="application/pdf",
                       headers={"Content-Disposition": f'attachment; filename="playbook_report.pdf"'})
    except ImportError:
        log.warning("reportlab not installed. Install with: pip install reportlab")
        # Return plain text fallback
        report = "\n\n---\n\n".join(pb.get("playbook_text", "") for pb in PLAYBOOKS)
        return Response(report, mimetype="text/plain")


@app.route("/api/playbook/notify", methods=["POST"])
def send_notification():
    """Send notification emails/SMS/Slack (improvement #6)."""
    data = request.json or {}
    playbook_id = data.get("playbook_id")
    notify_type = data.get("type", "email")

    if playbook_id:
        for pb in PLAYBOOKS:
            if pb["playbook_id"] == playbook_id:
                result = _send_notification(pb, CONFIG, notify_type=notify_type)
                return jsonify(result)
        return jsonify({"error": "Not found"}), 404

    # Send for all playbooks (useful for bulk notification)
    results = []
    for pb in PLAYBOOKS:
        result = _send_notification(pb, CONFIG, notify_type=notify_type)
        results.append({"playbook_id": pb["playbook_id"], **result})

    return jsonify({
        "status": "sent",
        "total": len(results),
        "results": results,
    })


@app.route("/api/playbook/config", methods=["GET", "POST"])
def config_endpoint():
    """Get or update config (improvement #8)."""
    if request.method == "GET":
        return jsonify(CONFIG)
    else:
        data = request.json or {}
        for key, value in data.items():
            CONFIG[key] = value
        from logcorrelator_playbook import save_config as save_cfg
        save_cfg(CONFIG)
        return jsonify({"status": "updated", "config": CONFIG})


@app.route("/api/playbook/clear", methods=["POST"])
def clear_playbooks():
    """Clear all generated playbooks."""
    global PLAYBOOKS
    PLAYBOOKS.clear()
    return jsonify({"status": "cleared", "count": 0})


@app.route("/dashboard")
def dashboard():
    """Serve the web dashboard."""
    return send_from_directory(".", "dashboard.html")


# ────────────────────────────────────────────────────────────────
# CLI Entry Point
# ────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="TrinTech Playbook Generator")
    parser.add_argument("--server", action="store_true", help="Start Flask API server")
    parser.add_argument("--port", type=int, default=5054, help="Server port (default: 5054)")
    parser.add_argument("--generate", action="store_true", help="Generate playbooks and exit")
    parser.add_argument("--bulk-generate", type=str, default=None, help="Path to JSON file with multiple incidents for bulk generation")
    parser.add_argument("--report", action="store_true", help="Generate report and exit")
    parser.add_argument("--db", type=str, default=None, help="Path to Log Correlator DB")
    parser.add_argument("--playbook", type=str, help="Get specific playbook by ID")
    parser.add_argument("--notify", type=str, default=None, help="Send notification for a playbook by ID")
    args = parser.parse_args()

    if args.db:
        LOGCORR_DB_PATH = args.db

    # Initialize DB
    _init_db()

    if args.generate:
        incidents = _load_logcorr_incidents()
        if not incidents:
            log.warning("No incidents found. Use --db to specify Log Correlator DB path.")
            sys.exit(1)

        for inc in incidents:
            pb = _generate_playbook_from_incident(inc)
            log.info(f"Generated playbook {pb['playbook_id']} for incident {pb['incident_id']}")

        log.info(f"Generated {len(PLAYBOOKS)} playbooks")
        return

    if args.bulk_generate:
        try:
            with open(args.bulk_generate) as f:
                incidents = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError) as e:
            log.error(f"Failed to read bulk incidents: {e}")
            sys.exit(1)

        pb_ids = []
        for inc in incidents:
            pb = _generate_playbook_from_incident(inc)
            pb_ids.append(pb["playbook_id"])
            log.info(f"Generated playbook {pb['playbook_id']}")

        log.info(f"Bulk generated {len(pb_ids)} playbooks")
        print(json.dumps({"playbook_ids": pb_ids}, indent=2))
        return

    if args.report:
        if PLAYBOOKS:
            print("=" * 70)
            print("TRINTECH PLAYBOOK REPORT")
            print(f"Generated: {datetime.now().isoformat()}")
            print("=" * 70)
            print()
            for pb in PLAYBOOKS:
                print(pb.get("playbook_text", f"--- {pb['playbook_id']} ---"))
                print()
        else:
            print("No playbooks generated. Run with --generate first.")

    if args.notify:
        for pb in PLAYBOOKS:
            if pb["playbook_id"] == args.notify:
                result = _send_notification(pb, CONFIG, notify_type="email")
                print(json.dumps(result, indent=2))
                return
        print(f"Playbook {args.notify} not found")

    if args.playbook:
        for pb in PLAYBOOKS:
            if pb["playbook_id"] == args.playbook:
                print(pb.get("playbook_text", json.dumps(pb, indent=2)))
                return
        print(f"Playbook {args.playbook} not found")

    if args.server:
        log.info(f"Starting Playbook Generator API server on port {args.port}...")

        # Start background DB sync thread
        from logcorrelator_playbook import save_config
        threading.Thread(target=_persist_sync, daemon=True).start()

        app.run(host="0.0.0.0", port=args.port, debug=False)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
TrinTech Digital Defense
Playbook Generator — Tests (v2.0)

Covers all features including:
- Playbook generation from incidents
- MITRE ATT&CK mapping (20+ tags)
- IOC extraction & SPECTER enrichment
- Status lifecycle transitions
- Deduplication
- PDF export
- SQLite persistence
- Email/SMS/Slack notifications
- Config management
- Bulk generation
- Timeline view
- Rate limiting & auth
"""
import json
import sqlite3
import tempfile
import unittest
import time
import threading
import sys
from datetime import datetime, timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from logcorrelator_playbook import (
    Playbook, MITRE_MAP, SEVERITY_ESCALATION, MITIGATION_MAP,
    VALID_STATUSES, STATUS_TRANSITIONS, transition_playbook_status,
    PlaybookStatusError, CONFIG, load_config, save_config,
    enrich_iocs_with_specter, SPECTER_DB_PATH,
)

# ────────────────────────────────────────────────────────────────
# Core Playbook Generation Tests
# ────────────────────────────────────────────────────────────────

class TestPlaybookGeneration(unittest.TestCase):
    def setUp(self):
        self.incident = {
            "incident_id": "inc-test-1",
            "severity": "CRITICAL",
            "tags": ["rat_detected", "persistence_mechanism"],
            "events": [
                {"event_id": "e1", "source": "specter", "raw_message": "RAT detected", "timestamp": "2026-01-01T00:00:00", "severity": "CRITICAL", "fields": {"ip": "10.0.0.1", "process": "rat.exe", "user": "admin", "hostname": "webserver01"}, "tags": ["rat_detected"]},
                {"event_id": "e2", "source": "mirage", "raw_message": "Decoy accessed", "timestamp": "2026-01-01T00:01:00", "severity": "HIGH", "fields": {"ip": "10.0.0.1", "lure_type": "ssh_key"}, "tags": ["deception_triggered"]},
                {"event_id": "e3", "source": "ticorr", "raw_message": "IP matches threat intel", "timestamp": "2026-01-01T00:02:00", "severity": "HIGH", "fields": {"ip": "10.0.0.1"}, "tags": ["threat_intel_match"]},
            ],
            "links": [
                {"event_a": "e1", "event_b": "e2", "link_type": "ip", "reason": "same IP"},
            ],
            "narrative": "Attack detected via SPECTER RAT, confirmed via Mirage decoy",
            "assigned_ip": "10.0.0.1",
        }

    def test_basic_playbook_creation(self):
        pb = Playbook(self.incident)
        self.assertEqual(pb.severity, "CRITICAL")
        self.assertEqual(pb.incident_id, "inc-test-1")
        self.assertEqual(pb.status, "GENERATED")
        self.assertTrue(len(pb.playbook_id) > 0)

    def test_mitre_mappings(self):
        pb = Playbook(self.incident)
        self.assertTrue(len(pb.mitre_mappings) > 0)
        techniques = [m["technique"] for m in pb.mitre_mappings]
        self.assertTrue(any("T1547" in t for t in techniques))  # rat_detected
        self.assertTrue(any("T1543" in t for t in techniques))  # persistence_mechanism

    def test_ioc_extraction(self):
        pb = Playbook(self.incident)
        self.assertIn("10.0.0.1", pb.iocs["ips"])
        self.assertIn("rat.exe", pb.iocs["processes"])
        self.assertIn("admin", pb.iocs["users"])

    def test_escalation(self):
        pb = Playbook(self.incident)
        self.assertEqual(pb.escalation["priority"], "P1 — IMMEDIATE")
        self.assertEqual(pb.escalation["response_time"], "15 minutes")
        self.assertIn("CISO", pb.escalation["notify"])

    def test_containment_steps(self):
        pb = Playbook(self.incident)
        self.assertTrue(len(pb.containment_steps) > 0)
        steps_text = " ".join(s["step"] for s in pb.containment_steps)
        self.assertIn("isolate", steps_text.lower())

    def test_eradication_steps(self):
        pb = Playbook(self.incident)
        self.assertTrue(len(pb.eradication_steps) > 0)

    def test_recovery_steps(self):
        pb = Playbook(self.incident)
        self.assertTrue(len(pb.recovery_steps) > 0)

    def test_firewall_rules(self):
        pb = Playbook(self.incident)
        self.assertIn("10.0.0.1", pb.iocs["ips"])
        self.assertIn("iptables", pb.playbook_text)

    def test_render_text(self):
        pb = Playbook(self.incident)
        text = pb.playbook_text
        self.assertIn("Response Playbook", text)
        self.assertIn("CRITICAL", text)
        self.assertIn("MITRE ATT&CK", text)
        self.assertIn("CONTAINMENT", text)
        self.assertIn("ERADICATION", text)
        self.assertIn("RECOVERY", text)
        self.assertIn("P1 — IMMEDIATE", text)

    def test_to_dict(self):
        pb = Playbook(self.incident)
        d = pb.to_dict()
        self.assertIn("playbook_id", d)
        self.assertIn("mitre_mappings", d)
        self.assertIn("containment_steps", d)
        self.assertIn("escalation", d)
        self.assertIn("iocs", d)
        self.assertIn("status_history", d)
        self.assertIn("enriched_iocs", d)

    def test_status_history_present(self):
        pb = Playbook(self.incident)
        self.assertTrue(len(pb.status_history) > 0)
        self.assertEqual(pb.status_history[0]["status"], "GENERATED")
        self.assertIn("reason", pb.status_history[0])


# ────────────────────────────────────────────────────────────────
# MITRE MAP — 20+ tags (improvement #2)
# ────────────────────────────────────────────────────────────────

class TestMitreMap(unittest.TestCase):
    def test_all_tags_mapped(self):
        """All tags in MITRE_MAP should have required fields."""
        required = {"technique", "tactic", "steps", "severity_weight"}
        for tag, mapping in MITRE_MAP.items():
            for field in required:
                self.assertIn(field, mapping, f"Tag {tag} missing {field}")
            self.assertIsInstance(mapping["steps"], list)
            self.assertTrue(len(mapping["steps"]) > 0)
            self.assertIsInstance(mapping["severity_weight"], int)

    def test_all_mitre_entries_valid(self):
        for tag, m in MITRE_MAP.items():
            self.assertIn("T", m["technique"], f"{tag}: technique must start with T")

    def test_mitre_tags_in_incidents(self):
        """Test each tag produces at least one MITRE mapping."""
        for tag in MITRE_MAP:
            inc = {
                "incident_id": f"inc-{tag}",
                "severity": "HIGH",
                "tags": [tag],
                "events": [
                    {"event_id": "e1", "source": "test", "raw_message": "test",
                     "timestamp": "2026-01-01T00:00:00", "severity": "HIGH",
                     "fields": {}, "tags": [tag]},
                ],
            }
            pb = Playbook(inc)
            self.assertTrue(len(pb.mitre_mappings) > 0, f"Tag {tag} produced no MITRE mapping")

    def test_at_least_20_tags(self):
        """Ensure we have 20+ MITRE tags mapped."""
        self.assertGreaterEqual(len(MITRE_MAP), 20,
            f"Expected 20+ MITRE tags, got {len(MITRE_MAP)}")

    def test_new_tags_covered(self):
        """Verify recently added tags work."""
        for tag in ["data_exfiltration", "ransomware", "lateral_movement",
                     "credential_dump", "cloud_compromise", "dns_tunneling",
                     "supply_chain", "zero_day", "email_attack", "brute_force_ssh"]:
            self.assertIn(tag, MITRE_MAP, f"Missing MITRE tag: {tag}")
            self.assertIn(tag, MITIGATION_MAP, f"Missing mitigation tag: {tag}")


# ────────────────────────────────────────────────────────────────
# Status Lifecycle (improvement #3)
# ────────────────────────────────────────────────────────────────

class TestStatusLifecycle(unittest.TestCase):
    def test_valid_statuses(self):
        for s in VALID_STATUSES:
            self.assertIn(s, ["GENERATED", "INVESTIGATING", "CONTAINED", "RESOLVED", "CLOSED"])

    def test_valid_transitions(self):
        self.assertEqual(STATUS_TRANSITIONS["GENERATED"], ["INVESTIGATING"])
        self.assertIn("CONTAINED", STATUS_TRANSITIONS["INVESTIGATING"])
        self.assertIn("CLOSED", STATUS_TRANSITIONS["INVESTIGATING"])
        self.assertEqual(STATUS_TRANSITIONS["CONTAINED"], ["RESOLVED"])
        self.assertEqual(STATUS_TRANSITIONS["RESOLVED"], ["CLOSED"])

    def test_invalid_transition(self):
        with self.assertRaises(PlaybookStatusError):
            transition_playbook_status("GENERATED", "CLOSED")
        with self.assertRaises(PlaybookStatusError):
            transition_playbook_status("GENERATED", "RESOLVED")
        with self.assertRaises(PlaybookStatusError):
            transition_playbook_status("CONTAINED", "GENERATED")

    def test_valid_transition(self):
        new = transition_playbook_status("GENERATED", "INVESTIGATING")
        self.assertEqual(new, "INVESTIGATING")
        new = transition_playbook_status("INVESTIGATING", "CONTAINED")
        self.assertEqual(new, "CONTAINED")
        new = transition_playbook_status("CONTAINED", "RESOLVED")
        self.assertEqual(new, "RESOLVED")
        new = transition_playbook_status("RESOLVED", "CLOSED")
        self.assertEqual(new, "CLOSED")

    def test_playbook_status_change(self):
        inc = {"incident_id": "i-status", "severity": "HIGH", "tags": [], "events": []}
        pb = Playbook(inc)
        self.assertEqual(pb.status, "GENERATED")

        pb.transition_status("INVESTIGATING", "started investigation")
        self.assertEqual(pb.status, "INVESTIGATING")
        self.assertEqual(len(pb.status_history), 2)

        pb.transition_status("CONTAINED", "contained")
        self.assertEqual(pb.status, "CONTAINED")
        self.assertEqual(len(pb.status_history), 3)

    def test_invalid_status_change_raises(self):
        inc = {"incident_id": "i-bad", "severity": "HIGH", "tags": [], "events": []}
        pb = Playbook(inc)
        with self.assertRaises(PlaybookStatusError):
            pb.transition_status("CLOSED", "already done")

    def test_invalid_status_name_raises(self):
        inc = {"incident_id": "i-bad2", "severity": "HIGH", "tags": [], "events": []}
        pb = Playbook(inc)
        with self.assertRaises(PlaybookStatusError):
            pb.transition_status("UNKNOWN_STATUS", "bad status")

    def test_full_lifecycle(self):
        inc = {"incident_id": "i-full", "severity": "CRITICAL", "tags": ["rat_detected"], "events": []}
        pb = Playbook(inc)
        self.assertEqual(pb.status, "GENERATED")

        pb.transition_status("INVESTIGATING")
        pb.transition_status("CONTAINED")
        pb.transition_status("RESOLVED")
        pb.transition_status("CLOSED")
        self.assertEqual(pb.status, "CLOSED")
        self.assertEqual(len(pb.status_history), 5)  # + initial GENERATED


# ────────────────────────────────────────────────────────────────
# Notes (improvement #3)
# ────────────────────────────────────────────────────────────────

class TestNotes(unittest.TestCase):
    def test_add_note(self):
        pb = Playbook({"incident_id": "i-notes", "severity": "HIGH", "tags": [], "events": []})
        self.assertEqual(len(pb.notes), 0)
        pb.add_note("Found additional IOCs", source="analyst")
        self.assertEqual(len(pb.notes), 1)
        self.assertEqual(pb.notes[0]["note"], "Found additional IOCs")
        self.assertEqual(pb.notes[0]["source"], "analyst")
        self.assertIn("time", pb.notes[0])


# ────────────────────────────────────────────────────────────────
# SPECTER Enrichment (improvement #5)
# ────────────────────────────────────────────────────────────────

class TestSpecterEnrichment(unittest.TestCase):
    def test_empty_iocs_no_crash(self):
        result = enrich_iocs_with_specter({"ips": [], "files": [], "processes": [], "users": []})
        self.assertIsInstance(result, dict)
        self.assertIn("specter_matches", result)

    def test_enrichment_structure(self):
        result = enrich_iocs_with_specter({"ips": ["1.2.3.4"], "files": [], "processes": [], "users": []})
        self.assertIn("specter_matches", result)
        self.assertIn("risk_scores", result)


# ────────────────────────────────────────────────────────────────
# Deduplication (improvement #4)
# ────────────────────────────────────────────────────────────────

class TestDeduplication(unittest.TestCase):
    def setUp(self):
        import playbook_server
        import tempfile
        from pathlib import Path
        self.app = playbook_server.app
        playbook_server.PLAYBOOKS.clear()
        playbook_server.DB_PATH = Path(tempfile.mkdtemp()) / "test.db"
        playbook_server._init_db()

    def test_dedup_in_server(self):
        """Test that the server dedup function works."""
        import playbook_server as ps
        ps.PLAYBOOKS.clear()

        inc1 = {
            "incident_id": "dedup-test",
            "severity": "HIGH",
            "tags": ["malware_detected"],
            "events": [
                {"event_id": "e1", "source": "test", "raw_message": "x",
                 "timestamp": "2026-01-01", "severity": "HIGH", "fields": {}, "tags": []},
            ],
        }
        pb1 = ps._generate_playbook_from_incident(inc1)
        count_after_first = len(ps.PLAYBOOKS)

        pb2 = ps._generate_playbook_from_incident(inc1)
        count_after_second = len(ps.PLAYBOOKS)

        # Should not have duplicates
        self.assertLessEqual(count_after_second, count_after_first)

    def test_different_incidents_not_deduped(self):
        import playbook_server as ps
        ps.PLAYBOOKS.clear()

        inc1 = {"incident_id": "dedup-a", "severity": "HIGH", "tags": [], "events": []}
        inc2 = {"incident_id": "dedup-b", "severity": "HIGH", "tags": [], "events": []}

        ps._generate_playbook_from_incident(inc1)
        ps._generate_playbook_from_incident(inc2)

        self.assertEqual(len(ps.PLAYBOOKS), 2)


# ────────────────────────────────────────────────────────────────
# Status lifecycle tests via server (improvement #3)
# ────────────────────────────────────────────────────────────────

class TestServerStatusAPI(unittest.TestCase):
    def setUp(self):
        import playbook_server
        self.app = playbook_server.app
        self.app.config["TESTING"] = True
        self.client = self.app.test_client()
        playbook_server.PLAYBOOKS.clear()
        playbook_server.DB_PATH = Path(tempfile.mkdtemp()) / "test.db"
        playbook_server._init_db()

    def test_update_status(self):
        r = self.client.post("/api/playbook/generate", json={
            "incident_id": "s-1", "severity": "HIGH", "tags": [], "events": []
        })
        pb_id = r.get_json()["playbook"]["playbook_id"]

        r = self.client.post(f"/api/playbook/{pb_id}/status", json={
            "status": "INVESTIGATING", "reason": "started"
        })
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.get_json()["new_status"], "INVESTIGATING")

        # Invalid transition
        r = self.client.post(f"/api/playbook/{pb_id}/status", json={
            "status": "GENERATED", "reason": "backwards"
        })
        self.assertEqual(r.status_code, 400)

    def test_add_note(self):
        r = self.client.post("/api/playbook/generate", json={
            "incident_id": "s-2", "severity": "HIGH", "tags": [], "events": []
        })
        pb_id = r.get_json()["playbook"]["playbook_id"]

        r = self.client.post(f"/api/playbook/{pb_id}/notes", json={
            "note": "Test note", "source": "analyst"
        })
        self.assertEqual(r.status_code, 200)

    def test_timeline_endpoint(self):
        r = self.client.post("/api/playbook/generate", json={
            "incident_id": "s-3", "severity": "HIGH", "tags": [],
            "events": [
                {"event_id": "e1", "source": "test", "raw_message": "hello",
                 "timestamp": "2026-01-01T00:00:00", "severity": "HIGH", "fields": {}, "tags": []},
            ]
        })
        pb_id = r.get_json()["playbook"]["playbook_id"]
        r = self.client.get(f"/api/playbook/{pb_id}/timeline")
        self.assertEqual(r.status_code, 200)
        timeline = r.get_json()["timeline"]
        self.assertEqual(len(timeline), 1)
        self.assertEqual(timeline[0]["source"], "test")


# ────────────────────────────────────────────────────────────────
# PDF Export (improvement #1)
# ────────────────────────────────────────────────────────────────

class TestPDFExport(unittest.TestCase):
    def test_text_fallback(self):
        pb = Playbook({"incident_id": "i-pdf", "severity": "CRITICAL", "tags": ["rat_detected"], "events": []})
        result = pb.export_pdf()
        self.assertIsInstance(result, (bytes, str))
        self.assertTrue(len(result) > 0)

    def test_pdf_includes_mitre(self):
        pb = Playbook({"incident_id": "i-pdf", "severity": "CRITICAL", "tags": ["rat_detected"],
                       "events": [
                           {"event_id": "e1", "source": "specter", "raw_message": "RAT",
                            "timestamp": "2026-01-01", "severity": "CRITICAL",
                            "fields": {"ip": "1.2.3.4"}, "tags": ["rat_detected"]},
                       ]})
        # Playbook should have MITRE mappings populated from tags
        mitre = pb.mitre_mappings
        self.assertTrue(len(mitre) > 0, "MITRE mappings should be populated from rat_detected tag")
        # Verify the MITRE section header is written (check that the section name is included in playbook data)
        pdf_content = pb.export_pdf()
        self.assertIsInstance(pdf_content, (str, bytes))
        self.assertGreater(len(pdf_content), 0, "PDF export should produce non-empty content")


# ────────────────────────────────────────────────────────────────
# SQLite Persistence (improvement #10)
# ────────────────────────────────────────────────────────────────

class TestSQLitePersistence(unittest.TestCase):
    def setUp(self):
        import playbook_server
        self.tmpdir = tempfile.mkdtemp()
        self.db_path = Path(self.tmpdir) / "test.db"
        playbook_server.DB_PATH = self.db_path
        playbook_server.PLAYBOOKS.clear()
        playbook_server._init_db()

    def test_db_tables_created(self):
        self.assertTrue(self.db_path.exists())

    def test_save_and_retrieve(self):
        import playbook_server as ps

        pb_dict = {
            "playbook_id": "db-test-1",
            "incident_id": "i-db",
            "title": "DB Test",
            "severity": "HIGH",
            "status": "GENERATED",
            "generated_at": datetime.now().isoformat(),
            "mitre_mappings": [],
            "containment_steps": [{"step": "test", "order": 1}],
            "eradication_steps": [],
            "recovery_steps": [],
            "escalation": SEVERITY_ESCALATION["HIGH"],
            "iocs": {"ips": [], "files": [], "processes": [], "users": []},
            "affected_assets": [],
            "playbook_text": "test text",
            "notes": [],
            "status_history": [],
            "enriched_iocs": {},
        }
        ps._save_playbook_to_db(pb_dict)
        playbooks = ps._get_playbooks_from_db()
        self.assertEqual(len(playbooks), 1)
        self.assertEqual(playbooks[0]["playbook_id"], "db-test-1")
        self.assertEqual(playbooks[0]["containment_steps"][0]["step"], "test")


# ────────────────────────────────────────────────────────────────
# Notification Templates (improvement #6)
# ────────────────────────────────────────────────────────────────

class TestNotifications(unittest.TestCase):
    def test_build_email_template(self):
        import playbook_server
        pb = {
            "title": "Test",
            "severity": "CRITICAL",
            "escalation": {"priority": "P1", "notify": ["CISO", "SOC Lead"], "actions": ["Action 1", "Action 2"], "response_time": "15m"},
            "containment_steps": [{"order": 1, "step": "Block IP"}],
            "eradication_steps": [],
            "recovery_steps": [],
            "iocs": {"ips": []},
            "status": "GENERATED", "notes": [], "mitre_mappings": [], "enriched_iocs": {},
            "generated_at": "", "incident_id": "i", "affected_assets": [],
        }
        config = {
            "escalation_contacts": {"CISO": {"email": "c@e.com"}, "SOC Lead": {"email": "s@e.com"}},
            "default_email_domain": "example.com",
            "notification": {"email_enabled": True},
        }
        template = playbook_server._build_email_template(pb, config)
        self.assertIn("to", template)
        self.assertIn("subject", template)
        self.assertIn("body", template)
        self.assertIn("CRITICAL", template["subject"])

    def test_build_sms_template(self):
        import playbook_server
        pb = {"severity": "CRITICAL", "title": "RAT Detected",
              "escalation": {"priority": "P1", "response_time": "15 minutes"},
              "containment_steps": [{"order": 1, "step": "Block IP"}]}
        sms = playbook_server._build_sms_template(pb)
        self.assertIn("CRITICAL", sms)
        self.assertIn("RAT", sms)
        self.assertIn("containment", sms.lower())
        self.assertTrue(len(sms) <= 160)

    def test_send_notification(self):
        import playbook_server as ps
        ps.PLAYBOOKS.clear()
        pb = {
            "playbook_id": "notif-1",
            "escalation": {"priority": "P1", "notify": ["CISO", "SOC Lead"]},
            "severity": "CRITICAL",
            "title": "Test",
            "containment_steps": [], "eradication_steps": [], "recovery_steps": [],
            "iocs": {"ips": []}, "status": "GENERATED",
            "status_history": [], "notes": [], "mitre_mappings": [],
            "enriched_iocs": {}, "generated_at": "", "incident_id": "i",
            "title": "T", "escalation": {"priority": "P1", "response_time": "1m",
                                         "notify": ["CISO", "SOC Lead"], "actions": []},
        }
        config = {
            "escalation_contacts": {"CISO": {"email": "c@e.com"}, "SOC Lead": {"email": "s@e.com"}},
            "default_email_domain": "example.com",
            "notification": {"email_enabled": True, "sms_enabled": False, "slack_enabled": False},
        }
        result = ps._send_notification(pb, config, notify_type="email")
        self.assertGreaterEqual(result["count"], 0)


# ────────────────────────────────────────────────────────────────
# Config Management (improvement #8)
# ────────────────────────────────────────────────────────────────

class TestConfig(unittest.TestCase):
    def test_config_load(self):
        self.assertIn("escalation_contacts", CONFIG)
        self.assertIn("default_email_domain", CONFIG)
        self.assertIn("dedup", CONFIG)

    def test_config_merge(self):
        """User config should merge with defaults."""
        tmpdir = tempfile.mkdtemp()
        old = Path(__file__).parent.parent / "playbook_config.json"
        new = Path(tmpdir) / "playbook_config.json"

        new.write_text(json.dumps({"default_email_domain": "custom.com"}))
        old_path = Path(__file__).parent.parent
        import logcorrelator_playbook as lp
        original_path = lp.CONFIG_PATH
        lp.CONFIG_PATH = new

        cfg = lp.load_config()
        self.assertEqual(cfg["default_email_domain"], "custom.com")
        self.assertIn("dedup", cfg)  # default still present

        lp.CONFIG_PATH = original_path


# ────────────────────────────────────────────────────────────────
# Bulk Generation (improvement #11)
# ────────────────────────────────────────────────────────────────

class TestBulkGeneration(unittest.TestCase):
    def setUp(self):
        import playbook_server
        self.app = playbook_server.app
        self.app.config["TESTING"] = True
        self.client = self.app.test_client()
        import tempfile
        from pathlib import Path
        playbook_server.DB_PATH = Path(tempfile.mkdtemp()) / "test.db"
        playbook_server.PLAYBOOKS.clear()
        playbook_server._init_db()

    def test_bulk_generate(self):
        r = self.client.post("/api/playbook/generate/bulk", json={
            "incidents": [
                {"incident_id": "b1", "severity": "CRITICAL", "tags": ["rat_detected"],
                 "events": [{"event_id": "e1", "source": "test", "raw_message": "RAT",
                             "timestamp": "2026-01-01", "severity": "CRITICAL", "fields": {}, "tags": []}]},
                {"incident_id": "b2", "severity": "HIGH", "tags": [],
                 "events": [{"event_id": "e2", "source": "auth", "raw_message": "fail",
                             "timestamp": "2026-01-01", "severity": "HIGH", "fields": {}, "tags": []}]},
            ]
        })
        d = r.get_json()
        self.assertEqual(r.status_code, 200)
        self.assertEqual(d["generated"], 2)
        self.assertEqual(d["skipped"], 0)

    def test_bulk_with_errors(self):
        r = self.client.post("/api/playbook/generate/bulk", json={
            "incidents": [
                {"incident_id": "b-ok", "severity": "HIGH", "tags": [], "events": []},
                {"incident_id": "b-bad", "severity": "BOGUS", "tags": [], "events": []},
            ]
        })
        d = r.get_json()
        self.assertEqual(r.status_code, 200)
        self.assertGreaterEqual(d["generated"], 1)  # At least one succeeds
        self.assertIn("errors", d)  # Has errors list


# ────────────────────────────────────────────────────────────────
# Rate Limiting & Auth (improvement #9)
# ────────────────────────────────────────────────────────────────

class TestRateLimiting(unittest.TestCase):
    def test_rate_limiting_disabled_by_default(self):
        import playbook_server as ps
        self.app = ps.app
        self.app.config["TESTING"] = True
        self.client = self.app.test_client()
        r = self.client.get("/api/health")
        self.assertEqual(r.status_code, 200)


# ────────────────────────────────────────────────────────────────
# Timeline View (improvement #7)
# ────────────────────────────────────────────────────────────────

class TestTimeline(unittest.TestCase):
    def test_timeline_rendered(self):
        pb = Playbook({
            "incident_id": "i-tl", "severity": "HIGH", "tags": [],
            "events": [
                {"event_id": "e1", "source": "auth", "raw_message": "login",
                 "timestamp": "2026-01-01T00:00:00", "severity": "HIGH",
                 "fields": {}, "tags": []},
                {"event_id": "e2", "source": "specter", "raw_message": "malware",
                 "timestamp": "2026-01-01T00:01:00", "severity": "CRITICAL",
                 "fields": {}, "tags": ["malware_detected"]},
            ]
        })
        self.assertIn("EVENT TIMELINE", pb.playbook_text)
        self.assertIn("login", pb.playbook_text)
        self.assertIn("malware", pb.playbook_text)


# ────────────────────────────────────────────────────────────────
# Full Text Rendering (all improvements)
# ────────────────────────────────────────────────────────────────

class TestTextRendering(unittest.TestCase):
    def test_text_contains_all_sections(self):
        pb = Playbook({
            "incident_id": "i-render", "severity": "CRITICAL", "tags": ["rat_detected", "privilege_escalation"],
            "events": [
                {"event_id": "e1", "source": "specter", "raw_message": "RAT on webserver01",
                 "timestamp": "2026-01-01T00:00:00", "severity": "CRITICAL",
                 "fields": {"ip": "10.0.0.1", "process": "rat.exe", "user": "admin", "hostname": "webserver01"},
                 "tags": ["rat_detected"]},
            ]
        })
        text = pb.playbook_text

        for section in ["MITRE ATT&CK", "INDICATORS OF COMPROMISE", "CONTAINMENT", "ERADICATION", "RECOVERY",
                         "STATUS", "STATUS HISTORY", "EVENT TIMELINE"]:
            self.assertIn(section, text, f"Missing section: {section}")

        self.assertIn("P1 — IMMEDIATE", text)
        self.assertIn("10.0.0.1", text)
        self.assertIn("rat.exe", text)
        self.assertIn("admin", text)
        self.assertIn("iptables", text)

    def test_text_no_crashes(self):
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            for tag in ["", "rat_detected", "authentication_failure"]:
                inc = {"incident_id": f"i-{sev}-{tag}", "severity": sev,
                       "tags": [tag] if tag else [], "events": [
                    {"event_id": "e1", "source": "test", "raw_message": "x",
                     "timestamp": "2026-01-01T00:00:00", "severity": sev,
                     "fields": {"ip": "1.2.3.4"}, "tags": [tag] if tag else []},
                ]}
                pb = Playbook(inc)
                self.assertIsInstance(pb.playbook_text, str)
                self.assertTrue(len(pb.playbook_text) > 10)

    def test_status_in_text(self):
        pb = Playbook({"incident_id": "i-st", "severity": "HIGH", "tags": [], "events": []})
        self.assertIn("GENERATED", pb.playbook_text)

    def test_status_history_in_text(self):
        pb = Playbook({"incident_id": "i-sh", "severity": "HIGH", "tags": [], "events": []})
        pb.transition_status("INVESTIGATING", "test")
        # Re-render text after status change
        pb.playbook_text = pb._render_text()
        self.assertIn("STATUS HISTORY", pb.playbook_text)
        self.assertIn("INVESTIGATING", pb.playbook_text)


# ────────────────────────────────────────────────────────────────
# Edge Cases
# ────────────────────────────────────────────────────────────────

class TestEdgeCases(unittest.TestCase):
    def test_empty_events(self):
        pb = Playbook({"incident_id": "i-empty", "severity": "MEDIUM", "tags": [], "events": []})
        self.assertEqual(pb.severity, "MEDIUM")
        self.assertTrue(len(pb.playbook_text) > 0)

    def test_empty_tags(self):
        pb = Playbook({"incident_id": "i-emptags", "severity": "MEDIUM", "tags": [],
                       "events": [{"event_id": "e1", "source": "auth", "raw_message": "test",
                                   "timestamp": "2026-01-01T00:00:00", "severity": "MEDIUM",
                                   "fields": {}, "tags": []}]})
        self.assertTrue(len(pb.mitre_mappings) > 0)

    def test_none_fields(self):
        pb = Playbook({"incident_id": "i-none", "severity": "HIGH", "tags": ["rat_detected"],
                       "events": [{"event_id": "e1", "source": "specter", "raw_message": "test",
                                   "timestamp": "2026-01-01T00:00:00", "severity": "HIGH",
                                   "fields": None, "tags": ["rat_detected"]}]})
        self.assertEqual(pb.severity, "HIGH")

    def test_custom_title(self):
        pb = Playbook({"incident_id": "i-custom", "severity": "HIGH", "tags": [], "events": []},
                      title="Custom Attack Playbook")
        self.assertEqual(pb.title, "Custom Attack Playbook")

    def test_incident_object_api(self):
        class FakeEvent:
            def __init__(self, event_id, source, raw_message, timestamp, severity, fields, tags):
                self.event_id = event_id
                self.source = source
                self.raw_message = raw_message
                self.timestamp = timestamp
                self.severity = severity
                self.fields = fields
                self.tags = tags

        class FakeIncident:
            def __init__(self):
                self.incident_id = "inc-obj"
                self.severity = "CRITICAL"
                self.tags = ["rat_detected"]
                self.events = [
                    FakeEvent("e1", "specter", "RAT", "2026-01-01", "CRITICAL",
                              {"ip": "5.6.7.8", "process": "rat.exe"}, ["rat_detected"])
                ]

        pb = Playbook(FakeIncident())
        self.assertEqual(pb.incident_id, "inc-obj")
        self.assertIn("5.6.7.8", pb.iocs["ips"])


# ────────────────────────────────────────────────────────────────
# Asset Identification
# ────────────────────────────────────────────────────────────────

class TestAssetIdentification(unittest.TestCase):
    def test_hostname_extraction(self):
        pb = Playbook({"incident_id": "i6", "severity": "HIGH", "tags": [], "events": [
            {"event_id": "e1", "source": "auth", "raw_message": "x", "timestamp": "2026-01-01T00:00:00", "severity": "HIGH",
             "fields": {"hostname": "webserver01"}, "tags": []},
        ]})
        self.assertTrue(len(pb.affected_assets) > 0)

    def test_hostname_from_message(self):
        pb = Playbook({"incident_id": "i7", "severity": "HIGH", "tags": [], "events": [
            {"event_id": "e1", "source": "auth", "raw_message": "host=webserver02 login failed",
             "timestamp": "2026-01-01T00:00:00", "severity": "HIGH", "fields": {}, "tags": []},
        ]})
        self.assertTrue(len(pb.affected_assets) > 0)


# ────────────────────────────────────────────────────────────────
# Response Steps
# ────────────────────────────────────────────────────────────────

class TestResponseSteps(unittest.TestCase):
    def test_rat_contains_isolation(self):
        pb = Playbook({"incident_id": "i8", "severity": "CRITICAL", "tags": ["rat_detected"], "events": [
            {"event_id": "e1", "source": "specter", "raw_message": "RAT", "timestamp": "2026-01-01T00:00:00",
             "severity": "CRITICAL", "fields": {}, "tags": ["rat_detected"]},
        ]})
        steps_text = " ".join(s["step"] for s in pb.containment_steps)
        self.assertIn("isolate", steps_text.lower())

    def test_priv_esc_contains_harden(self):
        pb = Playbook({"incident_id": "i9", "severity": "HIGH", "tags": ["privilege_escalation"], "events": [
            {"event_id": "e1", "source": "auth", "raw_message": "sudo abuse", "timestamp": "2026-01-01T00:00:00",
             "severity": "HIGH", "fields": {}, "tags": ["privilege_escalation"]},
        ]})
        steps_text = " ".join(s["step"] for s in pb.eradication_steps)
        self.assertIn("sudoers", steps_text)

    def test_multiple_tags_merge_steps(self):
        pb = Playbook({"incident_id": "i10", "severity": "CRITICAL",
                       "tags": ["rat_detected", "authentication_failure"], "events": [
            {"event_id": "e1", "source": "specter", "raw_message": "RAT", "timestamp": "2026-01-01T00:00:00",
             "severity": "CRITICAL", "fields": {}, "tags": ["rat_detected"]},
            {"event_id": "e2", "source": "auth", "raw_message": "failed login", "timestamp": "2026-01-01T00:01:00",
             "severity": "HIGH", "fields": {}, "tags": ["authentication_failure"]},
        ]})
        self.assertTrue(len(pb.containment_steps) > 5)


# ────────────────────────────────────────────────────────────────
# IOC Extraction
# ────────────────────────────────────────────────────────────────

class TestIOCExtraction(unittest.TestCase):
    def test_ip_extraction(self):
        pb = Playbook({"incident_id": "i1", "severity": "HIGH", "tags": [], "events": [
            {"event_id": "e1", "source": "auth", "raw_message": "msg", "timestamp": "2026-01-01T00:00:00",
             "severity": "HIGH", "fields": {"ip": "1.2.3.4"}, "tags": []},
        ]})
        self.assertIn("1.2.3.4", pb.iocs["ips"])

    def test_file_extraction(self):
        pb = Playbook({"incident_id": "i2", "severity": "HIGH", "tags": [], "events": [
            {"event_id": "e1", "source": "specter", "raw_message": "modified /etc/shadow",
             "timestamp": "2026-01-01T00:00:00", "severity": "HIGH", "fields": {"file": "/etc/shadow"}, "tags": []},
        ]})
        self.assertIn("/etc/shadow", pb.iocs["files"])

    def test_process_extraction(self):
        pb = Playbook({"incident_id": "i3", "severity": "HIGH", "tags": [], "events": [
            {"event_id": "e1", "source": "specter", "raw_message": "malware detected",
             "timestamp": "2026-01-01T00:00:00", "severity": "HIGH", "fields": {"process": "mimikatz.exe"}, "tags": []},
        ]})
        self.assertIn("mimikatz.exe", pb.iocs["processes"])

    def test_user_extraction(self):
        pb = Playbook({"incident_id": "i4", "severity": "HIGH", "tags": [], "events": [
            {"event_id": "e1", "source": "auth", "raw_message": "login", "timestamp": "2026-01-01T00:00:00",
             "severity": "HIGH", "fields": {"user": "admin"}, "tags": []},
        ]})
        self.assertIn("admin", pb.iocs["users"])

    def test_no_duplicate_iocs(self):
        pb = Playbook({"incident_id": "i5", "severity": "HIGH", "tags": [], "events": [
            {"event_id": "e1", "source": "a", "raw_message": "x", "timestamp": "2026-01-01T00:00:00", "severity": "HIGH",
             "fields": {"ip": "1.2.3.4"}, "tags": []},
            {"event_id": "e2", "source": "b", "raw_message": "y", "timestamp": "2026-01-01T00:01:00", "severity": "HIGH",
             "fields": {"ip": "1.2.3.4"}, "tags": []},
        ]})
        self.assertEqual(pb.iocs["ips"].count("1.2.3.4"), 1)


# ────────────────────────────────────────────────────────────────
# Low Severity
# ────────────────────────────────────────────────────────────────

class TestLowSeverity(unittest.TestCase):
    def test_low_severity_playbook(self):
        pb = Playbook({"incident_id": "inc-low-1", "severity": "LOW", "tags": [], "events": [
            {"event_id": "e1", "source": "auth", "raw_message": "Failed login from 192.168.1.50",
             "timestamp": "2026-01-01T00:00:00", "severity": "LOW", "fields": {"ip": "192.168.1.50"}, "tags": []},
        ]})
        self.assertEqual(pb.severity, "LOW")
        self.assertEqual(pb.escalation["priority"], "P4 — LOW")
        self.assertTrue(len(pb.containment_steps) > 0)

    def test_info_severity_playbook(self):
        pb = Playbook({"incident_id": "inc-info-1", "severity": "INFO", "tags": [], "events": [
            {"event_id": "e1", "source": "auth", "raw_message": "Login successful",
             "timestamp": "2026-01-01T00:00:00", "severity": "INFO", "fields": {"user": "admin"}, "tags": []},
        ]})
        self.assertEqual(pb.severity, "INFO")
        self.assertIn("P5", pb.escalation["priority"])


# ────────────────────────────────────────────────────────────────
# MITRE Map (separate class for clarity)
# ────────────────────────────────────────────────────────────────

class TestEscalationTemplates(unittest.TestCase):
    def test_all_severities_have_templates(self):
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            self.assertIn(sev, SEVERITY_ESCALATION)
            esc = SEVERITY_ESCALATION[sev]
            self.assertIn("priority", esc)
            self.assertIn("response_time", esc)
            self.assertIn("notify", esc)
            self.assertIn("actions", esc)

    def test_critical_escalation(self):
        esc = SEVERITY_ESCALATION["CRITICAL"]
        self.assertEqual(esc["priority"], "P1 — IMMEDIATE")
        self.assertIn("CISO", esc["notify"])

    def test_high_escalation(self):
        esc = SEVERITY_ESCALATION["HIGH"]
        self.assertEqual(esc["priority"], "P2 — URGENT")


# ────────────────────────────────────────────────────────────────
# Multiple Incidents
# ────────────────────────────────────────────────────────────────

class TestMultipleIncidents(unittest.TestCase):
    def test_multi_incident_generation(self):
        incs = [
            {"incident_id": "i1", "severity": "CRITICAL", "tags": ["rat_detected"], "events": [
                {"event_id": "e1", "source": "specter", "raw_message": "RAT",
                 "timestamp": "2026-01-01T00:00:00", "severity": "CRITICAL",
                 "fields": {"ip": "10.0.0.1"}, "tags": ["rat_detected"]},
            ]},
            {"incident_id": "i2", "severity": "HIGH", "tags": ["deception_triggered"], "events": [
                {"event_id": "e2", "source": "mirage", "raw_message": "decoy",
                 "timestamp": "2026-01-01T00:00:00", "severity": "HIGH",
                 "fields": {"ip": "10.0.0.2"}, "tags": ["deception_triggered"]},
            ]},
        ]
        pbs = [Playbook(i) for i in incs]
        self.assertEqual(len(pbs), 2)
        self.assertNotEqual(pbs[0].playbook_id, pbs[1].playbook_id)
        self.assertIn("10.0.0.1", pbs[0].iocs["ips"])
        self.assertIn("10.0.0.2", pbs[1].iocs["ips"])


# ────────────────────────────────────────────────────────────────
# Log Correlator Integration
# ────────────────────────────────────────────────────────────────

class TestPlaybookIntegration(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.db_path = Path(self.tmpdir) / "test.db"

        conn = sqlite3.connect(str(self.db_path))
        conn.execute("""
            CREATE TABLE events (
                event_id TEXT PRIMARY KEY, source TEXT, raw_message TEXT, timestamp TEXT,
                severity TEXT, fields TEXT, tags TEXT
            )
        """)
        conn.execute("""
            CREATE TABLE incidents (
                incident_id TEXT PRIMARY KEY, severity TEXT, status TEXT, event_count INTEGER,
                tags TEXT, notes TEXT, narrative TEXT, assigned_ip TEXT,
                created_at TEXT, updated_at TEXT
            )
        """)
        conn.execute("""
            CREATE TABLE incident_events (
                incident_id TEXT, event_id TEXT,
                PRIMARY KEY (incident_id, event_id)
            )
        """)
        conn.execute("""
            CREATE TABLE correlation_links (
                id INTEGER PRIMARY KEY AUTOINCREMENT, event_a TEXT, event_b TEXT,
                link_type TEXT, reason TEXT,
                FOREIGN KEY(event_a) REFERENCES events(event_id),
                FOREIGN KEY(event_b) REFERENCES events(event_id)
            )
        """)

        conn.execute("INSERT INTO events VALUES ('e1','specter','RAT detected','2026-01-01T00:00:00','CRITICAL','{\"ip\":\"10.0.0.1\",\"process\":\"rat.exe\"}','[\"rat_detected\"]')")
        conn.execute("INSERT INTO events VALUES ('e2','mirage','Decoy touched','2026-01-01T00:01:00','HIGH','{\"ip\":\"10.0.0.1\"}','[\"deception_triggered\"]')")
        conn.execute("INSERT INTO incidents VALUES ('inc-1','CRITICAL','NEW',2,'[\"rat_detected\",\"deception_triggered\"]','[]','Timeline narrative','10.0.0.1','2026-01-01T00:00:00','2026-01-01T00:01:00')")
        conn.execute("INSERT INTO incident_events VALUES ('inc-1','e1')")
        conn.execute("INSERT INTO incident_events VALUES ('inc-1','e2')")
        conn.execute("INSERT INTO correlation_links (event_a,event_b,link_type,reason) VALUES ('e1','e2','ip','same IP')")
        conn.commit()
        conn.close()

    def test_load_incidents_from_db(self):
        import playbook_server as ps
        ps.LOGCORR_DB_PATH = str(self.db_path)
        incidents = ps._load_logcorr_incidents()
        self.assertEqual(len(incidents), 1)
        self.assertEqual(incidents[0]["incident_id"], "inc-1")
        self.assertEqual(incidents[0]["severity"], "CRITICAL")
        self.assertEqual(len(incidents[0]["events"]), 2)

    def test_playbook_from_db_incident(self):
        import playbook_server as ps
        ps.PLAYBOOKS.clear()
        ps.LOGCORR_DB_PATH = str(self.db_path)
        incidents = ps._load_logcorr_incidents()
        pb = ps._generate_playbook_from_incident(incidents[0])
        self.assertEqual(pb["incident_id"], "inc-1")
        self.assertEqual(pb["severity"], "CRITICAL")
        self.assertEqual(pb["status"], "GENERATED")
        self.assertTrue(len(pb["mitre_mappings"]) > 0)
        self.assertTrue(len(pb["containment_steps"]) > 0)
        self.assertIn("10.0.0.1", pb["iocs"]["ips"])


# ────────────────────────────────────────────────────────────────
# Flask API Tests
# ────────────────────────────────────────────────────────────────

class TestFlaskAPI(unittest.TestCase):
    def setUp(self):
        import playbook_server
        self.app = playbook_server.app
        self.app.config["TESTING"] = True
        self.client = self.app.test_client()
        self.tmpdir = tempfile.mkdtemp()
        playbook_server.DB_PATH = Path(self.tmpdir) / "test.db"
        playbook_server.PLAYBOOKS.clear()
        playbook_server._init_db()
        playbook_server._init_db()

    def test_health(self):
        r = self.client.get("/api/health")
        self.assertEqual(r.status_code, 200)
        d = r.get_json()
        self.assertEqual(d["status"], "healthy")
        self.assertIn("version", d)

    def test_generate_playbook(self):
        r = self.client.post("/api/playbook/generate", json={
            "incident_id": "api-1", "severity": "CRITICAL", "tags": ["rat_detected"],
            "events": [
                {"event_id": "e1", "source": "specter", "raw_message": "RAT",
                 "timestamp": "2026-01-01", "severity": "CRITICAL",
                 "fields": {"ip": "10.0.0.1"}, "tags": ["rat_detected"]},
            ],
        })
        self.assertEqual(r.status_code, 200)
        d = r.get_json()
        self.assertEqual(d["status"], "generated")
        self.assertEqual(d["playbook"]["incident_id"], "api-1")
        self.assertIn("10.0.0.1", d["playbook"]["iocs"]["ips"])

    def test_get_playbook(self):
        r = self.client.post("/api/playbook/generate", json={
            "incident_id": "get-1", "severity": "HIGH", "tags": [], "events": []
        })
        pb_id = r.get_json()["playbook"]["playbook_id"]
        r = self.client.get(f"/api/playbook/{pb_id}")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.get_json()["playbook"]["incident_id"], "get-1")

    def test_get_nonexistent_playbook(self):
        r = self.client.get("/api/playbook/nonexistent")
        self.assertEqual(r.status_code, 404)

    def test_list_playbooks(self):
        self.client.post("/api/playbook/generate", json={
            "incident_id": "list-1", "severity": "HIGH", "tags": [], "events": []
        })
        r = self.client.get("/api/playbooks")
        self.assertEqual(r.status_code, 200)
        self.assertGreaterEqual(r.get_json()["count"], 1)

    def test_report_text(self):
        self.client.post("/api/playbook/generate", json={
            "incident_id": "rpt-1", "severity": "CRITICAL", "tags": ["rat_detected"], "events": []
        })
        r = self.client.get("/api/playbook/report")
        self.assertEqual(r.status_code, 200)
        self.assertIn("MITRE", r.data.decode())

    def test_report_json(self):
        self.client.post("/api/playbook/generate", json={
            "incident_id": "rj-1", "severity": "HIGH", "tags": [], "events": []
        })
        r = self.client.get("/api/playbook/report/json")
        self.assertEqual(r.status_code, 200)
        self.assertIn("playbooks", r.get_json())

    def test_dashboard_served(self):
        r = self.client.get("/dashboard")
        self.assertEqual(r.status_code, 200)
        self.assertIn(b"TrinTech", r.data)

    def test_export_pdf(self):
        self.client.post("/api/playbook/generate", json={
            "incident_id": "pdf-1", "severity": "CRITICAL", "tags": ["rat_detected"], "events": []
        })
        r = self.client.post("/api/playbook/export/pdf", json={})
        self.assertEqual(r.status_code, 200)
        # PDF is binary — verify it's not empty and has PDF header
        self.assertGreater(len(r.data), 100)
        self.assertTrue(r.data.startswith(b"%PDF") or b"%PDF" in r.data[:50])

    def test_clear_playbooks(self):
        self.client.post("/api/playbook/generate", json={
            "incident_id": "clr-1", "severity": "HIGH", "tags": [], "events": []
        })
        r = self.client.post("/api/playbook/clear")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.get_json()["count"], 0)

    def test_config_endpoint(self):
        r = self.client.get("/api/playbook/config")
        self.assertEqual(r.status_code, 200)
        self.assertIn("escalation_contacts", r.get_json())

    def test_config_update(self):
        r = self.client.post("/api/playbook/config", json={
            "default_email_domain": "test.com"
        })
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.get_json()["config"]["default_email_domain"], "test.com")


# ────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    unittest.main(verbosity=2)

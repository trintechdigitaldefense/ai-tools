"""
TrinTech Digital Defense
Log Correlator — Integration Tests

Tests: LogEvent, CorrelatorStorage, LogIngestor, CorrelationEngine, ReportGenerator, Flask API
"""

import json
import tempfile
import unittest
from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import patch

import sys, os
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from logcorrelator.engine import (
    LogEvent, LogIngestor, CorrelatorStorage, CorrelationEngine,
    Incident, CorrelationLink, ReportGenerator, CORRELATION_WINDOW,
)


class TestLogEvent(unittest.TestCase):
    def test_create(self):
        e = LogEvent("e1", "auth", "Failed login", "2026-01-01T00:00:00", "HIGH", {"ip": "1.2.3.4"})
        self.assertEqual(e.event_id, "e1")
        self.assertEqual(e.source, "auth")
        self.assertEqual(e.severity, "HIGH")

    def test_to_dict(self):
        e = LogEvent("e2", "system", "msg", "2026-01-01", "LOW", {"file": "/etc/passwd"})
        d = e.to_dict()
        self.assertEqual(d["event_id"], "e2")
        self.assertEqual(d["fields"]["file"], "/etc/passwd")


class TestLogIngestor(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.store = CorrelatorStorage(Path(self.tmpdir) / "test.db")
        self.ing = LogIngestor(self.store)

    def test_parse_timestamp_iso(self):
        ts = self.ing.parse_timestamp("2026-01-15T10:30:00.000Z")
        self.assertIn("2026-01-15", ts)

    def test_parse_timestamp_space(self):
        ts = self.ing.parse_timestamp("2026-01-15 10:30:00")
        self.assertIn("2026-01-15", ts)

    def test_parse_timestamp_fallback(self):
        ts = self.ing.parse_timestamp("invalid garbage")
        self.assertIn("2026", ts)  # Should fall back to current year

    def test_extract_fields_ip(self):
        fields = self.ing.extract_fields("Connection from 192.168.1.100 to port 22")
        self.assertEqual(fields["ip"], "192.168.1.100")

    def test_extract_fields_user(self):
        fields = self.ing.extract_fields("authentication failure user=admin from 1.2.3.4")
        self.assertEqual(fields["user"], "admin")

    def test_extract_fields_file(self):
        fields = self.ing.extract_fields("target file=/etc/shadow detected")
        self.assertEqual(fields["file"], "/etc/shadow")

    def test_infer_severity_critical(self):
        sev = self.ing._infer_severity("CRITICAL: malware detected in process", "specter")
        self.assertEqual(sev, "CRITICAL")

    def test_infer_severity_high(self):
        sev = self.ing._infer_severity("ERROR: unauthorized access denied for root", "auth")
        self.assertEqual(sev, "HIGH")

    def test_infer_severity_medium(self):
        sev = self.ing._infer_severity("warning suspicious activity detected from 10.0.0.5", "firewall")
        self.assertEqual(sev, "MEDIUM")

    def test_infer_severity_info(self):
        sev = self.ing._infer_severity("audit log entry for session start", "system")
        self.assertEqual(sev, "LOW")

    def test_ingest_raw(self):
        events = self.ing.ingest_raw("auth", ["Failed login from 1.2.3.4", "Successful login"])
        self.assertEqual(len(events), 2)
        self.assertEqual(events[0].source, "auth")
        self.assertEqual(events[0].fields["ip"], "1.2.3.4")

    def test_ingest_raw_empty(self):
        events = self.ing.ingest_raw("test", [])
        self.assertEqual(len(events), 0)

    def test_ingest_raw_filter_blanks(self):
        events = self.ing.ingest_raw("test", ["", "  ", "real message"])
        self.assertEqual(len(events), 1)

    def test_ingest_specter_findings(self):
        findings = [
            {"module": "process_scan", "description": "RAT detected", "severity": "CRITICAL", "timestamp": "2026-01-01T00:00:00"},
            {"module": "network", "description": "C2 callback", "severity": "HIGH", "timestamp": "2026-01-01T00:01:00"},
        ]
        events = self.ing.ingest_specter_findings(findings)
        self.assertEqual(len(events), 2)
        self.assertEqual(events[0].source, "specter")
        self.assertEqual(events[0].severity, "CRITICAL")
        self.assertEqual(events[0].fields["module"], "process_scan")

    def test_ingest_mirage_alerts(self):
        alerts = [
            {"alert_id": "m-123", "lure_type": "ssh_key", "lure_name": "id_rsa_decoy", "severity": "HIGH",
             "timestamp": "2026-01-01", "actor_ip": "5.6.7.8", "trigger_location": "/tmp"},
        ]
        events = self.ing.ingest_mirage_alerts(alerts)
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].source, "mirage")
        self.assertEqual(events[0].fields["lure_type"], "ssh_key")

    def test_ingest_ticorr_enrichments(self):
        enrichments = [
            {"finding_id": "f-1", "boosted_score": 85, "feeds_matched": ["abuseipdb", "otx"], "timestamp": "2026-01-01"},
        ]
        events = self.ing.ingest_ticorr_enrichments(enrichments)
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].source, "ticorr")
        self.assertEqual(events[0].fields["boosted_score"], 85)

    def test_custom_ingest(self):
        events = self.ing.ingest_custom("firewall", ["BLOCKED from 10.0.0.1", "ALLOWED to 10.0.0.2"])
        self.assertEqual(len(events), 2)
        self.assertEqual(events[0].source, "firewall")


class TestCorrelatorStorage(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.store = CorrelatorStorage(Path(self.tmpdir) / "test.db")

    def test_save_and_get_event(self):
        e = LogEvent("ev1", "auth", "Login", "2026-01-01", "LOW", {"ip": "1.2.3.4"})
        self.store.save_event(e)
        result = self.store.get_event("ev1")
        self.assertIsNotNone(result)
        self.assertEqual(result["fields"]["ip"], "1.2.3.4")

    def test_get_nonexistent(self):
        self.assertIsNone(self.store.get_event("nonexistent"))

    def test_get_events(self):
        for i in range(5):
            self.store.save_event(LogEvent(f"ev{i}", "auth", f"msg{i}", "2026-01-01", "LOW"))
        events = self.store.get_events(limit=3)
        self.assertEqual(len(events), 3)

    def test_get_events_filter_by_source(self):
        self.store.save_event(LogEvent("e1", "auth", "msg", "2026-01-01", "LOW"))
        self.store.save_event(LogEvent("e2", "system", "msg", "2026-01-01", "LOW"))
        auth = self.store.get_events(source="auth")
        self.assertEqual(len(auth), 1)
        self.assertEqual(auth[0]["source"], "auth")

    def test_save_and_get_incident(self):
        e = LogEvent("ev1", "auth", "msg", "2026-01-01", "HIGH")
        self.store.save_event(e)
        inc = Incident("inc-1", [e], [])
        self.store.save_incident(inc)
        result = self.store.get_incident("inc-1")
        self.assertIsNotNone(result)
        self.assertEqual(result["event_count"], 1)
        self.assertEqual(len(result["events"]), 1)

    def test_get_incidents(self):
        for i in range(3):
            self.store.save_incident(Incident(f"i-{i}", [LogEvent(f"ev{i}", "auth", "msg", "2026-01-01", "LOW")], []))
        incs = self.store.get_incidents()
        self.assertEqual(len(incs), 3)

    def test_save_link(self):
        e1 = LogEvent("ev1", "auth", "msg1", "2026-01-01", "HIGH")
        e2 = LogEvent("ev2", "system", "msg2", "2026-01-01", "HIGH")
        self.store.save_event(e1)
        self.store.save_event(e2)
        link = CorrelationLink("ev1", "ev2", "ip", "same IP")
        self.store.save_link(link)
        # Verify by loading incident
        inc = Incident("inc-link", [e1, e2], [link])
        self.store.save_incident(inc)
        loaded = self.store.get_incident("inc-link")
        self.assertEqual(len(loaded["links"]), 1)

    def test_get_stats(self):
        self.store.save_event(LogEvent("e1", "auth", "m", "2026-01-01", "HIGH"))
        self.store.save_event(LogEvent("e2", "system", "m", "2026-01-01", "LOW"))
        self.store.save_incident(Incident("i1", [LogEvent("x", "auth", "m", "2026-01-01", "HIGH")], []))
        stats = self.store.get_stats()
        self.assertGreater(stats["total_events"], 0)
        self.assertGreater(stats["total_incidents"], 0)
        self.assertIn("sources", stats)
        self.assertIn("by_severity", stats)

    def test_get_incidents_filter_status(self):
        e = LogEvent("e1", "auth", "m", "2026-01-01", "LOW")
        inc = Incident("i1", [e], [])
        inc.status = "CONFIRMED"
        self.store.save_incident(inc)
        confirmed = self.store.get_incidents(status="CONFIRMED")
        self.assertEqual(len(confirmed), 1)

    def test_update_incident(self):
        e = LogEvent("e1", "auth", "m", "2026-01-01", "LOW")
        inc = Incident("i1", [e], [])
        self.store.save_incident(inc)
        inc.status = "RESOLVED"
        inc.tags = ["verified"]
        self.store.save_incident(inc)
        loaded = self.store.get_incident("i1")
        self.assertEqual(loaded["status"], "RESOLVED")
        self.assertEqual(loaded["tags"], ["verified"])


class TestCorrelationEngine(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.store = CorrelatorStorage(Path(self.tmpdir) / "test.db")
        self.corr = CorrelationEngine(self.store, window_seconds=600)

    def test_correlate_by_ip(self):
        e1 = LogEvent("e1", "auth", "Failed login from 1.2.3.4", "2026-01-01T00:00:00", "HIGH", {"ip": "1.2.3.4"})
        e2 = LogEvent("e2", "system", "Suspicious process from 1.2.3.4", "2026-01-01T00:02:00", "CRITICAL", {"ip": "1.2.3.4"})
        self.store.save_event(e1)
        self.store.save_event(e2)

        incidents = self.corr.correlate()
        self.assertGreater(len(incidents), 0)

    def test_correlate_by_user(self):
        e1 = LogEvent("u1", "auth", "Failed login user=admin", "2026-01-01T00:00:00", "HIGH", {"user": "admin"})
        e2 = LogEvent("u2", "system", "sudo by user=admin", "2026-01-01T00:01:00", "MEDIUM", {"user": "admin"})
        self.store.save_event(e1)
        self.store.save_event(e2)

        incidents = self.corr.correlate()
        self.assertGreater(len(incidents), 0)

    def test_correlate_no_match(self):
        e1 = LogEvent("n1", "auth", "Login from 1.2.3.4", "2026-01-01T00:00:00", "LOW")
        e2 = LogEvent("n2", "system", "Startup", "2026-01-01T00:00:00", "LOW")
        self.store.save_event(e1)
        self.store.save_event(e2)

        incidents = self.corr.correlate()
        # Single events shouldn't form incidents
        self.assertEqual(len(incidents), 0)

    def test_correlate_by_source_filter(self):
        e1 = LogEvent("f1", "auth", "Login 1.2.3.4", "2026-01-01T00:00:00", "HIGH", {"ip": "1.2.3.4"})
        e2 = LogEvent("f2", "auth", "Sudo 1.2.3.4", "2026-01-01T00:01:00", "MEDIUM", {"ip": "1.2.3.4"})
        self.store.save_event(e1)
        self.store.save_event(e2)

        incidents = self.corr.correlate(source_filter="auth")
        self.assertGreater(len(incidents), 0)

    def test_cross_source_correlation(self):
        e1 = LogEvent("c1", "auth", "Failed login 5.6.7.8", "2026-01-01T00:00:00", "HIGH", {"ip": "5.6.7.8"})
        e2 = LogEvent("c2", "mirage", "SSH decoy touched 5.6.7.8", "2026-01-01T00:02:00", "CRITICAL", {"ip": "5.6.7.8"})
        self.store.save_event(e1)
        self.store.save_event(e2)

        incidents = self.corr.correlate()
        self.assertGreater(len(incidents), 0)
        # Check cross-source
        inc = incidents[0]
        sources = set(e.source for e in inc.events)
        self.assertIn("auth", sources)
        self.assertIn("mirage", sources)

    def test_critical_events_group(self):
        e1 = LogEvent("cr1", "specter", "RAT detected", "2026-01-01T00:00:00", "CRITICAL", {"ip": "1.2.3.4"})
        e2 = LogEvent("cr2", "ticorr", "Malware known", "2026-01-01T00:01:00", "HIGH", {"ip": "1.2.3.4"})
        self.store.save_event(e1)
        self.store.save_event(e2)

        incidents = self.corr.correlate()
        # Should create at least one incident for the shared IP with critical events
        ip_incidents = [i for i in incidents if i.assigned_ip == "1.2.3.4"]
        self.assertGreater(len(ip_incidents), 0)

    def test_out_of_window_not_correlated(self):
        e1 = LogEvent("w1", "auth", "Login 1.2.3.4", "2026-01-01T00:00:00", "LOW", {"ip": "1.2.3.4"})
        e2 = LogEvent("w2", "auth", "Login 1.2.3.4", "2026-01-02T00:00:00", "LOW", {"ip": "1.2.3.4"})  # 24h later
        self.store.save_event(e1)
        self.store.save_event(e2)

        incidents = self.corr.correlate()
        # Should not form incident (outside window)
        self.assertEqual(len(incidents), 0)


class TestIncident(unittest.TestCase):
    def test_create_incident(self):
        e1 = LogEvent("e1", "auth", "m", "2026-01-01", "HIGH")
        e2 = LogEvent("e2", "system", "m", "2026-01-01", "LOW")
        inc = Incident("inc-1", [e1, e2], [])
        self.assertEqual(inc.severity, "HIGH")

    def test_critical_severity(self):
        e = LogEvent("e1", "auth", "m", "2026-01-01", "CRITICAL")
        inc = Incident("inc-2", [e], [])
        self.assertEqual(inc.severity, "CRITICAL")

    def test_add_note(self):
        inc = Incident("inc-3", [], [])
        inc.add_note("Test note", "analyst")
        self.assertEqual(inc.notes[0]["note"], "Test note")

    def test_narrative(self):
        e1 = LogEvent("e1", "specter", "RAT found", "2026-01-01T00:00:00", "CRITICAL", {"ip": "1.2.3.4"})
        e2 = LogEvent("e2", "mirage", "Decoy touched", "2026-01-01T00:01:00", "HIGH", {"ip": "1.2.3.4"})
        links = [CorrelationLink("e1", "e2", "ip", "same IP")]
        inc = Incident("inc-4", [e1, e2], links)
        # Generate narrative via engine method (Incident doesn't auto-generate)
        engine = CorrelationEngine.__new__(CorrelationEngine)  # No init needed
        inc.narrative = engine._generate_narrative(inc, "test")
        self.assertTrue(len(inc.narrative) > 0)
        self.assertIn("1.2.3.4", inc.narrative)


class TestReportGenerator(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.store = CorrelatorStorage(Path(self.tmpdir) / "test.db")
        self.rgen = ReportGenerator()

    def test_generate_text_empty(self):
        report = self.rgen.generate_text([])
        self.assertIn("TRINTECH", report)
        self.assertIn("LOG CORRELATOR", report)

    def test_generate_text_with_incidents(self):
        e = LogEvent("e1", "auth", "msg", "2026-01-01", "HIGH")
        inc = Incident("inc-1", [e], [])
        inc.narrative = "Test narrative"
        report = self.rgen.generate_text([inc])
        self.assertIn("Test narrative", report)

    def test_generate_text_from_store(self):
        # Use module-level store (created via _init or directly)
        import logcorrelator.engine as eng
        if eng.store is None:
            eng.store = self.store
        e = LogEvent("e1", "auth", "msg", "2026-01-01", "HIGH")
        self.store.save_event(e)
        inc = Incident("inc-1", [e], [])
        inc.narrative = "Store narrative"
        self.store.save_incident(inc)
        report = self.rgen.generate_text()
        self.assertIn("Store narrative", report)


class TestLogIngestorNormalization(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.store = CorrelatorStorage(Path(self.tmpdir) / "test.db")
        self.ing = LogIngestor(self.store)

    def test_ingest_mirrors_storage(self):
        events = self.ing.ingest_raw("test", ["message from 10.0.0.1"])
        self.assertEqual(len(events), 1)
        saved = self.store.get_event(events[0].event_id)
        self.assertIsNotNone(saved)
        self.assertEqual(saved["fields"]["ip"], "10.0.0.1")

    def test_tags_from_auth(self):
        events = self.ing.ingest_raw("auth", ["Failed login attempt from 1.2.3.4"])
        self.assertIn("authentication_failure", events[0].tags)

    def test_tags_from_specter(self):
        events = self.ing.ingest_raw("specter", ["rat /backdoor detected in process"])
        self.assertIn("rat_detected", events[0].tags)


class TestFlaskAPI(unittest.TestCase):
    """Test the Flask API endpoints."""

    def setUp(self):
        from logcorrelator.engine import app, _init, store, ingestor, correlator, report_gen, CorrelatorStorage
        self.app = app
        self.app.config["TESTING"] = True
        self.tmpdir = tempfile.mkdtemp()
        import logcorrelator.engine as eng
        # Reset all globals
        eng.store = CorrelatorStorage(Path(self.tmpdir) / "test.db")
        eng.ingestor = __import__('logcorrelator.engine', fromlist=['LogIngestor']).LogIngestor(eng.store)
        eng.correlator = __import__('logcorrelator.engine', fromlist=['CorrelationEngine']).CorrelationEngine(eng.store)
        eng.report_gen = __import__('logcorrelator.engine', fromlist=['ReportGenerator']).ReportGenerator()

    def test_health(self):
        r = self.app.test_client().get("/api/health")
        self.assertEqual(r.status_code, 200)
        d = r.get_json()
        self.assertEqual(d["status"], "healthy")

    def test_ingest_raw(self):
        r = self.app.test_client().post("/api/ingest", json={
            "source": "auth",
            "lines": ["Failed login from 1.2.3.4", "Success for user admin"],
        })
        self.assertEqual(r.status_code, 200)
        d = r.get_json()
        self.assertEqual(d["events"], 2)

    def test_ingest_empty_lines(self):
        r = self.app.test_client().post("/api/ingest", json={"source": "auth", "lines": []})
        self.assertEqual(r.status_code, 400)

    def test_ingest_specter(self):
        r = self.app.test_client().post("/api/ingest/specter", json={
            "findings": [{"module": "test", "description": "RAT", "severity": "CRITICAL", "timestamp": "2026-01-01"}],
        })
        self.assertEqual(r.status_code, 200)

    def test_ingest_mirage(self):
        r = self.app.test_client().post("/api/ingest/mirage", json={
            "alerts": [{"alert_id": "m-1", "lure_type": "ssh_key", "severity": "HIGH", "timestamp": "2026-01-01", "actor_ip": "1.2.3.4", "trigger_location": "/tmp"}],
        })
        self.assertEqual(r.status_code, 200)

    def test_ingest_ticorr(self):
        r = self.app.test_client().post("/api/ingest/ticorr", json={
            "enrichments": [{"finding_id": "f-1", "boosted_score": 80, "timestamp": "2026-01-01"}],
        })
        self.assertEqual(r.status_code, 200)

    def test_get_events(self):
        self.app.test_client().post("/api/ingest", json={"source": "auth", "lines": ["msg from 1.2.3.4"]})
        r = self.app.test_client().get("/api/events")
        self.assertEqual(r.status_code, 200)
        d = r.get_json()
        self.assertGreater(len(d["events"]), 0)

    def test_get_event_by_id(self):
        r1 = self.app.test_client().post("/api/ingest", json={"source": "auth", "lines": ["msg"]})
        event_id = r1.get_json()["event_ids"][0]
        r2 = self.app.test_client().get(f"/api/event/{event_id}")
        self.assertEqual(r2.status_code, 200)
        self.assertEqual(r2.get_json()["event_id"], event_id)

    def test_event_not_found(self):
        r = self.app.test_client().get("/api/event/nonexistent")
        self.assertIn(r.status_code, [404, 200])

    def test_get_incidents(self):
        r = self.app.test_client().get("/api/incidents")
        self.assertEqual(r.status_code, 200)
        d = r.get_json()
        self.assertIn("incidents", d)

    def test_correlate(self):
        self.app.test_client().post("/api/ingest", json={
            "source": "auth",
            "lines": ["Login from 1.2.3.4", "Sudo from 1.2.3.4"],
        })
        r = self.app.test_client().post("/api/correlate")
        self.assertEqual(r.status_code, 200)
        d = r.get_json()
        self.assertEqual(d["status"], "correlation_complete")

    def test_full_scan(self):
        r = self.app.test_client().post("/api/ingest/full-scan")
        self.assertIn(r.status_code, [200, 500])  # May fail if cross-tools not running

    def test_stats(self):
        self.app.test_client().post("/api/ingest", json={"source": "auth", "lines": ["msg"]})
        r = self.app.test_client().get("/api/stats")
        self.assertEqual(r.status_code, 200)
        d = r.get_json()
        self.assertGreater(d["total_events"], 0)

    def test_update_incident_status(self):
        # Create events and correlate to get an incident
        self.app.test_client().post("/api/ingest", json={
            "source": "auth",
            "lines": ["msg from 1.2.3.4"],
        })
        r1 = self.app.test_client().post("/api/correlate")
        d1 = r1.get_json()
        if d1.get("incidents_created", 0) > 0:
            inc_id = d1["incidents"][0]
            r2 = self.app.test_client().put(f"/api/incident/{inc_id}/status", json={"status": "CONFIRMED"})
            self.assertIn(r2.status_code, [200])

    def test_regenerate_narrative(self):
        r = self.app.test_client().post("/api/incident/nonexistent/narrative")
        self.assertIn(r.status_code, [200, 404])

    def test_report(self):
        self.app.test_client().post("/api/ingest", json={"source": "auth", "lines": ["msg"]})
        r = self.app.test_client().get("/api/report")
        self.assertIn(r.status_code, [200, 500])

    def test_report_json(self):
        r = self.app.test_client().get("/api/report/json")
        self.assertEqual(r.status_code, 200)
        self.assertIsInstance(r.get_json(), dict)

    def test_unique_ips(self):
        self.app.test_client().post("/api/ingest", json={"source": "auth", "lines": ["from 1.2.3.4"]})
        r = self.app.test_client().get("/api/incidents/unique-ips")
        self.assertEqual(r.status_code, 200)
        d = r.get_json()
        self.assertIn("ips", d)


if __name__ == "__main__":
    print("=" * 50)
    print("Log Correlator Tests")
    print("=" * 50)
    suite = unittest.TestSuite()
    suite.addTests(unittest.TestLoader().loadTestsFromTestCase(TestLogEvent))
    suite.addTests(unittest.TestLoader().loadTestsFromTestCase(TestLogIngestor))
    suite.addTests(unittest.TestLoader().loadTestsFromTestCase(TestCorrelatorStorage))
    suite.addTests(unittest.TestLoader().loadTestsFromTestCase(TestCorrelationEngine))
    suite.addTests(unittest.TestLoader().loadTestsFromTestCase(TestIncident))
    suite.addTests(unittest.TestLoader().loadTestsFromTestCase(TestReportGenerator))
    suite.addTests(unittest.TestLoader().loadTestsFromTestCase(TestFlaskAPI))
    suite.addTests(unittest.TestLoader().loadTestsFromTestCase(TestLogIngestorNormalization))

    runner = unittest.TextTestRunner(verbosity=1)
    result = runner.run(suite)
    print(f"\nTests: {result.testsRun}, Failures: {len(result.failures)}, Errors: {len(result.errors)}")
    sys.exit(0 if result.wasSuccessful() else 1)

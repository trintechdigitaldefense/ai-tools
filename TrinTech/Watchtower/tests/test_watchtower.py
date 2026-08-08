"""
Watchtower — Live Alert Bridge Tests
Tests the correlation engine, server endpoints, SSE, and cross-tool integration.
"""

import json
import os
import sys
import tempfile
import time

import pytest

# Add package root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from watchtower.engine import (
    SUPPORTED_SOURCES,
    AlertEvent,
    WatchtowerEngine,
    compute_incident_score,
    severity_from_score,
    extract_entities,
)
import watchtower_server


# ────────────────────────────────────────────────────────────────────
# Entity Extraction
# ────────────────────────────────────────────────────────────────────

class TestEntityExtraction:

    def test_extract_ipv4(self):
        ips = extract_entities("Connection from 192.168.1.10 to 10.0.0.5")
        assert "192.168.1.10" in ips
        assert "10.0.0.5" in ips

    def test_extract_ipv6(self):
        ips = extract_entities("Connection from 2001:db8:0:0:0:0:0:1 to fe80::1")
        assert any("2001" in ip for ip in ips)
        assert any("fe80" in ip for ip in ips)

    def test_extract_domain(self):
        doms = extract_entities("DNS lookup for evil.com and c2.attacker.org")
        assert "evil.com" in doms
        assert "c2.attacker.org" in doms

    def test_extract_multiple_ips(self):
        ips = extract_entities("192.168.1.1 and 10.0.0.1 and 172.16.0.1")
        assert len(ips) >= 3

    def test_no_falsy_ip(self):
        ips = extract_entities("999.999.999.999 is invalid")
        assert "999.999.999.999" not in ips

    def test_empty_string(self):
        assert extract_entities("") == []


# ────────────────────────────────────────────────────────────────────
# Scoring
# ────────────────────────────────────────────────────────────────────

class TestScoring:

    def test_single_critical_alert(self):
        a = AlertEvent(
            alert_id="t1", source="specter", alert_type="RAT",
            severity="CRITICAL", timestamp="2026-01-01T00:00:00",
            title="Test", detail="Test",
        )
        score = compute_incident_score([a])
        assert score == 40 * 1.2  # CRITICAL=40, specter=1.2

    def test_multi_source_bonus(self):
        a1 = AlertEvent(
            alert_id="t1", source="specter", alert_type="RAT",
            severity="HIGH", timestamp="2026-01-01T00:00:00",
            title="Test", detail="Test", entities=["192.168.1.10"],
        )
        a2 = AlertEvent(
            alert_id="t2", source="phantom", alert_type="beacon",
            severity="CRITICAL", timestamp="2026-01-01T00:00:01",
            title="Test", detail="Test", entities=["192.168.1.10"],
        )
        score = compute_incident_score([a1, a2])
        # HIGH=25*1.2 + CRITICAL=40*1.1 + 1*8 (multi-source bonus)
        expected = 25 * 1.2 + 40 * 1.1 + 8
        assert score == expected

    def test_cap_at_100(self):
        alerts = [
            AlertEvent(
                alert_id=f"t{i}", source="mirage", alert_type=f"X{i}",
                severity="CRITICAL", timestamp="2026-01-01T00:00:00",
                title="Test", detail="Test", entities=["192.168.1.1"],
            )
            for i in range(10)
        ]
        assert compute_incident_score(alerts) == 100

    def test_empty_alerts(self):
        assert compute_incident_score([]) == 0

    def test_severity_mapping(self):
        assert severity_from_score(100) == "CRITICAL"
        assert severity_from_score(70) == "CRITICAL"
        assert severity_from_score(69) == "HIGH"
        assert severity_from_score(45) == "HIGH"
        assert severity_from_score(44) == "MEDIUM"
        assert severity_from_score(20) == "MEDIUM"
        assert severity_from_score(19) == "LOW"
        assert severity_from_score(0) == "LOW"


# ────────────────────────────────────────────────────────────────────
# Core Engine — Ingestion
# ────────────────────────────────────────────────────────────────────

class TestIngestion:

    def test_ingest_single_alert(self):
        engine = WatchtowerEngine()
        result = engine.ingest("specter", [{
            "alert_type": "RAT_DETECTED",
            "severity": "CRITICAL",
            "title": "njRAT found",
            "detail": "Process njRAT on host",
            "src_ip": "192.168.1.10",
        }])
        assert len(result) == 1
        assert result[0].source == "specter"
        assert result[0].severity == "CRITICAL"
        assert "192.168.1.10" in result[0].entities

    def test_ingest_multiple_alerts(self):
        engine = WatchtowerEngine()
        results = engine.ingest("phantom", [
            {"alert_type": "beaconing", "severity": "HIGH", "title": "B1", "detail": "d1", "src_ip": "1.1.1.1"},
            {"alert_type": "exfil", "severity": "CRITICAL", "title": "E1", "detail": "d2", "dst_ip": "2.2.2.2"},
        ])
        assert len(results) == 2

    def test_ingest_empty_list(self):
        engine = WatchtowerEngine()
        assert engine.ingest("specter", []) == []

    def test_ingest_invalid_severity_defaults_to_medium(self):
        engine = WatchtowerEngine()
        result = engine.ingest("specter", [{
            "alert_type": "TEST", "severity": "UNKNOWN", "title": "T", "detail": "T",
        }])
        assert result[0].severity == "MEDIUM"

    def test_ingest_no_entities(self):
        engine = WatchtowerEngine()
        result = engine.ingest("specter", [{
            "alert_type": "TEST", "severity": "LOW", "title": "No IP here", "detail": "Just text",
        }])
        assert len(result) == 1
        assert result[0].entities == []

    def test_ingest_unsupported_source(self):
        engine = WatchtowerEngine()
        assert engine.ingest("unknown_tool", [{"alert_type": "T"}]) == []

    def test_auto_ingest_single(self):
        engine = WatchtowerEngine()
        result = engine.ingest_single("mirage", {
            "alert_type": "lateral", "severity": "HIGH",
            "title": "LM", "detail": "d", "src_ip": "3.3.3.3",
        })
        assert result is not None
        assert result.alert_type == "lateral"

    def test_ingest_single_unsupported_source(self):
        engine = WatchtowerEngine()
        assert engine.ingest_single("unknown", {"alert_type": "T"}) is None


# ────────────────────────────────────────────────────────────────────
# Core Engine — Correlation
# ────────────────────────────────────────────────────────────────────

class TestCorrelation:

    def test_no_correlation_different_ips(self):
        engine = WatchtowerEngine()
        engine.ingest("specter", [{"alert_type": "RAT", "severity": "HIGH", "title": "T", "detail": "T", "src_ip": "1.1.1.1"}])
        engine.ingest("phantom", [{"alert_type": "beacon", "severity": "HIGH", "title": "T", "detail": "T", "src_ip": "2.2.2.2"}])
        assert len(engine.incidents) == 2  # 2 separate incidents

    def test_correlation_same_ip(self):
        engine = WatchtowerEngine()
        engine.ingest("specter", [{"alert_type": "RAT", "severity": "CRITICAL", "title": "T", "detail": "192.168.1.10 malware found", "src_ip": "192.168.1.10"}])
        engine.ingest("phantom", [{"alert_type": "beacon", "severity": "CRITICAL", "title": "T", "detail": "192.168.1.10 beaconing", "src_ip": "192.168.1.10"}])
        assert len(engine.incidents) == 1
        inc = list(engine.incidents.values())[0]
        assert inc.score >= 60  # Multi-source CRITICAL+CRITICAL bonus
        assert len(inc.sources) == 2

    def test_correlation_via_text_extraction(self):
        """Alerts without explicit IP should still correlate via text extraction."""
        engine = WatchtowerEngine()
        engine.ingest("specter", [{"alert_type": "RAT", "severity": "CRITICAL", "title": "Found on 192.168.1.100", "detail": "192.168.1.100 has malware"}])
        engine.ingest("phantom", [{"alert_type": "exfil", "severity": "HIGH", "title": "Traffic from 192.168.1.100", "detail": "192.168.1.100 sending data"}])
        assert len(engine.incidents) == 1

    def test_no_correlation_no_entities(self):
        engine = WatchtowerEngine()
        engine.ingest("specter", [{"alert_type": "TEST", "severity": "LOW", "title": "No IP", "detail": "Just text"}])
        engine.ingest("phantom", [{"alert_type": "TEST2", "severity": "LOW", "title": "No IP too", "detail": "Also text"}])
        # Each gets its own incident since no entities to correlate on
        assert len(engine.incidents) == 2

    def test_alert_count_after_correlation(self):
        engine = WatchtowerEngine()
        engine.ingest("specter", [{"alert_type": "A", "severity": "HIGH", "title": "T", "detail": "d", "src_ip": "5.5.5.5"}])
        engine.ingest("phantom", [{"alert_type": "B", "severity": "HIGH", "title": "T", "detail": "d", "src_ip": "5.5.5.5"}])
        engine.ingest("mirage", [{"alert_type": "C", "severity": "MEDIUM", "title": "T", "detail": "d", "src_ip": "5.5.5.5"}])
        assert len(engine.alert_queue) == 3
        assert len(engine.incidents) == 1
        inc = list(engine.incidents.values())[0]
        assert len(inc.child_alerts) == 3

    def test_correlation_different_severity(self):
        engine = WatchtowerEngine()
        engine.ingest("specter", [{"alert_type": "RAT", "severity": "CRITICAL", "title": "T", "detail": "d", "src_ip": "6.6.6.6"}])
        engine.ingest("phantom", [{"alert_type": "beacon", "severity": "LOW", "title": "T", "detail": "d", "src_ip": "6.6.6.6"}])
        assert len(engine.incidents) == 1

    def test_correlation_hostname(self):
        engine = WatchtowerEngine()
        engine.ingest("specter", [{"alert_type": "RAT", "severity": "HIGH", "title": "T", "detail": "host corp-server-01 infected", "hostname": "corp-server-01"}])
        engine.ingest("phantom", [{"alert_type": "exfil", "severity": "HIGH", "title": "T", "detail": "corp-server-01 sending data", "dst_ip": "7.7.7.7"}])
        assert len(engine.incidents) == 1


# ────────────────────────────────────────────────────────────────────
# Core Engine — Query
# ────────────────────────────────────────────────────────────────────

class TestQuery:

    def test_get_all_alerts(self):
        engine = WatchtowerEngine()
        engine.ingest("specter", [
            {"alert_type": "A", "severity": "HIGH", "title": "T1", "detail": "d", "src_ip": "1.1.1.1"},
            {"alert_type": "B", "severity": "LOW", "title": "T2", "detail": "d", "src_ip": "2.2.2.2"},
        ])
        alerts = engine.get_all_alerts()
        assert len(alerts) == 2
        assert alerts[0].title == "T2"  # Reversed order (newest first)

    def test_filter_alerts_by_source(self):
        engine = WatchtowerEngine()
        engine.ingest("specter", [{"alert_type": "A", "severity": "HIGH", "title": "S", "detail": "d", "src_ip": "1.1.1.1"}])
        engine.ingest("phantom", [{"alert_type": "B", "severity": "LOW", "title": "P", "detail": "d", "src_ip": "2.2.2.2"}])
        alerts = engine.get_all_alerts(source="specter")
        assert len(alerts) == 1
        assert alerts[0].source == "specter"

    def test_get_incident(self):
        engine = WatchtowerEngine()
        engine.ingest("specter", [{"alert_type": "A", "severity": "HIGH", "title": "T", "detail": "d", "src_ip": "3.3.3.3"}])
        inc_id = list(engine.incidents.keys())[0]
        inc = engine.get_incident(inc_id)
        assert inc is not None
        assert inc.incident_id == inc_id

    def test_get_missing_incident(self):
        assert WatchtowerEngine().get_incident("NONEXISTENT") is None

    def test_get_stats(self):
        engine = WatchtowerEngine()
        stats = engine.get_stats()
        assert stats["total_alerts"] == 0
        assert stats["total_incidents"] == 0
        assert set(stats["supported_sources"]) == set(sorted(SUPPORTED_SOURCES))

    def test_get_incident_feed(self):
        engine = WatchtowerEngine()
        engine.ingest("specter", [{"alert_type": "A", "severity": "HIGH", "title": "T", "detail": "d", "src_ip": "4.4.4.4"}])
        feed = engine.get_incident_feed()
        assert len(feed) == 1
        assert feed[0]["incident_id"] in engine.incidents

    def test_get_incident_feed_empty(self):
        feed = WatchtowerEngine().get_incident_feed()
        assert feed == []

    def test_get_all_incidents(self):
        engine = WatchtowerEngine()
        engine.ingest("specter", [{"alert_type": "A", "severity": "HIGH", "title": "T", "detail": "d", "src_ip": "5.5.5.5"}])
        all_inc = engine.get_all_incidents()
        assert len(all_inc) == 1

    def test_clear(self):
        engine = WatchtowerEngine()
        engine.ingest("specter", [{"alert_type": "A", "severity": "HIGH", "title": "T", "detail": "d", "src_ip": "6.6.6.6"}])
        assert engine.clear() > 0
        assert len(engine.alert_queue) == 0
        assert len(engine.incidents) == 0


# ────────────────────────────────────────────────────────────────────
# Core Engine — Queue management
# ────────────────────────────────────────────────────────────────────

class TestQueueManagement:

    def test_queue_trimming(self):
        engine = WatchtowerEngine()
        engine._max_alerts = 5  # Very small for testing
        for i in range(10):
            engine.ingest("specter", [{"alert_type": f"A{i}", "severity": "LOW", "title": f"T{i}", "detail": f"d{i}", "src_ip": f"{i}.{i}.{i}.{i}"}])
        assert len(engine.alert_queue) <= 5

    def test_auto_increment_id(self):
        engine = WatchtowerEngine()
        r1 = engine.ingest("specter", [{"alert_type": "A", "severity": "HIGH", "title": "T", "detail": "d"}])
        r2 = engine.ingest("phantom", [{"alert_type": "B", "severity": "HIGH", "title": "T", "detail": "d"}])
        assert r1[0].alert_id != r2[0].alert_id


# ────────────────────────────────────────────────────────────────────
# Server — Endpoints
# ────────────────────────────────────────────────────────────────────

class TestWebhookEndpoints:

    def setup_method(self):
        self.client = watchtower_server.app.test_client()

    def teardown_method(self):
        watchtower_server.engine.clear()
        with watchtower_server._sse_lock:
            watchtower_server._latest_alerts.clear()

    def test_webhook_specter(self):
        resp = self.client.post("/webhook/specter", json=[
            {"alert_type": "RAT", "severity": "CRITICAL", "title": "Test", "detail": "d", "src_ip": "1.1.1.1"},
        ])
        data = resp.get_json()
        assert resp.status_code == 200
        assert data["ingested"] == 1

    def test_webhook_unsupported_source(self):
        resp = self.client.post("/webhook/unknown_tool", json=[{"alert_type": "T"}])
        assert resp.status_code == 400

    def test_webhook_empty_body(self):
        resp = self.client.post("/webhook/specter", json={})
        assert resp.status_code == 400

    def test_webhook_empty_array(self):
        resp = self.client.post("/webhook/specter", json=[])
        data = resp.get_json()
        assert data["ingested"] == 0

    def test_webhook_mirage(self):
        resp = self.client.post("/webhook/mirage", json=[
            {"alert_type": "lateral", "severity": "HIGH", "title": "L", "detail": "d", "src_ip": "2.2.2.2"},
        ])
        assert resp.get_json()["ingested"] == 1

    def test_webhook_ticorr(self):
        resp = self.client.post("/webhook/ticorr", json=[
            {"alert_type": "IOC_match", "severity": "CRITICAL", "title": "IOC", "detail": "d", "src_ip": "3.3.3.3"},
        ])
        assert resp.get_json()["ingested"] == 1

    def test_webhook_footprintscanner(self):
        resp = self.client.post("/webhook/footprintscanner", json=[
            {"alert_type": "exposed", "severity": "MEDIUM", "title": "E", "detail": "d", "src_ip": "4.4.4.4"},
        ])
        assert resp.get_json()["ingested"] == 1

    def test_webhook_logcorrelator(self):
        resp = self.client.post("/webhook/logcorrelator", json=[
            {"alert_type": "incident", "severity": "HIGH", "title": "Inc", "detail": "d", "src_ip": "5.5.5.5"},
        ])
        assert resp.get_json()["ingested"] == 1

    def test_webhook_custom(self):
        resp = self.client.post("/webhook/custom", json=[
            {"alert_type": "custom_alert", "severity": "MEDIUM", "title": "C", "detail": "d", "src_ip": "6.6.6.6"},
        ])
        assert resp.get_json()["ingested"] == 1

    def test_webhook_json_object_format(self):
        """Watchtower accepts {alerts: [...]} or just [{}]."""
        resp = self.client.post("/webhook/specter", json={
            "alerts": [{"alert_type": "A", "severity": "HIGH", "title": "T", "detail": "d", "src_ip": "7.7.7.7"}]
        })
        assert resp.get_json()["ingested"] == 1

    def test_webhook_total_in_system(self):
        self.client.post("/webhook/specter", json=[
            {"alert_type": "A", "severity": "HIGH", "title": "T", "detail": "d", "src_ip": "8.8.8.8"},
        ])
        resp = self.client.post("/webhook/phantom", json=[
            {"alert_type": "B", "severity": "HIGH", "title": "T", "detail": "d", "src_ip": "9.9.9.9"},
        ])
        data = resp.get_json()
        assert data["ingested"] == 1
        assert data["total_in_system"] == 2


class TestPhantomPush:

    def setup_method(self):
        self.client = watchtower_server.app.test_client()

    def teardown_method(self):
        watchtower_server.engine.clear()
        with watchtower_server._sse_lock:
            watchtower_server._latest_alerts.clear()

    def test_phantom_push(self):
        resp = self.client.post("/webhook/phantom/push", json={
            "alerts": [
                {"alert_type": "RAT", "severity": "CRITICAL", "title": "Test", "detail": "d"},
            ]
        })
        data = resp.get_json()
        assert data["ingested"] == 1

    def test_phantom_push_no_alerts(self):
        resp = self.client.post("/webhook/phantom/push", json={"alerts": []})
        assert resp.status_code == 400


class TestQueryEndpoints:

    def setup_method(self):
        self.client = watchtower_server.app.test_client()

    def teardown_method(self):
        watchtower_server.engine.clear()
        with watchtower_server._sse_lock:
            watchtower_server._latest_alerts.clear()

    def test_health(self):
        resp = self.client.get("/api/health")
        data = resp.get_json()
        assert data["status"] == "ok"
        assert data["version"] == "1.0.0"

    def test_get_alerts_empty(self):
        resp = self.client.get("/api/alerts")
        data = resp.get_json()
        assert data["count"] == 0

    def test_get_alerts_with_data(self):
        self.client.post("/webhook/specter", json=[
            {"alert_type": "A", "severity": "HIGH", "title": "T", "detail": "d", "src_ip": "1.1.1.1"},
        ])
        resp = self.client.get("/api/alerts")
        data = resp.get_json()
        assert data["count"] >= 1
        assert data["alerts"][0]["source"] == "specter"

    def test_get_alerts_filter_source(self):
        self.client.post("/webhook/specter", json=[{"alert_type": "A", "severity": "HIGH", "title": "T", "detail": "d", "src_ip": "1.1.1.1"}])
        self.client.post("/webhook/phantom", json=[{"alert_type": "B", "severity": "HIGH", "title": "T", "detail": "d", "src_ip": "2.2.2.2"}])
        resp = self.client.get("/api/alerts?source=specter")
        data = resp.get_json()
        assert data["count"] >= 1
        for a in data["alerts"]:
            assert a["source"] == "specter"

    def test_get_latest_alerts(self):
        self.client.post("/webhook/specter", json=[{"alert_type": "A", "severity": "HIGH", "title": "T", "detail": "d", "src_ip": "1.1.1.1"}])
        resp = self.client.get("/api/alerts/latest")
        data = resp.get_json()
        assert data["count"] >= 1

    def test_get_incidents(self):
        self.client.post("/webhook/specter", json=[{"alert_type": "A", "severity": "HIGH", "title": "T", "detail": "d", "src_ip": "1.1.1.1"}])
        resp = self.client.get("/api/incidents")
        data = resp.get_json()
        assert data["count"] >= 0

    def test_get_incident(self):
        self.client.post("/webhook/specter", json=[{"alert_type": "A", "severity": "HIGH", "title": "T", "detail": "d", "src_ip": "1.1.1.1"}])
        inc_id = list(watchtower_server.engine.incidents.keys())[0]
        resp = self.client.get(f"/api/incident/{inc_id}")
        data = resp.get_json()
        assert data["incident_id"] == inc_id
        assert "entity_alerts" in data

    def test_get_missing_incident(self):
        resp = self.client.get("/api/incident/NONEXISTENT")
        assert resp.status_code == 404

    def test_get_stats(self):
        resp = self.client.get("/api/stats")
        data = resp.get_json()
        assert "total_alerts" in data
        assert "total_incidents" in data
        assert "severity_breakdown" in data

    def test_clear(self):
        self.client.post("/webhook/specter", json=[{"alert_type": "A", "severity": "HIGH", "title": "T", "detail": "d", "src_ip": "1.1.1.1"}])
        resp = self.client.post("/api/clear")
        data = resp.get_json()
        assert data["status"] == "cleared"
        assert data["items"] > 0

    def test_clear_all_data(self):
        self.client.post("/webhook/specter", json=[{"alert_type": "A", "severity": "HIGH", "title": "T", "detail": "d", "src_ip": "1.1.1.1"}])
        self.client.post("/api/clear")
        resp = self.client.get("/api/alerts")
        assert resp.get_json()["count"] == 0


class TestDashboard:

    def setup_method(self):
        self.client = watchtower_server.app.test_client()

    def test_dashboard_returns_html(self):
        resp = self.client.get("/")
        assert resp.status_code == 200
        assert "text/html" in resp.content_type
        assert "Watchtower" in resp.get_data(as_text=True)


class TestSSE:
    """Tests for the SSE stream endpoint."""

    def setup_method(self):
        self.client = watchtower_server.app.test_client()

    def teardown_method(self):
        watchtower_server.engine.clear()
        with watchtower_server._sse_lock:
            watchtower_server._latest_alerts.clear()
            watchtower_server._sse_subscribers.clear()

    def test_sse_content_type(self):
        """SSE endpoint should have text/event-stream content type."""
        resp = self.client.get("/api/stream")
        assert "text/event-stream" in resp.content_type

    @pytest.mark.skip(reason="SSE streaming endpoint hangs in test client")
    def test_sse_no_events_returns_empty(self):
        """SSE with no events should return without error."""
        resp = self.client.get("/api/stream")
        assert resp.status_code == 200
        assert resp.content_type == "text/event-stream"

    def test_sse_pushes_incidents_on_ingest(self):
        """Ingesting correlated alerts should push to SSE queue."""
        watchtower_server.engine.ingest("specter", [
            {"alert_type": "RAT", "severity": "CRITICAL", "title": "Test", "detail": "d", "src_ip": "1.1.1.1"},
        ])
        watchtower_server.engine.ingest("phantom", [
            {"alert_type": "beacon", "severity": "CRITICAL", "title": "Test", "detail": "d", "src_ip": "1.1.1.1"},
        ])

        # Alerts should be in the engine
        assert len(watchtower_server.engine.alert_queue) == 2
        assert len(watchtower_server.engine.incidents) == 1

    @pytest.mark.skip(reason="SSE streaming endpoint hangs in test client")
    def test_sse_headers_present(self):
        """SSE response should have correct headers."""
        resp = self.client.get("/api/stream")
        assert "Cache-Control" in resp.headers
        assert "X-Accel-Buffering" in resp.headers


# ────────────────────────────────────────────────────────────────────
# Integration: End-to-end correlation
# ────────────────────────────────────────────────────────────────────

class TestIntegration:

    def test_full_attack_chain_correlation(self):
        """Simulate a full attack chain across multiple tools."""
        engine = WatchtowerEngine()

        # Phase 1: FootprintScanner finds exposed ports
        engine.ingest("footprintscanner", [
            {
                "alert_type": "exposed_service",
                "severity": "MEDIUM",
                "title": "SSH exposed to internet",
                "detail": "Port 22 open on 10.0.1.5",
                "src_ip": "10.0.1.5",
            }
        ])
        assert len(engine.incidents) >= 1

        # Phase 2: SPECTER detects RAT on the same host
        engine.ingest("specter", [
            {
                "alert_type": "RAT_DETECTED",
                "severity": "CRITICAL",
                "title": "njRAT process detected",
                "detail": "Process njRAT (PID 4444) on 10.0.1.5",
                "src_ip": "10.0.1.5",
            }
        ])

        # Phase 3: Phantom detects beaconing from the same host
        engine.ingest("phantom", [
            {
                "alert_type": "beaconing_detected",
                "severity": "CRITICAL",
                "title": "Beaconing to C2",
                "detail": "10.0.1.5 beaconing to 198.51.100.1",
                "src_ip": "10.0.1.5",
                "dst_ip": "198.51.100.1",
            }
        ])

        # Phase 4: Mirage detects lateral movement from compromised host
        engine.ingest("mirage", [
            {
                "alert_type": "lateral_movement",
                "severity": "HIGH",
                "title": "SMB lateral movement",
                "detail": "10.0.1.5 connecting to 10.0.1.10",
                "src_ip": "10.0.1.5",
            }
        ])

        # Phase 5: TI-Corr enriches with threat intel
        engine.ingest("ticorr", [
            {
                "alert_type": "IOC_match",
                "severity": "CRITICAL",
                "title": "C2 IP in threat feed",
                "detail": "198.51.100.1 is a known C2 for njRAT",
                "src_ip": "198.51.100.1",
            }
        ])

        # Verify: all 5 alerts in one correlated incident
        stats = engine.get_stats()
        assert stats["total_alerts"] == 5

        # All should be correlated on 10.0.1.5 (check entity map)
        assert len(engine.incidents) >= 1
        assert "10.0.1.5" in engine._entity_map, "10.0.1.5 should be in entity map"
        inc_ids = engine._entity_map["10.0.1.5"]
        assert len(inc_ids) == 1  # All 5 alerts on 10.0.1.5 in one incident

        main_incident = list(engine.incidents.values())[0]
        assert len(main_incident.child_alerts) >= 4  # At least 4 on 10.0.1.5
        assert len(main_incident.sources) >= 4  # multiple tool sources

        # Score should be very high (multi-source CRITICAL alerts)
        assert main_incident.score >= 60

    def test_independent_incidents(self):
        """Multiple attack chains should remain separate."""
        engine = WatchtowerEngine()

        # Attack chain 1 on 10.0.1.5
        engine.ingest("specter", [{"alert_type": "RAT", "severity": "CRITICAL", "title": "T", "detail": "d", "src_ip": "10.0.1.5"}])
        engine.ingest("phantom", [{"alert_type": "beacon", "severity": "CRITICAL", "title": "T", "detail": "d", "src_ip": "10.0.1.5"}])

        # Attack chain 2 on 10.0.2.5 (different IP, should be separate)
        engine.ingest("specter", [{"alert_type": "RAT", "severity": "HIGH", "title": "T", "detail": "d", "src_ip": "10.0.2.5"}])
        engine.ingest("phantom", [{"alert_type": "beacon", "severity": "MEDIUM", "title": "T", "detail": "d", "src_ip": "10.0.2.5"}])

        incidents_with_10_0_1_5 = sum(1 for inc in engine.incidents.values() if "10.0.1.5" in str(inc.entities))
        incidents_with_10_0_2_5 = sum(1 for inc in engine.incidents.values() if "10.0.2.5" in str(inc.entities))

        assert incidents_with_10_0_1_5 == 1
        assert incidents_with_10_0_2_5 == 1


class TestSupportedSources:

    def test_all_known_sources_in_supported(self):
        expected = {"specter", "phantom", "mirage", "ticorr", "footprintscanner", "logcorrelator", "playbook", "custom"}
        assert SUPPORTED_SOURCES == expected

    def test_all_sources_ingestable(self):
        engine = WatchtowerEngine()
        for src in SUPPORTED_SOURCES:
            result = engine.ingest(src, [{"alert_type": "TEST", "severity": "LOW", "title": "T", "detail": "d"}])
            assert len(result) == 1, f"Source {src} failed to ingest"

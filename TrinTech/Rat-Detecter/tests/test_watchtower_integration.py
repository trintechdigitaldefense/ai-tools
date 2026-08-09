"""
Unit tests for SPECTER → Watchtower integration.

Tests:
- findings_to_watchtower_alerts: correct mapping of findings → alerts
- push_to_watchtower: correct HTTP POST format, error handling
- CLI flags: --no-watchtower and --watchtower-url are recognized
"""

import sys
from unittest.mock import MagicMock, patch

# Add parent to path for imports
sys.path.insert(0, "/opt/baal-agent/workspace/TrinTech/Rat-Detecter")

import importlib.util
spec = importlib.util.spec_from_file_location("specter", "/opt/baal-agent/workspace/TrinTech/Rat-Detecter/Rat-Detecter.py")
specter = importlib.util.module_from_spec(spec)
spec.loader.exec_module(specter)


class TestFindingsToWatchtower:
    """Convert SPECTER findings dict → Watchtower alert dict."""

    def _make_finding(self, ftype, severity, detail, extra=None):
        item = {
            "type": ftype,
            "severity": severity,
            "detail": detail,
            "ts": "2026-08-09 10:00:00",
        }
        if extra:
            item.update(extra)
        return item

    def test_basic_conversion(self):
        f = self._make_finding("LISTENING_SUSPICIOUS_PORT", "HIGH",
                               "Listening on suspicious port 4444 (backdoor) PID=1234",
                               {"pid": 1234, "port": 4444})
        alerts = specter.findings_to_watchtower_alerts([f])
        assert len(alerts) == 1
        a = alerts[0]
        assert a["alert_type"] == "LISTENING_SUSPICIOUS_PORT"
        assert a["severity"] == "HIGH"
        assert a["title"] == "LISTENING_SUSPICIOUS_PORT"
        assert "port 4444" in a["detail"]
        assert a["pid"] == 1234
        assert a["port"] == 4444

    def test_suspicious_connection_with_ip(self):
        f = self._make_finding("SUSPICIOUS_CONNECTION", "CRITICAL",
                               "Suspicious outbound connection on port 6667 to 192.168.1.50 PID=5678",
                               {"pid": 5678, "remote_port": 6667})
        alerts = specter.findings_to_watchtower_alerts([f])
        assert len(alerts) == 1
        assert alerts[0]["severity"] == "CRITICAL"
        assert alerts[0]["src_ip"] == "192.168.1.50"

    def test_no_ip_in_detail(self):
        f = self._make_finding("MALWARE_DETECTED", "MEDIUM",
                               "RAT process detected: remcos.exe in /tmp")
        alerts = specter.findings_to_watchtower_alerts([f])
        assert len(alerts) == 1
        assert "src_ip" not in alerts[0]

    def test_empty_findings(self):
        alerts = specter.findings_to_watchtower_alerts([])
        assert alerts == []

    def test_multiple_findings(self):
        findings = [
            self._make_finding("A", "HIGH", "Detail A"),
            self._make_finding("B", "CRITICAL", "Detail B with 10.0.0.1"),
            self._make_finding("C", "LOW", "Detail C"),
        ]
        alerts = specter.findings_to_watchtower_alerts(findings)
        assert len(alerts) == 3
        assert alerts[0]["alert_type"] == "A"
        assert alerts[1]["alert_type"] == "B"
        assert alerts[1]["src_ip"] == "10.0.0.1"
        assert alerts[2]["alert_type"] == "C"

    def test_severity_uppercase(self):
        f = self._make_finding("TEST", "critical", "test detail")
        alerts = specter.findings_to_watchtower_alerts([f])
        assert alerts[0]["severity"] == "CRITICAL"

    def test_missing_severity_defaults_to_medium(self):
        f = {"type": "TEST", "detail": "no severity here"}
        alerts = specter.findings_to_watchtower_alerts([f])
        assert alerts[0]["severity"] == "MEDIUM"

    def test_extra_fields_preserved(self):
        f = self._make_finding("PORT_OPEN", "INFO", "Port 80 open",
                               {"port": 80, "service": "http", "os": "linux"})
        alerts = specter.findings_to_watchtower_alerts([f])
        assert alerts[0]["port"] == 80
        assert alerts[0]["service"] == "http"
        assert alerts[0]["os"] == "linux"


class TestPushToWatchtower:
    """Fire-and-forget push to Watchtower webhook."""

    def test_success(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"status": "ok", "ingested": 3, "source": "specter"}

        with patch.object(specter.requests, 'post', return_value=mock_resp) as mock_post:
            result = specter.push_to_watchtower([
                {"type": "A", "severity": "HIGH", "detail": "test"},
                {"type": "B", "severity": "LOW", "detail": "test2"},
                {"type": "C", "severity": "MEDIUM", "detail": "test3"},
            ])

        assert result["status"] == "ok"
        assert result["pushed"] == 3
        assert result["total"] == 3
        mock_post.assert_called_once()
        # Verify the JSON payload structure
        call_args = mock_post.call_args
        payload = call_args[1]["json"]
        assert "alerts" in payload
        assert len(payload["alerts"]) == 3
        assert payload["alerts"][0]["alert_type"] == "A"

    def test_empty_findings_skipped(self):
        result = specter.push_to_watchtower([])
        assert result["status"] == "skipped"
        assert result["reason"] == "no findings"

    def test_connection_error(self):
        with patch.object(specter.requests, 'post', side_effect=Exception("no network")):
            result = specter.push_to_watchtower([{"type": "X", "severity": "HIGH", "detail": "y"}])
        assert result["status"] == "error"
        assert "no network" in result["message"]

    def test_timeout(self):
        with patch.object(specter.requests, 'post', side_effect=Exception("timeout")):
            result = specter.push_to_watchtower([{"type": "X", "severity": "HIGH", "detail": "y"}])
        assert result["status"] == "error"

    def test_custom_watchtower_url(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"status": "ok", "ingested": 1}

        with patch.object(specter.requests, 'post', return_value=mock_resp) as mock_post:
            specter.push_to_watchtower(
                [{"type": "X", "severity": "HIGH", "detail": "y"}],
                watchtower_url="http://custom-wt:9999"
            )
        mock_post.assert_called_once()
        assert "custom-wt:9999" in mock_post.call_args[0][0]

    def test_push_format_matches_watchtower_expectation(self):
        """Ensure pushed JSON matches what Watchtower's webhook expects."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"status": "ok", "ingested": 1}

        with patch.object(specter.requests, 'post', return_value=mock_resp) as mock_post:
            specter.push_to_watchtower([
                {"type": "SUSPICIOUS_PROCESS", "severity": "CRITICAL",
                 "detail": "njrat detected on host 10.0.0.5 PID=999 port=4444",
                 "ts": "2026-08-09 12:00:00", "pid": 999, "port": 4444},
            ])

        payload = mock_post.call_args[1]["json"]
        alert = payload["alerts"][0]

        # Watchtower expects these fields
        assert "alert_type" in alert
        assert "severity" in alert
        assert "title" in alert
        assert "detail" in alert
        assert "timestamp" in alert
        assert alert["src_ip"] == "10.0.0.5"


class TestIntegration:
    """End-to-end: find an IP in detail → get it in entities."""

    def test_ip_extraction_via_detail(self):
        """Finding with IP in detail → Watchtower alert gets src_ip → entities."""
        f = {"type": "CONNECTED_C2", "severity": "HIGH",
             "detail": "Outbound connection to C2 server at 172.16.0.100 port 443",
             "ts": "2026-08-09 14:00:00"}
        alerts = specter.findings_to_watchtower_alerts([f])
        assert alerts[0]["src_ip"] == "172.16.0.100"

    def test_hostname_in_detail(self):
        """Finding with hostname in detail — IP is extracted, hostname noted."""
        f = {"type": "DNS_QUERY", "severity": "MEDIUM",
             "detail": "Suspicious DNS query to evil-c2-server-01.badsite.com from workstation-5",
             "ts": "2026-08-09 15:00:00"}
        alerts = specter.findings_to_watchtower_alerts([f])
        # Domain in detail will be extracted by Watchtower's engine
        assert alerts[0]["detail"] == f["detail"]

    def test_mixed_severities_all_pushed(self):
        """All severity levels get pushed correctly.
        Note: Watchtower only supports 4 levels, so INFO → MEDIUM.
        """
        findings = [
            {"type": "T1", "severity": "CRITICAL", "detail": "d1"},
            {"type": "T2", "severity": "HIGH", "detail": "d2"},
            {"type": "T3", "severity": "MEDIUM", "detail": "d3"},
            {"type": "T4", "severity": "LOW", "detail": "d4"},
            {"type": "T5", "severity": "INFO", "detail": "d5"},
        ]
        alerts = specter.findings_to_watchtower_alerts(findings)
        assert len(alerts) == 5
        assert [a["severity"] for a in alerts] == ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
        # Watchtower's engine will normalize INFO → MEDIUM during ingestion
        # This test just verifies SPECTER preserves the original severity


def main():
    tests = [
        ("TestFindingsToWatchtower", [
            "test_basic_conversion",
            "test_suspicious_connection_with_ip",
            "test_no_ip_in_detail",
            "test_empty_findings",
            "test_multiple_findings",
            "test_severity_uppercase",
            "test_missing_severity_defaults_to_medium",
            "test_extra_fields_preserved",
        ]),
        ("TestPushToWatchtower", [
            "test_success",
            "test_empty_findings_skipped",
            "test_connection_error",
            "test_timeout",
            "test_custom_watchtower_url",
            "test_push_format_matches_watchtower_expectation",
        ]),
        ("TestIntegration", [
            "test_ip_extraction_via_detail",
            "test_hostname_in_detail",
            "test_mixed_severities_all_pushed",
        ]),
    ]

    passed = 0
    failed = 0

    for test_class_name, methods in tests:
        print(f"\n=== {test_class_name} ===")
        cls = globals()[test_class_name]()
        for method_name in methods:
            try:
                getattr(cls, method_name)()
                print(f"  PASS {test_class_name}.{method_name}")
                passed += 1
            except AssertionError as e:
                print(f"  FAIL {test_class_name}.{method_name}: {e}")
                failed += 1
            except Exception as e:
                print(f"  ERROR {test_class_name}.{method_name}: {type(e).__name__}: {e}")
                failed += 1

    print(f"\n{'='*50}")
    print(f"Results: {passed} passed, {failed} failed")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())

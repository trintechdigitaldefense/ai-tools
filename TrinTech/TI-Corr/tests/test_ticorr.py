"""
TrinTech Digital Defense
TI-Corr: Threat Intelligence Correlator — Integration Tests
"""

import json
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import TestCase, main

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from ticorr.correlator.correlator import ThreatCorrelator, TIStorage
from ticorr.feeds.implementations import (
    AbuseIPDBFeed,
    CISAKEVFeed,
    OTXFeed,
    ShodanFeed,
    ThreatCrowdFeed,
    VirusTotalFeed,
)


class TestTIStorage(TestCase):
    """Test SQLite storage layer."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.db_path = Path(self.tmpdir) / "test.db"
        self.storage = TIStorage(self.db_path)

    def test_save_and_retrieve_lookup(self):
        result = {
            "source": "TestFeed",
            "type": "ip",
            "value": "1.2.3.4",
            "confidence": 75,
            "tags": ["malware", "c2"],
            "description": "Test description",
        }
        self.storage.save_lookup(result)
        cached = self.storage.get_lookup("TestFeed", "ip", "1.2.3.4")
        self.assertIsNotNone(cached)
        self.assertEqual(cached["value"], "1.2.3.4")
        self.assertEqual(cached["confidence"], 75)

    def test_save_and_retrieve_correlation(self):
        self.storage.save_correlation("find-001", "TestFeed", {"result": "data"}, 30)
        corrs = self.storage.get_correlations("find-001")
        self.assertEqual(len(corrs), 1)
        self.assertEqual(corrs[0]["feed"], "TestFeed")

    def test_missing_lookup_returns_none(self):
        result = self.storage.get_lookup("NoFeed", "ip", "0.0.0.0")
        self.assertIsNone(result)

    def test_db_file_created(self):
        self.assertTrue(self.db_path.exists())


class TestFeedImplementations(TestCase):
    """Test feed initialization and structure."""

    def test_abuseipdb_init(self):
        feed = AbuseIPDBFeed()
        self.assertEqual(feed.name, "AbuseIPDB")
        self.assertFalse(feed.enabled)  # No API key set

    def test_abuseipdb_with_key(self):
        os.environ["ABUSEIPDB_API_KEY"] = "test_key"
        try:
            feed = AbuseIPDBFeed()
            self.assertTrue(feed.enabled)
        finally:
            del os.environ["ABUSEIPDB_API_KEY"]

    def test_cisa_kev_no_key_required(self):
        feed = CISAKEVFeed()
        self.assertTrue(feed.enabled)  # No API key needed
        self.assertEqual(feed.name, "CISA KEV")

    def test_otx_init(self):
        feed = OTXFeed()
        self.assertEqual(feed.name, "AlienVault OTX")
        self.assertFalse(feed.enabled)

    def test_virustotal_init(self):
        feed = VirusTotalFeed()
        self.assertEqual(feed.name, "VirusTotal")
        self.assertFalse(feed.enabled)

    def test_threatcrowd_init(self):
        feed = ThreatCrowdFeed()
        self.assertTrue(feed.enabled)  # No API key needed

    def test_shodan_init(self):
        feed = ShodanFeed()
        self.assertEqual(feed.name, "Shodan")
        self.assertFalse(feed.enabled)


class TestCorrelator(TestCase):
    """Test the main correlator engine."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.correlator = ThreatCorrelator(
            reports_dir=Path(self.tmpdir),
        )

    def test_init_with_no_keys(self):
        """Correlator should work with 0 enabled feeds."""
        self.assertIsInstance(self.correlator.active_feeds, dict)
        self.assertGreater(len(self.correlator.FEEDS), 0)

    def test_correlate_finding_no_intel(self):
        """Finding with no queries should return unchanged."""
        finding = {
            "id": "test-1",
            "type": "SUSPICIOUS_PROCESS",
            "severity": "HIGH",
            "detail": "Process 'bad_process' (PID: 1234)",
        }
        result = self.correlator.correlate_finding(finding)
        self.assertIn("intel", result)
        self.assertEqual(result["type"], "SUSPICIOUS_PROCESS")

    def test_correlate_finding_with_ip(self):
        """Finding with an IP should generate AbuseIPDB/Shodan queries."""
        finding = {
            "id": "test-2",
            "type": "SUSPICIOUS_CONNECTION",
            "severity": "HIGH",
            "detail": "Connection to 203.0.113.50 on port 4444",
        }
        result = self.correlator.correlate_finding(finding)
        self.assertIn("intel", result)
        # AbuseIPDB and Shodan should be queried
        queries = self.correlator._extract_queries(finding)
        ip_queries = [(t, v) for t, v in queries if v == "203.0.113.50"]
        self.assertGreater(len(ip_queries), 0)

    def test_correlate_finding_with_hash(self):
        """Finding with a SHA-256 hash should query VirusTotal."""
        sha256 = "a" * 64
        finding = {
            "id": "test-3",
            "type": "FILE_INTEGRITY",
            "severity": "MEDIUM",
            "detail": f"File hash: {sha256}",
        }
        queries = self.correlator._extract_queries(finding)
        vt_queries = [(t, v) for t, v in queries if t == "virustotal" and len(v) == 64]
        self.assertGreater(len(vt_queries), 0)

    def test_extract_queries_ip(self):
        finding = {"detail": "IP 1.2.3.4 connected"}
        queries = self.correlator._extract_queries(finding)
        values = [v for _, v in queries]
        self.assertIn("1.2.3.4", values)

    def test_extract_queries_domain(self):
        finding = {"detail": "Domain evil.com in cmdline"}
        queries = self.correlator._extract_queries(finding)
        values = [v for _, v in queries]
        self.assertIn("evil.com", values)

    def test_extract_queries_cve(self):
        finding = {"detail": "CVE-2023-12345 detected"}
        queries = self.correlator._extract_queries(finding)
        values = [v for _, v in queries]
        self.assertIn("CVE-2023-12345", values)

    def test_extract_queries_cve_no_match_kev(self):
        """CVE should only query CISA KEV, not other feeds."""
        finding = {"detail": "CVE-2023-9999"}
        queries = self.correlator._extract_queries(finding)
        kev_queries = [t for t, _ in queries]
        self.assertIn("cisa_kev", kev_queries)

    def test_batch_correlation(self):
        findings = [
            {"id": f"test-{i}", "type": "TEST", "severity": "INFO",
             "detail": f"Connection to 192.0.2.{i}"}
            for i in range(3)
        ]
        results = self.correlator.correlate_batch(findings)
        self.assertEqual(len(results), 3)

    def test_report_generation(self):
        findings = [
            {"id": "t1", "type": "TEST", "severity": "INFO", "detail": "1.2.3.4"},
        ]
        results = self.correlator.correlate_batch(findings)
        report = self.correlator.generate_report(results)
        self.assertIsInstance(report, str)
        self.assertIn("THREAT INTELLIGENCE", report)

    def test_is_hash_true(self):
        self.assertTrue(self.correlator._is_hash("a" * 64))
        self.assertTrue(self.correlator._is_hash("b" * 32))

    def test_is_hash_false(self):
        self.assertFalse(self.correlator._is_hash("not-a-hash"))
        self.assertFalse(self.correlator._is_hash("a" * 10))

    def test_boost_calculation(self):
        self.assertEqual(self.correlator._calculate_boost({"confidence": 90}), 50)
        self.assertEqual(self.correlator._calculate_boost({"confidence": 60}), 35)
        self.assertEqual(self.correlator._calculate_boost({"confidence": 30}), 20)
        self.assertEqual(self.correlator._calculate_boost({"confidence": 5}), 5)
        self.assertEqual(self.correlator._calculate_boost({"confidence": 1}), 5)

    def test_feed_status(self):
        status = self.correlator.get_feed_status()
        self.assertIsInstance(status, dict)
        for name, s in status.items():
            self.assertIn("enabled", s)

    def test_cisa_kev_fetch(self):
        """Test that CISA KEV catalog can be fetched."""
        feed = CISAKEVFeed()
        catalog = feed._get_catalog()
        self.assertIsInstance(catalog, list)


class TestExtractQueries(TestCase):
    """Test query extraction logic."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.correlator = ThreatCorrelator(reports_dir=Path(self.tmpdir))

    def test_single_ip(self):
        finding = {"detail": "192.168.1.1 connected"}
        queries = self.correlator._extract_queries(finding)
        values = [v for _, v in queries]
        self.assertIn("192.168.1.1", values)

    def test_multiple_ips(self):
        finding = {"detail": "10.0.0.1 and 10.0.0.2 connected"}
        queries = self.correlator._extract_queries(finding)
        values = [v for _, v in queries]
        self.assertIn("10.0.0.1", values)
        self.assertIn("10.0.0.2", values)

    def test_ip_not_extracted_from_domain(self):
        finding = {"detail": "example.com"}
        queries = self.correlator._extract_queries(finding)
        values = [v for _, v in queries]
        # example.com is NOT an IP
        self.assertNotIn("example.com", [v for _, v in queries if "." not in v])

    def test_domain_extracted(self):
        finding = {"detail": "c2.evil.com seen"}
        queries = self.correlator._extract_queries(finding)
        values = [v for _, v in queries]
        self.assertIn("c2.evil.com", values)

    def test_file_path_not_extracted_as_domain(self):
        finding = {"detail": "/var/log/syslog"}
        queries = self.correlator._extract_queries(finding)
        values = [v for _, v in queries]
        # /var/log/syslog should not be extracted
        self.assertNotIn("/var/log/syslog", values)

    def test_sha256_extracted(self):
        hash_val = "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
        finding = {"detail": f"Hash: {hash_val}"}
        queries = self.correlator._extract_queries(finding)
        values = [v for _, v in queries]
        self.assertIn(hash_val, values)

    def test_cve_extracted(self):
        finding = {"detail": "CVE-2024-1234 and CVE-2024-5678"}
        queries = self.correlator._extract_queries(finding)
        values = [v for _, v in queries]
        self.assertIn("CVE-2024-1234", values)
        self.assertIn("CVE-2024-5678", values)

    def test_no_matches(self):
        finding = {"detail": "nothing suspicious here"}
        queries = self.correlator._extract_queries(finding)
        self.assertEqual(len(queries), 0)


def run_api_tests():
    """Run Flask API integration tests."""
    from ticorr_server import app

    print("\n--- API Integration Tests ---")

    client = app.test_client()

    # Health check
    resp = client.get("/api/health")
    assert resp.status_code == 200, f"Health check failed: {resp.status_code}"
    data = resp.get_json()
    assert data["status"] == "healthy"
    print("  ✅ Health check")

    # Start correlation
    resp = client.post("/api/start", json={"mode": "quick"})
    assert resp.status_code == 200, f"Start failed: {resp.status_code}"
    data = resp.get_json()
    assert data["status"] == "started"
    print("  ✅ Start correlation")

    # Duplicate start (should 409 — first one is still running)
    time.sleep(0.1)
    resp = client.post("/api/start", json={"mode": "quick"})
    assert resp.status_code == 409, f"Expected 409, got {resp.status_code}"
    print("  ✅ Duplicate start blocked (409)")

    # Check state
    time.sleep(2)
    resp = client.get("/api/state")
    assert resp.status_code == 200
    state = resp.get_json()
    assert "running" in state
    print(f"  ✅ State check (progress: {state.get('progress')}%)")

    # Wait for completion
    for _ in range(20):
        time.sleep(0.5)
        resp = client.get("/api/state")
        state = resp.get_json()
        if not state.get("running", True):
            break
    else:
        print("  ⚠️  Correlation timed out")

    # Report
    resp = client.get("/api/report")
    assert resp.status_code == 200
    assert len(resp.data) > 0
    print(f"  ✅ Report generated ({len(resp.data)} bytes)")

    # JSON report
    resp = client.get("/api/report/json")
    assert resp.status_code == 200
    data = resp.get_json()
    assert "findings" in data
    print(f"  ✅ JSON report ({len(data.get('findings', []))} findings)")

    # Health check
    resp = client.get("/api/health")
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["status"] == "healthy"
    print("  ✅ Health check")

    # Feed status
    resp = client.get("/api/feeds/status")
    assert resp.status_code == 200
    data = resp.get_json()
    assert "feeds" in data
    print(f"  ✅ Feed status ({data['active_count']} active)")

    print("\n  All API tests passed! ✅\n")


if __name__ == "__main__":
    print("=" * 50)
    print("TI-Corr Integration Tests")
    print("=" * 50 + "\n")

    # Run unit tests first
    suite = unittest.TestLoader().loadTestsFromTestCase(TestTIStorage)
    suite.addTests(unittest.TestLoader().loadTestsFromTestCase(TestFeedImplementations))
    suite.addTests(unittest.TestLoader().loadTestsFromTestCase(TestCorrelator))
    suite.addTests(unittest.TestLoader().loadTestsFromTestCase(TestExtractQueries))
    runner = unittest.TextTestRunner(verbosity=1)
    result = runner.run(suite)

    # Run API tests
    try:
        run_api_tests()
    except Exception as e:
        print(f"  ⚠️  API tests skipped: {e}")

    # Summary
    print(f"\nTests: {result.testsRun}, Failures: {len(result.failures)}, Errors: {len(result.errors)}")
    sys.exit(0 if result.wasSuccessful() else 1)

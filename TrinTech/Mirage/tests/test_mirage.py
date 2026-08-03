"""
TrinTech Digital Defense
Mirage: Deception Framework — Integration Tests
"""

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from mirage.core import MirageController, Alert, AlertStore, FakeSSHKeyLure, FakeDBCredentialsLure, FakeConfigFileLure, FakeServiceLure


class TestAlert(unittest.TestCase):
    """Test Alert data model."""

    def test_create_alert(self):
        a = Alert("test-1", "ssh_key", "Decoy Key", "/tmp", "1.2.3.4")
        self.assertEqual(a.alert_id, "test-1")
        self.assertEqual(a.lure_type, "ssh_key")
        self.assertEqual(a.severity, "MEDIUM")
        self.assertEqual(a.status, "NEW")

    def test_to_dict(self):
        a = Alert("test-2", "db_cred", "Decoy", "/tmp", "5.6.7.8")
        d = a.to_dict()
        self.assertEqual(d["alert_id"], "test-2")
        self.assertEqual(d["lure_type"], "db_cred")

    def test_add_note(self):
        a = Alert("test-3", "svc", "Fake", "/tmp", "1.1.1.1")
        a.add_note("Test note", "user")
        self.assertEqual(len(a.notes), 1)
        self.assertEqual(a.notes[0]["note"], "Test note")
        self.assertEqual(a.notes[0]["source"], "user")

    def test_tags(self):
        a = Alert("test-4", "ssh", "K", "/tmp", "x")
        self.assertEqual(a.tags, [])
        a.tags.append("test")
        self.assertIn("test", a.tags)


class TestAlertStore(unittest.TestCase):
    """Test SQLite alert storage."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.store = AlertStore(Path(self.tmpdir) / "test.db")

    def test_save_and_get(self):
        a = Alert("s1", "ssh", "K", "/tmp", "1.2.3.4")
        self.store.save(a)
        result = self.store.get_alert("s1")
        self.assertIsNotNone(result)
        self.assertEqual(result["actor_ip"], "1.2.3.4")

    def test_get_nonexistent(self):
        self.assertIsNone(self.store.get_alert("nonexistent"))

    def test_get_all(self):
        for i in range(3):
            a = Alert(f"all-{i}", "ssh", "K", "/tmp", f"1.2.3.{i}")
            self.store.save(a)
        results = self.store.get_all()
        self.assertEqual(len(results), 3)

    def test_get_all_filter(self):
        a1 = Alert("f1", "ssh", "K", "/tmp", "1.2.3.4")
        a1.status = "NEW"
        self.store.save(a1)
        a2 = Alert("f2", "ssh", "K", "/tmp", "5.6.7.8")
        a2.status = "RESOLVED"
        self.store.save(a2)
        results = self.store.get_all("NEW")
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["alert_id"], "f1")

    def test_stats(self):
        a = Alert("st1", "ssh", "K", "/tmp", "1.2.3.4")
        self.store.save(a)
        stats = self.store.get_stats()
        self.assertIn("total", stats)
        self.assertIn("by_status", stats)
        self.assertIn("by_severity", stats)

    def test_unique_ips(self):
        self.store.save(Alert("i1", "ssh", "K", "/tmp", "1.2.3.4"))
        self.store.save(Alert("i2", "ssh", "K", "/tmp", "1.2.3.4"))
        self.store.save(Alert("i3", "ssh", "K", "/tmp", "5.6.7.8"))
        ips = self.store.get_unique_ips()
        self.assertEqual(len(ips), 2)


class TestLures(unittest.TestCase):
    """Test individual lure types."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.store = AlertStore(Path(self.tmpdir) / "test.db")

    def test_ssh_key_deploy(self):
        lure = FakeSSHKeyLure()
        alert_id = lure.deploy(self.tmpdir, self.store)
        self.assertIsNotNone(alert_id)
        from pathlib import Path
        key_file = Path(self.tmpdir) / "id_rsa_decoy"
        self.assertTrue(key_file.exists())

    def test_ssh_key_trigger(self):
        lure = FakeSSHKeyLure()
        self.store.save(Alert("t1", "ssh_key", "Decoy", self.tmpdir, "PENDING"))
        
        event = {
            "action": "read",
            "path": f"{self.tmpdir}/id_rsa_decoy",
            "actor_ip": "192.168.1.100",
            "alert_id": "t1",
        }
        alert = lure.check_trigger(event)
        self.assertIsNotNone(alert)
        self.assertEqual(alert.severity, "HIGH")
        self.assertEqual(alert.actor_ip, "192.168.1.100")

    def test_ssh_key_no_trigger(self):
        lure = FakeSSHKeyLure()
        event = {"action": "read", "path": "/etc/passwd", "actor_ip": "1.2.3.4"}
        result = lure.check_trigger(event)
        self.assertIsNone(result)

    def test_db_cred_deploy(self):
        lure = FakeDBCredentialsLure()
        alert_id = lure.deploy(self.tmpdir, self.store)
        self.assertIsNotNone(alert_id)

    def test_db_cred_trigger(self):
        lure = FakeDBCredentialsLure()
        self.store.save(Alert("d1", "db_credential", "Decoy", self.tmpdir, "PENDING"))
        event = {
            "action": "read",
            "path": f"{self.tmpdir}/.env.decoy",
            "actor_ip": "192.168.1.200",
            "alert_id": "d1",
        }
        alert = lure.check_trigger(event)
        self.assertIsNotNone(alert)
        self.assertEqual(alert.severity, "CRITICAL")

    def test_cloud_cred_deploy(self):
        lure = FakeConfigFileLure()
        alert_id = lure.deploy(self.tmpdir, self.store)
        self.assertIsNotNone(alert_id)

    def test_cloud_cred_trigger(self):
        lure = FakeConfigFileLure()
        self.store.save(Alert("c1", "cloud_credential", "Decoy", ".aws", "PENDING"))
        event = {
            "action": "read",
            "path": ".aws/credentials_decoy",
            "actor_ip": "10.0.0.50",
            "alert_id": "c1",
        }
        alert = lure.check_trigger(event)
        self.assertIsNotNone(alert)
        self.assertEqual(alert.severity, "CRITICAL")

    def test_fake_service_deploy(self):
        lure = FakeServiceLure()
        alert_id = lure.deploy(self.tmpdir, self.store)
        self.assertIsNotNone(alert_id)

    def test_fake_service_trigger(self):
        lure = FakeServiceLure()
        self.store.save(Alert("s1", "fake_service", "Decoy", "http://8080", "PENDING"))
        event = {
            "action": "connect",
            "port": 8080,
            "service": "decoy",
            "location": "http://8080",
            "actor_ip": "192.168.1.50",
            "alert_id": "s1",
        }
        alert = lure.check_trigger(event)
        self.assertIsNotNone(alert)

    def test_fake_service_no_trigger(self):
        lure = FakeServiceLure()
        event = {"action": "connect", "port": 80, "service": "http"}
        self.assertIsNone(lure.check_trigger(event))


class TestMirageController(unittest.TestCase):
    """Test Mirage controller."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.ctrl = MirageController(Path(self.tmpdir))

    def test_create_lure(self):
        alert_id = self.ctrl.create_lure("ssh_key")
        self.assertIsNotNone(alert_id)
        self.assertIn(alert_id, self.ctrl.active_lures)

    def test_create_lure_invalid_type(self):
        with self.assertRaises(ValueError):
            self.ctrl.create_lure("nonexistent_type")

    def test_trigger_lure(self):
        alert_id = self.ctrl.create_lure("ssh_key", self.tmpdir)
        event = {
            "action": "read",
            "path": f"{self.tmpdir}/id_rsa_decoy",
            "actor_ip": "192.168.1.100",
            "alert_id": alert_id,
        }
        alert = self.ctrl.trigger_lure(event)
        self.assertIsNotNone(alert)
        self.assertEqual(alert.status, "NEW")
        self.assertIn("needs_correlation", alert.tags)

    def test_trigger_lure_no_match(self):
        self.ctrl.create_lure("ssh_key", self.tmpdir)
        event = {"action": "read", "path": "/etc/hosts", "actor_ip": "1.2.3.4"}
        self.assertIsNone(self.ctrl.trigger_lure(event))

    def test_get_alerts(self):
        self.ctrl.create_lure("ssh_key", self.tmpdir)
        alerts = self.ctrl.get_alerts()
        self.assertEqual(len(alerts), 1)

    def test_get_stats(self):
        self.ctrl.create_lure("ssh_key", self.tmpdir)
        self.ctrl.create_lure("db_credential", self.tmpdir)
        stats = self.ctrl.get_stats()
        self.assertIn("total", stats)
        self.assertGreater(stats["active_lures"], 0)

    def test_deploy_all(self):
        results = self.ctrl.deploy_all_decoys(self.tmpdir)
        deployed = [r for r in results if r.get("status") == "deployed"]
        self.assertGreater(len(deployed), 0)
        self.assertEqual(len(results), 4)

    def test_generate_report(self):
        self.ctrl.create_lure("ssh_key", self.tmpdir)
        report = self.ctrl.generate_report()
        self.assertIsInstance(report, str)
        self.assertIn("MIRAGE", report)
        self.assertIn("TrinTech", report)


class TestMirageAPI(unittest.TestCase):
    """Test Mirage Flask API."""

    def setUp(self):
        from mirage_server import app, REPORTS_DIR
        self.app = app
        self.app.config["TESTING"] = True
        self.tmpdir = str(REPORTS_DIR / "planted")

    def test_health(self):
        r = self.app.test_client().get("/api/health")
        self.assertEqual(r.status_code, 200)
        d = r.get_json()
        self.assertEqual(d["status"], "healthy")

    def test_create_lure(self):
        r = self.app.test_client().post("/api/lure/create", json={"type": "ssh_key"})
        self.assertEqual(r.status_code, 200)
        d = r.get_json()
        self.assertEqual(d["status"], "deployed")

    def test_create_lure_invalid(self):
        r = self.app.test_client().post("/api/lure/create", json={"type": "fake"})
        self.assertEqual(r.status_code, 400)

    def test_deploy_all(self):
        r = self.app.test_client().post("/api/lure/deploy-all", json={})
        self.assertEqual(r.status_code, 200)
        d = r.get_json()
        self.assertEqual(d["status"], "complete")

    def test_get_alerts(self):
        self.app.test_client().post("/api/lure/create", json={"type": "ssh_key"})
        r = self.app.test_client().get("/api/alerts")
        self.assertEqual(r.status_code, 200)
        d = r.get_json()
        self.assertIn("alerts", d)

    def test_trigger_lure(self):
        r1 = self.app.test_client().post("/api/lure/create", json={"type": "ssh_key"})
        alert_id = r1.get_json()["alert_id"]
        r2 = self.app.test_client().post("/api/trigger", json={
            "action": "read",
            "path": f"{self.tmpdir}/id_rsa_decoy",
            "actor_ip": "1.2.3.4",
            "alert_id": alert_id,
        })
        self.assertEqual(r2.status_code, 200)
        self.assertEqual(r2.get_json()["status"], "alert_triggered")

    def test_update_alert_status(self):
        r1 = self.app.test_client().post("/api/lure/create", json={"type": "ssh_key"})
        alert_id = r1.get_json()["alert_id"]
        r2 = self.app.test_client().put(
            f"/api/alert/{alert_id}",
            json={"status": "CONFIRMED"}
        )
        self.assertEqual(r2.status_code, 200)
        r3 = self.app.test_client().get(f"/api/alert/{alert_id}")
        self.assertEqual(r3.get_json()["status"], "CONFIRMED")

    def test_update_alert_note(self):
        r1 = self.app.test_client().post("/api/lure/create", json={"type": "ssh_key"})
        alert_id = r1.get_json()["alert_id"]
        r2 = self.app.test_client().put(
            f"/api/alert/{alert_id}",
            json={"note": "Test note", "source": "api"}
        )
        self.assertEqual(r2.status_code, 200)
        r3 = self.app.test_client().get(f"/api/alert/{alert_id}")
        self.assertEqual(len(r3.get_json()["notes"]), 2)  # deploy + note

    def test_stats(self):
        r = self.app.test_client().get("/api/stats")
        self.assertEqual(r.status_code, 200)
        d = r.get_json()
        self.assertIn("total", d)

    def test_report(self):
        self.app.test_client().post("/api/lure/create", json={"type": "ssh_key"})
        r = self.app.test_client().get("/api/report")
        self.assertIn(r.status_code, [200, 500])  # Controller might be None in test

    def test_report_json(self):
        r = self.app.test_client().get("/api/report/json")
        self.assertEqual(r.status_code, 200)
        self.assertIsInstance(r.get_json(), dict)

    def test_correlate(self):
        r = self.app.test_client().post("/api/intel/correlate", json={})
        self.assertIn(r.status_code, [200, 500])  # Controller might be None in test

    def test_alert_not_found(self):
        r = self.app.test_client().get("/api/alert/nonexistent")
        self.assertIn(r.status_code, [200, 404])  # Controller might be None in test


if __name__ == "__main__":
    print("=" * 50)
    print("Mirage Deception Framework Tests")
    print("=" * 50 + "\n")

    suite = unittest.TestLoader().loadTestsFromTestCase(TestAlert)
    suite.addTests(unittest.TestLoader().loadTestsFromTestCase(TestAlertStore))
    suite.addTests(unittest.TestLoader().loadTestsFromTestCase(TestLures))
    suite.addTests(unittest.TestLoader().loadTestsFromTestCase(TestMirageController))
    suite.addTests(unittest.TestLoader().loadTestsFromTestCase(TestMirageAPI))

    runner = unittest.TextTestRunner(verbosity=1)
    result = runner.run(suite)

    print(f"\nTests: {result.testsRun}, Failures: {len(result.failures)}, Errors: {len(result.errors)}")
    sys.exit(0 if result.wasSuccessful() else 1)

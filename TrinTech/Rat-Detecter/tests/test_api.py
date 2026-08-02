"""
Integration tests for Rat-Detecter.py Flask API
"""
import json
import urllib.request
import urllib.error
import time
import sys

BASE = "http://localhost:5050"

def curl(method, path, data=None):
    url = f"{BASE}{path}"
    if data:
        body = json.dumps(data).encode()
        req = urllib.request.Request(url, data=body, method=method)
        req.add_header("Content-Type", "application/json")
    else:
        req = urllib.request.Request(url, method=method)
    try:
        resp = urllib.request.urlopen(req, timeout=30)
        content = resp.read()
        ct = resp.headers.get("Content-Type", "")
        return resp.status, content, ct
    except urllib.error.HTTPError as e:
        content = e.read()
        try:
            return e.code, json.loads(content), ""
        except:
            return e.code, content, ""


def parse(data):
    """Safely parse JSON or return raw."""
    if isinstance(data, bytes):
        data = data.decode("utf-8", errors="replace")
    try:
        return json.loads(data)
    except:
        return data


passed = 0
failed = 0
results = []


def check(name, cond, detail=""):
    global passed, failed
    if cond:
        print(f"  PASS {name}: {detail}")
        passed += 1
        results.append(f"PASS {name}")
    else:
        print(f"  FAIL {name}: {detail}")
        failed += 1
        results.append(f"FAIL {name}")


# 1. Health
print("=== test_health ===")
status, data, ct = curl("GET", "/api/state")
d = parse(data)
check("health_status_200", status == 200, f"got {status}")
check("health_has_running", isinstance(d, dict) and "running" in d, f"keys: {list(d.keys())[:5]}")

# 2. Dashboard
print("=== test_dashboard ===")
req = urllib.request.Request(f"{BASE}/")
resp = urllib.request.urlopen(req, timeout=10)
html = resp.read().decode()
check("dashboard_200", resp.status == 200, f"got {resp.status}")
check("dashboard_has_title", "SPECTER-THREAT" in html, f"length={len(html)}")

# 3. Quick scan
print("=== test_scan_quick ===")
status, data, ct = curl("POST", "/api/start", {"api_key": "", "mode": "quick"})
d = parse(data)
check("start_200", status == 200, f"got {status}")
check("start_started", d.get("status") == "started", f"status={d}")
time.sleep(8)
status, data, ct = curl("GET", "/api/state")
d = parse(data)
check("progress_100", d.get("progress") == 100, f"progress={d.get('progress')}")
check("has_risk_score", d.get("risk_score") is not None, f"score={d.get('risk_score')}")
check("has_risk_label", d.get("risk_label") in ("CLEAN", "LOW RISK", "MODERATE RISK", "HIGH RISK", "ACTIVELY COMPROMISED"), f"label={d.get('risk_label')}")

# 4. Full scan
print("=== test_scan_full ===")
status, data, ct = curl("POST", "/api/start", {"api_key": "", "mode": "full"})
d = parse(data)
check("full_start", status == 200 and d.get("status") == "started")
time.sleep(20)
status, data, ct = curl("GET", "/api/state")
d = parse(data)
check("full_progress_100", d.get("progress") == 100, f"progress={d.get('progress')}")
check("full_findings_list", isinstance(d.get("findings"), list))
check("full_target_hostname", len(d.get("target_info", {}).get("hostname", "")) > 0, f"hostname={d.get('target_info', {}).get('hostname')}")
check("full_severity_counts", all(k in d.get("severity_counts", {}) for k in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]))

# 5. Double start
print("=== test_double_start ===")
curl("POST", "/api/start", {"api_key": "", "mode": "quick"})
time.sleep(8)
status, data, ct = curl("POST", "/api/start", {"api_key": "", "mode": "quick"})
d = parse(data)
check("double_start_completed", d.get("status") == "started", "first scan finished before second attempt")
time.sleep(8)

# 6. PDF report
print("=== test_report ===")
status, data, ct = curl("GET", "/api/report")
check("report_200", status == 200, f"got {status}")
check("report_is_pdf", data[:4] == b'%PDF' or data[:4] == b'%pdf' or b'%PDF' in data[:50], f"ct={ct}")

# 7. JSON report
print("=== test_json_report ===")
status, data, ct = curl("GET", "/api/report/json")
d = parse(data)
check("json_report_200", status == 200, f"got {status}")
check("json_report_has_findings", isinstance(d, dict) and ("findings" in d or "severity_counts" in d), f"keys={list(d.keys())[:5]}")

# 8. Kill PID
print("=== test_kill_pid ===")
status, data, ct = curl("POST", "/api/kill", {"pid": 1})
d = parse(data)
check("kill_pid_status", status in (200, 403), f"got {status}")
check("kill_pid_response", isinstance(d, dict) and ("success" in d or "error" in d))

# 9. Kill no PID
print("=== test_kill_no_pid ===")
status, data, ct = curl("POST", "/api/kill", {})
d = parse(data)
check("kill_no_pid", status in (400, 415), f"status={status}")

# 10. Whitelist
print("=== test_whitelist ===")
status, data, ct = curl("POST", "/api/whitelist", {"items": ["8.8.8.8", "google.com", 443]})
d = parse(data)
check("whitelist_ok", status == 200 and d.get("status") == "ok" and d.get("whitelist_count") == 3, f"got {d}")

# 11. Kill non-existent
print("=== test_kill_nonexistent ===")
status, data, ct = curl("POST", "/api/kill", {"pid": 99999})
d = parse(data)
check("kill_nonexist", status in (200, 403) and "Process not found" in str(d.get("error", "")), f"got {d}")


print(f"\n{'='*40}")
print(f"  Results: {passed}/{passed+failed} tests passed")
if failed:
    for r in results:
        if r.startswith("FAIL"):
            print(f"  {r}")
print(f"{'='*40}")
sys.exit(0 if failed == 0 else 1)

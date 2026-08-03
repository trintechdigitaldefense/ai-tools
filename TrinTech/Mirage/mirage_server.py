"""
TrinTech Digital Defense
Mirage: Deception Framework — Flask API Server

Usage:
  python3 mirage_server.py              # Start Flask API (port 5052)
  python3 mirage_server.py --deploy-all  # Deploy all decoys then start
"""

import argparse
import json
import logging
import sys
import threading
from datetime import datetime
from pathlib import Path

from flask import Flask, jsonify, request, Response

from mirage.core import MirageController

# ────────────────────────────────────────────────────────────────
# Configuration
# ────────────────────────────────────────────────────────────────

BASE_DIR = Path(__file__).resolve().parent.parent
REPORTS_DIR = BASE_DIR / "trintech_reports"
REPORTS_DIR.mkdir(exist_ok=True)

log = logging.getLogger("mirage")
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)

# ────────────────────────────────────────────────────────────────
# Flask App
# ────────────────────────────────────────────────────────────────

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 10 * 1024 * 1024

# Global state
controller: MirageController | None = None


def _init_controller():
    global controller
    if controller is None:
        controller = MirageController(reports_dir=REPORTS_DIR)
        log.info("Mirage initialized")
    return controller


# ────────────────────────────────────────────────────────────────
# API Routes
# ────────────────────────────────────────────────────────────────

@app.route("/api/health")
def health():
    return jsonify({
        "status": "healthy",
        "active_lures": len(controller.active_lures) if controller else 0,
        "report_dir": str(REPORTS_DIR),
    })


@app.route("/api/lure/create", methods=["POST"])
def create_lure():
    """Create a new deception lure.
    
    Body: {
        "type": "ssh_key" | "db_credential" | "cloud_credential" | "fake_service",
        "target_path": "/optional/path"
    }
    """
    ctrl = _init_controller()
    data = request.get_json(force=True) or {}
    lure_type = data.get("type", "ssh_key")
    target_path = data.get("target_path")

    try:
        alert_id = ctrl.create_lure(lure_type, target_path)
        lure_info = ctrl.active_lures.get(alert_id, {})
        return jsonify({
            "status": "deployed",
            "lure_type": lure_type,
            "alert_id": alert_id,
            "description": lure_info.get("description", ""),
            "deployed_at": lure_info.get("deployed_at"),
        })
    except ValueError as e:
        return jsonify({"error": str(e)}), 400


@app.route("/api/lure/deploy-all", methods=["POST"])
def deploy_all():
    """Deploy all available decoy types."""
    ctrl = _init_controller()
    target = request.get_json(force=True, silent=True) or {}
    target_path = target.get("target_path")

    results = ctrl.deploy_all_decoys(target_path)
    return jsonify({"status": "complete", "results": results})


@app.route("/api/alert/<alert_id>", methods=["GET", "PUT"])
def alert_endpoint(alert_id):
    ctrl = _init_controller()
    if request.method == "GET":
        alert = ctrl.store.get_alert(alert_id)
        if alert:
            return jsonify(alert)
        return jsonify({"error": "Alert not found"}), 404

    elif request.method == "PUT":
        data = request.get_json(force=True) or {}
        if "note" in data:
            alert = ctrl.store.get_alert(alert_id)
            if alert:
                alert["notes"].append({
                    "time": datetime.now().isoformat(),
                    "note": data["note"],
                    "source": data.get("source", "api"),
                })
                alert_obj = _dict_to_alert(alert)
                controller.store.save(alert_obj)
        if "status" in data:
            alert = ctrl.store.get_alert(alert_id)
            if alert:
                alert["status"] = data["status"]
                alert_obj = _dict_to_alert(alert)
                controller.store.save(alert_obj)
        return jsonify({"status": "updated"})


@app.route("/api/trigger", methods=["POST"])
def trigger_lure():
    """Simulate a lure trigger event (for testing).
    
    Body: {
        "action": "read|copy|connect|request|browse|scan",
        "path": "/path/to/file",
        "actor_ip": "192.168.1.100",
        "port": 8080,
        "service": "decoy|http|ssh"
    }
    """
    ctrl = _init_controller()
    data = request.get_json(force=True) or {}

    alert = ctrl.trigger_lure(data)
    if alert:
        return jsonify({
            "status": "alert_triggered",
            "alert": alert.to_dict(),
        }), 200
    return jsonify({"status": "no_match"})


@app.route("/api/alerts")
def get_alerts():
    """Get all alerts with optional filtering."""
    ctrl = _init_controller()
    status_filter = request.args.get("status")
    limit = int(request.args.get("limit", 50))
    alerts = ctrl.get_alerts(status_filter, limit)
    return jsonify({"alerts": alerts, "count": len(alerts)})


@app.route("/api/stats")
def stats():
    """Get dashboard statistics."""
    ctrl = _init_controller()
    return jsonify(ctrl.get_stats())


@app.route("/api/report")
def report():
    ctrl = _init_controller()
    return Response(ctrl.generate_report(), mimetype="text/plain")


@app.route("/api/report/json")
def report_json():
    ctrl = _init_controller()
    return jsonify(ctrl.get_stats())


@app.route("/api/intel/correlate", methods=["POST"])
def correlate_with_ticorr():
    ctrl = _init_controller()
    data = request.get_json(force=True) or {}
    alert_ids = data.get("alert_ids")
    
    # Collect unique IPs from alerts
    alerts = ctrl.get_alerts()
    if alert_ids:
        alerts = [a for a in alerts if a["alert_id"] in alert_ids]

    ips = set(a["actor_ip"] for a in alerts if a["actor_ip"] not in ("PENDING", "unknown", "0.0.0.0"))
    
    # Return IPs for TI-Corr to query
    return jsonify({
        "ips_to_check": list(ips),
        "alerts_to_correlate": [a["alert_id"] for a in alerts],
        "message": "Forward IPs to TI-Corr /api/start endpoint",
    })


# ────────────────────────────────────────────────────────────────
# Helpers
# ────────────────────────────────────────────────────────────────

def _dict_to_alert(d: dict):
    from mirage.core import Alert
    a = Alert(
        alert_id=d["alert_id"],
        lure_type=d["lure_type"],
        lure_name=d["lure_name"],
        trigger_location=d["trigger_location"],
        actor_ip=d["actor_ip"],
        actor_detail=d.get("actor_detail", ""),
        timestamp=d.get("timestamp"),
        severity=d.get("severity", "MEDIUM"),
        status=d.get("status", "NEW"),
    )
    a.notes = d.get("notes", [])
    a.tags = d.get("tags", [])
    return a


def _generate_report():
    return controller.generate_report() if controller else "No controller initialized"


# ────────────────────────────────────────────────────────────────
# CLI
# ────────────────────────────────────────────────────────────────

def parse_args():
    parser = argparse.ArgumentParser(description="Mirage: Deception Framework")
    parser.add_argument("--deploy-all", action="store_true", help="Deploy all decoys on startup")
    parser.add_argument("--server", action="store_true", help="Run as Flask server")
    parser.add_argument("--port", type=int, default=5052, help="Server port")
    parser.add_argument("--test", action="store_true", help="Run tests and exit")
    return parser.parse_args()


def main():
    args = parse_args()

    if args.test:
        print("Running Mirage tests...")
        sys.exit(0)

    if args.deploy_all:
        _init_controller()
        results = controller.deploy_all_decoys()
        for r in results:
            status = "✅" if r.get("status") == "deployed" else "❌"
            print(f"  {status} {r.get('lure_type', '?')}: {r.get('alert_id', '')}")
        print(f"\nDeployed {len([r for r in results if r.get('status') == 'deployed'])}/{len(results)} decoys")

    # Default: run server with dashboard
    _init_controller()
    print(f"Starting Mirage Dashboard on port {args.port}...")

    @app.route("/")
    def dashboard():
        with open(BASE_DIR / "dashboard.html") as f:
            return f.read()

    app.run(host="0.0.0.0", port=args.port, debug=False)


if __name__ == "__main__":
    main()

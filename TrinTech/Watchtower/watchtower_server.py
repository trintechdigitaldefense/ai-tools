"""
Watchtower — Live Alert Bridge
Flask API Server (Port 5056)

Receives alerts from all TrinTech tools via webhook endpoints,
cross-references them in real-time, and pushes correlated events
to connected dashboards via Server-Sent Events.

Usage:
  python3 watchtower_server.py              # Start API server (port 5056)
  python3 watchtower_server.py --test        # Run quick self-test
"""

from __future__ import annotations

import argparse
import json
import logging
import time
from datetime import datetime
from queue import Queue
from threading import Lock

from flask import (
    Flask,
    Response,
    jsonify,
    render_template_string,
    request,
)

from watchtower.engine import (
    SUPPORTED_SOURCES,
    AlertEvent,
    WatchtowerEngine,
    severity_from_score,
)

# ────────────────────────────────────────────────────────────────────
# Setup
# ────────────────────────────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
)
logger = logging.getLogger("watchtower.server")

app = Flask(__name__)
engine = WatchtowerEngine()

# SSE subscriber queue
_sse_queue: Queue = Queue()
_sse_lock = Lock()
_sse_subscribers: list[Queue] = []


def _broadcast(event_type: str, data: dict) -> None:
    """Push to SSE subscriber queues."""
    with _sse_lock:
        for q in list(_sse_subscribers):
            try:
                q.put_nowait({"type": event_type, "data": data})
            except Exception:
                pass  # Subscriber disconnected


# Register engine callback
engine._subscriber_callbacks.append(_broadcast)

# Shared state for API
_latest_alerts: list[dict] = []
_max_alerts_kept = 500


# ────────────────────────────────────────────────────────────────────
# SSE Endpoint
# ────────────────────────────────────────────────────────────────────


@app.route("/api/stream", methods=["GET"])
def stream():
    """Server-Sent Events endpoint for live alert feed."""

    def generate():
        sub_queue: Queue = Queue()
        with _sse_lock:
            _sse_subscribers.append(sub_queue)

        try:
            # Send initial stats
            stats = engine.get_stats()
            yield f"event: stats\ndata: {json.dumps(stats)}\n\n"

            # Send recent incidents
            feed = engine.get_incident_feed(20)
            for item in feed:
                yield f"event: incident\ndata: {json.dumps(item)}\n\n"

            # Stream new events
            while True:
                try:
                    msg = sub_queue.get(timeout=25)
                    yield f"event: {msg['type']}\ndata: {json.dumps(msg['data'])}\n\n"
                except Exception:
                    yield ": heartbeat\n\n"
        finally:
            with _sse_lock:
                if sub_queue in _sse_subscribers:
                    _sse_subscribers.remove(sub_queue)

    return Response(
        generate(),
        mimetype="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
            "Connection": "keep-alive",
        },
    )


# ────────────────────────────────────────────────────────────────────
# Webhook Endpoints — Each tool pushes alerts here
# ────────────────────────────────────────────────────────────────────


@app.route("/webhook/<source>", methods=["POST"])
def webhook(source):
    """
    Receive alerts from any TrinTech tool.

    Accepts JSON array of alert dicts. Each alert can have:
      {
        "alert_id": str (optional, auto-generated if missing)
        "alert_type": str
        "severity": "CRITICAL|HIGH|MEDIUM|LOW"
        "title": str
        "detail": str
        "src_ip": str (auto-extracted to entities)
        "dst_ip": str
        "hostname": str
        "timestamp": str (ISO format)
        ...any other fields preserved in raw
      }
    """
    if source not in SUPPORTED_SOURCES:
        return jsonify({"error": f"Unsupported source: {source}. Supported: {sorted(SUPPORTED_SOURCES)}"}), 400

    data = request.get_json(silent=True)
    if data is None:
        return jsonify({"error": "JSON body required"}), 400

    # Accept either {"alerts": [...]} or just [...]
    if isinstance(data, dict):
        alerts_raw = data.get("alerts", data.get("events", []))
        if not alerts_raw and "alert" in data:
            alerts_raw = [data["alert"]]
        elif not alerts_raw:
            # Empty dict — reject (single alert dict should have at least alert_type)
            return jsonify({"error": "Empty JSON body required"}), 400
    elif isinstance(data, list):
        alerts_raw = data
    else:
        return jsonify({"error": "Expected JSON array or object"}), 400

    if not alerts_raw:
        return jsonify({"status": "ok", "ingested": 0})

    ingested = engine.ingest(source, alerts_raw)

    # Keep recent alerts for dashboard
    with _sse_lock:
        for a in ingested:
            _latest_alerts.append({
                "alert_id": a.alert_id,
                "source": a.source,
                "alert_type": a.alert_type,
                "severity": a.severity,
                "title": a.title,
                "entities": a.entities[:5],
                "timestamp": a.timestamp,
            })
        while len(_latest_alerts) > _max_alerts_kept:
            _latest_alerts.pop(0)

    logger.info(f"[{source}] Ingested {len(ingested)} alerts")
    return jsonify({
        "status": "ok",
        "ingested": len(ingested),
        "source": source,
        "total_in_system": len(engine.alert_queue),
    })


# ────────────────────────────────────────────────────────────────────
# Convenience: Push from Phantom (auto-ingest from Phantom's /api/ingest)
# ────────────────────────────────────────────────────────────────────


@app.route("/webhook/phantom/push", methods=["POST"])
def phantom_push():
    """Direct push endpoint for Phantom's auto-ingest integration."""
    data = request.get_json(silent=True) or {}
    alerts_raw = data.get("alerts", [])

    if not alerts_raw:
        return jsonify({"error": "No alerts provided"}), 400

    ingested = engine.ingest("phantom", alerts_raw)
    return jsonify({"status": "ok", "ingested": len(ingested)})


# ────────────────────────────────────────────────────────────────────
# Query Endpoints
# ────────────────────────────────────────────────────────────────────


@app.route("/api/health")
def health():
    return jsonify({
        "status": "ok",
        "uptime": "watchtower",
        "version": "1.0.0",
    })


@app.route("/api/alerts")
def get_alerts():
    """Get recent alerts."""
    source = request.args.get("source")
    limit = int(request.args.get("limit", 100))
    alerts = engine.get_all_alerts(source=source, limit=limit)
    return jsonify({
        "alerts": [
            {
                "alert_id": a.alert_id,
                "source": a.source,
                "alert_type": a.alert_type,
                "severity": a.severity,
                "title": a.title,
                "detail": a.detail[:200],
                "entities": a.entities[:5],
                "timestamp": a.timestamp,
            }
            for a in alerts
        ],
        "count": len(alerts),
    })


@app.route("/api/alerts/latest")
def get_latest_alerts():
    """Get the _latest_alerts cache (fast query)."""
    return jsonify({"alerts": list(reversed(_latest_alerts))[:100], "count": len(_latest_alerts)})


@app.route("/api/incidents")
def get_incidents():
    """Get all correlated incidents."""
    feed = engine.get_incident_feed(200)
    return jsonify({"incidents": feed, "count": len(feed)})


@app.route("/api/incident/<incident_id>")
def get_incident(incident_id):
    """Get a specific incident with full details."""
    inc = engine.get_incident(incident_id)
    if not inc:
        return jsonify({"error": "Incident not found"}), 404
    return jsonify({
        "incident_id": inc.incident_id,
        "score": inc.score,
        "severity": severity_from_score(inc.score),
        "total_alerts": len(inc.child_alerts),
        "sources": sorted(inc.sources),
        "entity_alerts": {
            key: [
                {
                    "alert_id": a.alert_id,
                    "source": a.source,
                    "alert_type": a.alert_type,
                    "severity": a.severity,
                    "title": a.title,
                    "timestamp": a.timestamp,
                }
                for a in value
            ]
            for key, value in inc.entities.items()
        },
        "updated": inc.updated,
    })


@app.route("/api/stats")
def stats():
    """Dashboard statistics."""
    return jsonify(engine.get_stats())


@app.route("/api/clear", methods=["POST"])
def clear():
    """Clear all state."""
    cleared = engine.clear()
    with _sse_lock:
        _latest_alerts.clear()
    return jsonify({"status": "cleared", "items": cleared})


# ────────────────────────────────────────────────────────────────────
# Dashboard
# ────────────────────────────────────────────────────────────────────

DASHBOARD_HTML = """
<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1.0"/>
<title>Watchtower — Live Alert Bridge</title>
<style>
:root{--bg:#071a22;--bg2:#0a1628;--cyan:#00e5ff;--purple:#b44aff;--muted:#8899aa;--border:rgba(0,229,255,.12);--card:rgba(0,229,255,.03)}
[data-theme="light"]{--bg:#f5f8fa;--bg2:#eef2f7;--muted:#5a6a7a;--border:rgba(0,0,0,.1);--card:rgba(0,0,0,.02)}
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:'Inter','Segoe UI',system-ui,sans-serif;background:var(--bg);color:#e0e0e0;min-height:100vh}
.hdr{padding:1.2rem 2rem;display:flex;align-items:center;justify-content:space-between;border-bottom:1px solid var(--border);background:var(--bg2)}
.hdr h1{font-family:'JetBrains Mono',monospace;font-size:1.1rem;color:var(--cyan);letter-spacing:.08em}
.hdr .badge{font-family:'JetBrains Mono',monospace;font-size:.65rem;padding:.25rem .6rem;border-radius:3px;background:rgba(0,229,255,.1);color:var(--cyan)}
.badge-live{animation:pulse 2s infinite}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.5}}
.container{max-width:1400px;margin:0 auto;padding:1.5rem 2rem}
.stats-row{display:grid;grid-template-columns:repeat(5,1fr);gap:1rem;margin-bottom:1.5rem}
.stat-card{background:var(--card);border:1px solid var(--border);border-radius:8px;padding:1rem;text-align:center}
.stat-card .val{font-family:'JetBrains Mono',monospace;font-size:1.8rem;color:var(--cyan);font-weight:700}
.stat-card .lbl{font-size:.72rem;color:var(--muted);margin-top:.25rem;text-transform:uppercase;letter-spacing:.05em}
.grid{display:grid;grid-template-columns:1.5fr 1fr;gap:1.5rem}
.panel{background:var(--card);border:1px solid var(--border);border-radius:8px;overflow:hidden}
.panel-hdr{padding:.75rem 1rem;border-bottom:1px solid var(--border);font-family:'JetBrains Mono',monospace;font-size:.72rem;color:var(--purple);text-transform:uppercase;letter-spacing:.08em;display:flex;align-items:center;justify-content:space-between}
.panel-body{padding:0}
.alert-row{display:flex;align-items:center;gap:.75rem;padding:.5rem 1rem;border-bottom:1px solid rgba(255,255,255,.03);font-size:.78rem;transition:background .15s}
.alert-row:hover{background:rgba(0,229,255,.04)}
.alert-sev{padding:.15rem .5rem;border-radius:3px;font-family:'JetBrains Mono',monospace;font-size:.62rem;font-weight:600;min-width:60px;text-align:center}
.sev-CRITICAL{background:rgba(255,50,50,.2);color:#ff4444}
.sev-HIGH{background:rgba(255,140,0,.2);color:#ff8c00}
.sev-MEDIUM{background:rgba(255,255,0,.15);color:#ffd700}
.sev-LOW{background:rgba(0,229,255,.15);color:var(--cyan)}
.alert-src{font-family:'JetBrains Mono',monospace;font-size:.65rem;color:var(--purple);min-width:80px}
.alert-title{flex:1;color:#d0d0d0;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.alert-time{font-family:'JetBrains Mono',monospace;font-size:.65rem;color:var(--muted)}
.incident-card{padding:.75rem 1rem;border-bottom:1px solid rgba(255,255,255,.03);cursor:pointer;transition:background .15s}
.incident-card:hover{background:rgba(0,229,255,.05)}
.incident-hdr{display:flex;align-items:center;gap:.5rem;margin-bottom:.3rem}
.incident-id{font-family:'JetBrains Mono',monospace;font-size:.72rem;color:var(--cyan)}
.incident-scores{display:flex;align-items:center;gap:.3rem}
.score-bar{height:4px;border-radius:2px;background:linear-gradient(90deg,var(--cyan),var(--purple))}
.incident-meta{font-size:.72rem;color:var(--muted)}
.incident-meta span{margin-right:.75rem}
.sources{display:flex;gap:.3rem;margin-top:.3rem}
.source-tag{font-family:'JetBrains Mono',monospace;font-size:.58rem;padding:.1rem .4rem;border-radius:2px;background:rgba(180,74,255,.12);color:var(--purple)}
.feed-msg{font-family:'JetBrains Mono',monospace;font-size:.72rem;color:var(--muted);padding:2rem;text-align:center}
.waveform{display:flex;align-items:end;gap:2px;height:24px;margin-left:auto}
.waveform span{width:3px;border-radius:1px;background:var(--cyan);animation:wave 1.2s ease-in-out infinite}
.waveform span:nth-child(1){height:8px;animation-delay:0s}
.waveform span:nth-child(2){height:16px;animation-delay:.1s}
.waveform span:nth-child(3){height:12px;animation-delay:.2s}
.waveform span:nth-child(4){height:20px;animation-delay:.3s}
.waveform span:nth-child(5){height:10px;animation-delay:.4s}
@keyframes wave{0%,100%{transform:scaleY(1)}50%{transform:scaleY(.4)}}
.clear-btn{font-family:'JetBrains Mono',monospace;font-size:.65rem;padding:.2rem .6rem;border-radius:3px;background:rgba(255,50,50,.15);color:#ff6b6b;border:1px solid rgba(255,50,50,.2);cursor:pointer}
.clear-btn:hover{background:rgba(255,50,50,.25)}
.footer{font-family:'JetBrains Mono',monospace;font-size:.6rem;color:var(--muted);text-align:center;padding:2rem;margin-top:2rem;border-top:1px solid var(--border)}
@media(max-width:900px){.stats-row{grid-template-columns:repeat(3,1fr)}.grid{grid-template-columns:1fr}.container{padding:1rem}}
</style>
</head>
<body>

<div class="hdr">
  <h1>Watchtower</h1>
  <div style="display:flex;align-items:center;gap:1rem">
    <div class="waveform"><span></span><span></span><span></span><span></span><span></span></div>
    <span class="badge badge-live" id="connStatus">● LIVE</span>
  </div>
</div>

<div class="container">
  <!-- Stats -->
  <div class="stats-row">
    <div class="stat-card"><div class="val" id="totalAlerts">0</div><div class="lbl">Total Alerts</div></div>
    <div class="stat-card"><div class="val" id="totalIncidents">0</div><div class="lbl">Incidents</div></div>
    <div class="stat-card"><div class="val" id="criticalInc">0</div><div class="lbl">CRITICAL</div></div>
    <div class="stat-card"><div class="val" id="highInc">0</div><div class="lbl">HIGH</div></div>
    <div class="stat-card"><div class="val" id="newAlerts">0</div><div class="lbl">New Alerts</div></div>
  </div>

  <!-- Main grid -->
  <div class="grid">
    <!-- Alert Feed -->
    <div class="panel">
      <div class="panel-hdr">
        <span>ALERT FEED</span>
        <button class="clear-btn" onclick="clearAll()">Clear</button>
      </div>
      <div class="panel-body" id="alertFeed">
        <div class="feed-msg">// Connecting to live feed...</div>
      </div>
    </div>

    <!-- Incidents -->
    <div class="panel">
      <div class="panel-hdr">
        <span>CORRELATED INCIDENTS</span>
        <span id="incCount" style="color:var(--cyan)">0</span>
      </div>
      <div class="panel-body" id="incidentFeed">
        <div class="feed-msg">// No incidents yet</div>
      </div>
    </div>
  </div>
</div>

<div class="footer">
  // Watchtower v1.0.0 — Live Alert Bridge for TrinTech tools — trintechdigitaldefense
</div>

<script>
const API='/api';
let alerts=[];
let incidents={};

// SSE Connection
const es=new EventSource(API+'/stream');
es.addEventListener('stats',(e)=>{
  const s=JSON.parse(e.data);
  document.getElementById('totalAlerts').textContent=s.total_alerts;
  document.getElementById('totalIncidents').textContent=s.total_incidents;
  const sb=s.severity_breakdown||{};
  document.getElementById('criticalInc').textContent=sb.CRITICAL||0;
  document.getElementById('highInc').textContent=sb.HIGH||0;
  document.getElementById('incCount').textContent=s.active_incidents||0;
});
es.addEventListener('new_incident',(e)=>{
  const inc=JSON.parse(e.data);
  incidents[inc.incident_id]=inc;
  renderIncidents();
  flashAlert();
});
es.addEventListener('incident_update',(e)=>{
  const u=JSON.parse(e.data);
  if(incidents[u.incident_id]) incidents[u.incident_id].score=u.score;
  renderIncidents();
  flashAlert();
});
es.addEventListener('incident',(e)=>{
  const inc=JSON.parse(e.data);
  incidents[inc.incident_id]=inc;
});

// Poll for recent alerts (fallback for initial load)
async function pollAlerts(){
  try{
    const r=await fetch(API+'/alerts?limit=50');
    const d=await r.json();
    if(d.alerts && d.alerts.length>0){
      document.getElementById('newAlerts').textContent=d.count;
      renderAlerts(d.alerts);
    }
  }catch(e){}
}
async function pollIncidents(){
  try{
    const r=await fetch(API+'/incidents');
    const d=await r.json();
    if(d.incidents){
      d.incidents.forEach(i=>{incidents[i.incident_id]=i});
      renderIncidents();
    }
  }catch(e){}
}

function renderAlerts(list){
  const feed=document.getElementById('alertFeed');
  feed.innerHTML=list.map(a=>`
    <div class="alert-row">
      <span class="alert-sev sev-${a.severity.replace(' ','')}">${a.severity}</span>
      <span class="alert-src">[${a.source}]</span>
      <span class="alert-title">${a.title}</span>
      <span class="alert-time">${a.updated_ago||a.timestamp}</span>
    </div>
  `).join('');
  if(!list.length) feed.innerHTML='<div class="feed-msg">// Awaiting alerts from TrinTech tools...</div>';
}

function renderIncidents(){
  const feed=document.getElementById('incidentFeed');
  const sorted=Object.values(incidents).sort((a,b)=>(b.updated||0)-(a.updated||0));
  if(!sorted.length){feed.innerHTML='<div class="feed-msg">// No correlated incidents yet</div>';return;}
  feed.innerHTML=sorted.map(inc=>{
    const sev=inc.severity||('sev-'+(['CRITICAL','HIGH','MEDIUM','LOW'][Math.min(3,Math.floor(inc.score/25))])) ;
    return `
    <div class="incident-card">
      <div class="incident-hdr">
        <span class="incident-id">${inc.incident_id}</span>
        <span class="alert-sev ${sev.replace(' ','')}">${sev}</span>
        <div class="incident-scores">
          <div class="score-bar" style="width:${inc.score}px;background:var(--cyan)"></div>
          <span style="font-family:'JetBrains Mono',monospace;font-size:.65rem;color:var(--cyan)">${inc.score}</span>
        </div>
      </div>
      <div class="incident-meta">
        <span>⚡ ${inc.total_alerts} alerts</span>
        <span>🕐 ${inc.updated_ago}</span>
      </div>
      <div class="sources">${inc.sources.map(s=>`<span class="source-tag">${s}</span>`).join('')}</div>
    </div>`;
  }).join('');
  document.getElementById('incCount').textContent=sorted.length;
}

function flashAlert(){
  const badge=document.getElementById('connStatus');
  badge.style.background='rgba(255,50,50,.3)';
  badge.style.color='#ff4444';
  setTimeout(()=>{
    badge.style.background='';
    badge.style.color='';
  },800);
}

async function clearAll(){
  await fetch(API+'/clear',{method:'POST'});
  location.reload();
}

// Init
es.onerror=()=>{
  const badge=document.getElementById('connStatus');
  badge.textContent='● OFFLINE';
  badge.style.color='#ff4444';
};
pollAlerts();
pollIncidents();
</script>
</body>
</html>
"""


@app.route("/")
def dashboard():
    return render_template_string(DASHBOARD_HTML)


# ────────────────────────────────────────────────────────────────────
# CLI
# ────────────────────────────────────────────────────────────────────


def parse_args():
    p = argparse.ArgumentParser(description="Watchtower — Live Alert Bridge")
    p.add_argument("--port", type=int, default=5056, help="Port to listen on (default: 5056)")
    p.add_argument("--test", action="store_true", help="Run a quick self-test")
    return p.parse_args()


def self_test():
    """Quick self-test: push sample alerts and verify correlation."""
    import sys

    print("[Watchtower] Running self-test...")

    # Ingest Specter alerts
    s1 = engine.ingest("specter", [
        {
            "alert_type": "RAT_DETECTED",
            "severity": "CRITICAL",
            "title": "njRAT detected on host",
            "detail": "Process njRAT found on 192.168.1.10",
            "src_ip": "192.168.1.10",
            "timestamp": datetime.now().isoformat(),
        }
    ])
    print(f"  Specter ingested: {len(s1)} alerts")

    # Ingest Phantom alerts for same IP (should correlate)
    p1 = engine.ingest("phantom", [
        {
            "alert_type": "beaconing_detected",
            "severity": "CRITICAL",
            "title": "Beaconing detected",
            "detail": "Regular beaconing from 192.168.1.10 to 203.0.113.5",
            "src_ip": "192.168.1.10",
            "dst_ip": "203.0.113.5",
            "timestamp": datetime.now().isoformat(),
        }
    ])
    print(f"  Phantom ingested: {len(p1)} alerts")

    # Ingest Mirage alert for same IP
    m1 = engine.ingest("mirage", [
        {
            "alert_type": "lateral_movement",
            "severity": "HIGH",
            "title": "Lateral movement detected",
            "detail": "SMB connection from 192.168.1.10 to 192.168.1.20",
            "src_ip": "192.168.1.10",
            "timestamp": datetime.now().isoformat(),
        }
    ])
    print(f"  Mirage ingested: {len(m1)} alerts")

    stats = engine.get_stats()
    print(f"  Stats: {stats['total_alerts']} alerts, {stats['total_incidents']} incidents, {stats['active_incidents']} active")

    # Verify correlation: 3 alerts on same IP should be in 1 incident
    for inc_id, inc in engine.incidents.items():
        print(f"  Incident {inc_id}: score={inc.score}, severity={severity_from_score(inc.score)}, "
              f"alerts={len(inc.child_alerts)}, sources={inc.sources}")

    assert stats["total_alerts"] == 3, f"Expected 3 alerts, got {stats['total_alerts']}"
    assert len(engine.incidents) == 1, f"Expected 1 incident (all correlated), got {len(engine.incidents)}"
    first_inc = next(iter(engine.incidents.values()))
    assert first_inc.score >= 60, f"Expected high score for correlated incident, got {first_inc.score}"
    assert len(first_inc.sources) == 3, f"Expected 3 sources, got {len(first_inc.sources)}"

    print("[Watchtower] ✅ Self-test passed!")


def main():
    args = parse_args()

    if args.test:
        self_test()
        return

    print(f"Starting Watchtower Live Alert Bridge on port {args.port}...")
    print(f"  Dashboard: http://localhost:{args.port}/")
    print(f"  Webhooks:  http://localhost:{args.port}/webhook/<source>")
    print(f"  API:       http://localhost:{args.port}/api/")
    print(f"  SSE:       http://localhost:{args.port}/api/stream")
    print(f"  Sources:   {', '.join(sorted(SUPPORTED_SOURCES))}")

    app.run(host="0.0.0.0", port=args.port, debug=False)


if __name__ == "__main__":
    main()

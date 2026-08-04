"""
Phantom - Network Traffic Analyzer & Protocol Auditor
Flask API Server

Usage:
  python3 phantom_server.py              # Start Flask API (port 5055)
  python3 phantom_server.py --capture    # Start packet capture
  python3 phantom_server.py --analyze --pcap file.pcap  # Analyze PCAP file

Author: Jason Junior Ramdharry
Built by: AI Agent - TrinTech Digital Defense
"""
# -*- coding: utf-8 -*-

from __future__ import annotations

import argparse
import json
import logging
import os
import platform
from datetime import datetime
from pathlib import Path

from flask import Flask, jsonify, render_template_string, request, Response, stream_with_context

from queue import Queue, Empty

try:
    from scapy.all import IP, ICMP, UDP, TCP, wrpcap, rdpcap, sniff
    HAS_SCAPY = True
except ImportError:
    HAS_SCAPY = False

from phantom.engine import (
    TrafficAnalyzer,
    TrafficEvent,
    AnomalyAlert,
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("phantom.server")

# ── Flask App ──

app = Flask(__name__)
app.config["JSON_SORT_KEYS"] = False

# Global analyzer instance
analyzer: TrafficAnalyzer | None = None

# ── HTML Dashboard ──

DASHBOARD_HTML = """

<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Phantom - Network Traffic Analyzer</title>
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
<script src="https://cdn.jsdelivr.net/npm/chartjs-plugin-datalabels@2.2.0/dist/chartjs-plugin-datalabels.min.js"></script>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:'Courier New',monospace;background:#0a0a0f;color:#e0e0e8}
.header{background:linear-gradient(135deg,#1a1a2e 0%,#16213e 100%);padding:1.5rem 2rem;border-bottom:1px solid #2a2a3a;display:flex;justify-content:space-between;align-items:center}
.header h1{color:#4ade80;font-size:1.5rem;display:flex;align-items:center;gap:0.5rem}
.header h1::before{content:"◈";font-size:1.8rem}
.header p{color:#8888a0;font-size:0.85rem;margin-top:0.3rem}
.container{max-width:1400px;margin:0 auto;padding:1.5rem}
.section{margin-bottom:2rem}
.section-title{color:#60a5fa;font-size:1.1rem;margin-bottom:1rem;padding-bottom:0.5rem;border-bottom:1px solid #1a1a2e}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:1rem}
.card{background:#12121a;border:1px solid #2a2a3a;border-radius:8px;padding:1rem;transition:border-color 0.2s,transform 0.2s}
.card:hover{border-color:#4ade80;transform:translateY(-2px)}
.card-title{color:#a78bfa;font-size:0.75rem;text-transform:uppercase;margin-bottom:0.5rem;letter-spacing:1px}
.card-value{font-size:1.8rem;font-weight:bold;color:#4ade80}
.card-sub{color:#8888a0;font-size:0.75rem;margin-top:0.2rem}
.charts-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(350px,1fr));gap:1.5rem;margin-bottom:2rem}
.chart-card{background:#12121a;border:1px solid #2a2a3a;border-radius:8px;padding:1.2rem}
.chart-card h3{color:#a78bfa;font-size:0.85rem;margin-bottom:1rem}
.chart-card canvas{max-height:250px}
.table-wrap{overflow-x:auto;margin-top:1rem;max-height:500px;overflow-y:auto}
table{width:100%;border-collapse:collapse}
th{background:#1a1a2e;color:#4ade80;padding:0.6rem;text-align:left;font-size:0.8rem;position:sticky;top:0;z-index:1}
td{padding:0.5rem;border-bottom:1px solid #1a1a2e;font-size:0.8rem}
tr:hover{background:#1a1a2e}
.sev-CRITICAL{color:#ff4444;font-weight:bold}
.sev-HIGH{color:#ff8800;font-weight:bold}
.sev-MEDIUM{color:#ffcc00}
.sev-LOW{color:#4ade80}
.btn{background:#4ade80;color:#0a0a0f;border:none;padding:0.6rem 1.2rem;border-radius:6px;cursor:pointer;font-family:inherit;font-weight:bold;font-size:0.85rem;transition:all 0.2s}
.btn:hover{background:#22c55e;transform:translateY(-1px)}
.btn-outline{background:transparent;color:#4ade80;border:1px solid #4ade80}
.btn-outline:hover{background:#4ade80;color:#0a0a0f}
.btn-danger{background:#ff4444;color:#fff}
.btn-danger:hover{background:#cc0000}
.btn-sm{padding:0.3rem 0.8rem;font-size:0.75rem}
.btn-group{display:flex;gap:0.5rem;flex-wrap:wrap}
.form-row{display:flex;gap:0.5rem;align-items:center;margin-bottom:0.5rem}
.status-new{color:#60a5fa}
.status-confirmed{color:#ff8800}
.status-resolved{color:#4ade80}
#capture-status{padding:0.5rem;border-radius:4px;margin-top:1rem;font-size:0.85rem}
.capture-running{background:#1a2e1a;border:1px solid #4ade80;color:#4ade80}
.capture-stopped{background:#2a1a1a;border:1px solid #ff4444;color:#ff4444}
.event-form{background:#12121a;border:1px solid #2a2a3a;border-radius:8px;padding:1.5rem;margin-bottom:2rem}
.event-form h3{color:#a78bfa;margin-bottom:1rem}
.form-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:0.5rem}
.form-group{display:flex;flex-direction:column;gap:0.3rem}
.form-group label{color:#8888a0;font-size:0.75rem}
.form-group input,.form-group select{background:#0a0a0f;border:1px solid #2a2a3a;color:#e0e0e8;padding:0.4rem;border-radius:4px;font-family:inherit}
.form-group input:focus,.form-group select:focus{outline:none;border-color:#4ade80}
.mitre-badge{display:inline-block;background:#1a1a2e;color:#a78bfa;padding:0.15rem 0.5rem;border-radius:3px;font-size:0.7rem;margin-right:0.3rem}
.ip-rep-score{display:inline-block;width:30px;height:30px;border-radius:50%;text-align:center;line-height:30px;font-weight:bold;font-size:0.8rem}
.ip-rep-low{background:#22c55e;color:#000}
.ip-rep-med{background:#ffcc00;color:#000}
.ip-rep-high{background:#ff8800;color:#000}
.ip-rep-crit{background:#ff4444;color:#fff}
.filter-bar{display:flex;gap:0.5rem;align-items:center;margin-bottom:1rem;flex-wrap:wrap}
.filter-bar select,.filter-bar input{background:#12121a;border:1px solid #2a2a3a;color:#e0e0e8;padding:0.4rem;border-radius:4px;font-family:inherit;font-size:0.8rem}
::-webkit-scrollbar{width:8px;height:8px}
::-webkit-scrollbar-track{background:#0a0a0f}
::-webkit-scrollbar-thumb{background:#2a2a3a;border-radius:4px}
</style>
</head>
<body>
<div class="header">
  <div>
    <h1>Phantom - Network Traffic Analyzer</h1>
    <p>TrinTech Digital Defense // v2.0.0</p>
  </div>
  <div style="text-align:right">
    <div style="font-size:0.75rem;color:#8888a0" id="clock">--:--:--</div>
    <div style="font-size:0.7rem;color:#4ade80" id="status-badge">● Live</div>
  </div>
</div>

<div class="container">
  <div class="section">
    <div class="section-title">// Traffic Overview</div>
    <div class="grid">
      <div class="card"><div class="card-title">Total Events</div><div class="card-value" id="stat-events">0</div></div>
      <div class="card"><div class="card-title">Total Alerts</div><div class="card-value" id="stat-alerts">0</div><div class="card-sub" id="stat-alert-sev"></div></div>
      <div class="card"><div class="card-title">Critical</div><div class="card-value" id="stat-critical">0</div></div>
      <div class="card"><div class="card-title">High</div><div class="card-value" id="stat-high">0</div></div>
      <div class="card"><div class="card-title">Unique IPs</div><div class="card-value" id="stat-ips">0</div></div>
      <div class="card"><div class="card-title">Protocols</div><div class="card-value" id="stat-protocols">0</div></div>
    </div>
  </div>

  <div class="section">
    <div class="section-title">// Analytics Dashboard</div>
    <div class="charts-grid">
      <div class="chart-card"><h3>Protocol Distribution</h3><canvas id="chart-protocols"></canvas></div>
      <div class="chart-card"><h3>Alerts by Severity</h3><canvas id="chart-severity"></canvas></div>
      <div class="chart-card"><h3>Top 10 Dest Ports</h3><canvas id="chart-ports"></canvas></div>
      <div class="chart-card"><h3>Top 10 Talkers</h3><canvas id="chart-talkers"></canvas></div>
    </div>
  </div>

  <div class="section">
    <div class="section-title">// Actions</div>
    <div class="btn-group">
      <button class="btn" onclick="refreshData()">Refresh</button>
      <button class="btn btn-outline" onclick="startCapture()">Start Capture</button>
      <button class="btn btn-outline" onclick="stopCapture()">Stop Capture</button>
      <button class="btn btn-outline" onclick="runAnalysis()">Analyze</button>
      <button class="btn btn-outline" onclick="exportHTML()">HTML Report</button>
      <button class="btn btn-outline" onclick="exportPDF()">PDF Report</button>
      <button class="btn btn-outline" onclick="exportCSV()">CSV Export</button>
      <button class="btn btn-danger" onclick="clearData()">Clear</button>
    </div>
    <div id="capture-status" class="capture-stopped">Capture: Stopped</div>
  </div>

  <div class="section" id="mitre-section" style="display:none">
    <div class="section-title">// MITRE ATT&CK Mappings</div>
    <div class="table-wrap">
      <table><thead><tr><th>Technique</th><th>Tactic</th><th>Subtechnique</th><th>Description</th></tr></thead>
      <tbody id="mitre-table"></tbody>
    </div>
  </div>

  <div class="section" id="ip-rep-section" style="display:none">
    <div class="section-title">// IP Reputation Scores</div>
    <div class="table-wrap">
      <table><thead><tr><th>IP</th><th>Score</th><th>Events</th><th>Ports</th><th>Dests</th></tr></thead>
      <tbody id="ip-rep-table"></tbody>
    </div>
  </div>

  <div class="section">
    <div class="section-title">// Add Event</div>
    <div class="event-form">
      <div class="form-grid">
        <div class="form-group"><label>Src IP</label><input id="f-src" value="192.168.1.10"></div>
        <div class="form-group"><label>Dst IP</label><input id="f-dst" value="10.0.0.5"></div>
        <div class="form-group"><label>Src Port</label><input id="f-sport" type="number" value="44321"></div>
        <div class="form-group"><label>Dst Port</label><input id="f-dport" type="number" value="53"></div>
        <div class="form-group"><label>Protocol</label><select id="f-proto"><option>TCP</option><option>UDP</option><option>DNS</option><option>HTTP</option><option>HTTPS</option><option>SSH</option><option>ICMP</option><option>FTP</option><option>SMTP</option><option>TLS</option><option>OTHER</option></select></div>
        <div class="form-group"><label>Payload Size</label><input id="f-size" type="number" value="0"></div>
      </div>
      <div style="margin-top:0.8rem"><button class="btn btn-sm" onclick="addManualEvent()">Add Event</button></div>
    </div>
  </div>

  <div class="section">
    <div class="section-title">// Auto-Ingest (Push Events from Other Tools)</div>
    <div class="event-form">
      <div class="form-group" style="margin-bottom:0.5rem"><label>Source</label>
        <select id="ingest-source"><option value="mirage">Mirage</option><option value="specter">Specter/Rat-Detecter</option><option value="ti-corr">TI-Corr</option><option value="footprint">FootprintScanner</option><option value="logcorr">Log Correlator</option><option value="custom">Custom</option></select>
      </div>
      <div class="form-group" style="margin-bottom:0.5rem"><label>JSON Events Array</label>
        <textarea id="ingest-payload" rows="4" style="background:#0a0a0f;border:1px solid #2a2a3a;color:#e0e0e8;padding:0.4rem;border-radius:4px;font-family:inherit;font-size:0.75rem;width:100%;resize:vertical" placeholder='[{"src_ip":"10.0.0.1","dst_ip":"10.0.0.2","src_port":12345,"dst_port":80,"protocol":"TCP","payload_size":256}]'></textarea>
      </div>
      <div style="display:flex;gap:0.5rem">
        <button class="btn btn-sm" onclick="ingestEvents()">Push Ingest</button>
        <button class="btn btn-outline btn-sm" onclick="autoIngestTest()">Auto-Test (10 Events)</button>
      </div>
      <div id="ingest-status" style="margin-top:0.5rem;font-size:0.8rem;color:#8888a0"></div>
    </div>
  </div>

  <div class="section">
    <div class="section-title">// Alert Dedup</div>
    <div class="btn-group">
      <button class="btn btn-outline btn-sm" onclick="runDedup()">Run Dedup</button>
      <button class="btn btn-outline btn-sm" onclick="showDedupStats()">Dedup Stats</button>
    </div>
    <div id="dedup-status" style="margin-top:0.5rem;font-size:0.8rem;color:#8888a0"></div>
  </div>

  <div class="section">
    <div class="section-title">// Alerts</div>
    <div class="filter-bar">
      <select id="filter-type" onchange="filterAlerts()"><option value="">All Types</option></select>
      <select id="filter-sev" onchange="filterAlerts()"><option value="">All Severities</option></select>
    </div>
    <div class="table-wrap">
      <table>
        <thead><tr><th>ID</th><th>Type</th><th>MITRE</th><th>Severity</th><th>Score</th><th>Details</th><th>IPs</th><th>Status</th><th>Actions</th></tr></thead>
        <tbody id="alerts-table"></tbody>
      </table>
    </div>
  </div>

  <div class="section">
    <div class="section-title">// Recent Traffic</div>
    <div class="table-wrap">
      <table>
        <thead><tr><th>ID</th><th>Timestamp</th><th>Source</th><th>Dest</th><th>Proto</th><th>Size</th></tr></thead>
        <tbody id="events-table"></tbody>
      </table>
    </div>
  </div>
</div>

<script>
const API='';
let currentAlerts=[];
let chartInstances={};

function createChart(id,config){const ctx=document.getElementById(id);if(!ctx)return null;if(chartInstances[id])chartInstances[id].destroy();chartInstances[id]=new Chart(ctx,config);return chartInstances[id]}

function updateCharts(stats,alertSummary){
  const protocols=stats.protocols||{};
  if(Object.keys(protocols).length){
    createChart('chart-protocols',{type:'doughnut',data:{labels:Object.keys(protocols),datasets:[{data:Object.values(protocols),backgroundColor:['#4ade80','#60a5fa','#a78bfa','#f59e0b','#ff4444','#ff8800','#22d3ee','#ec4899','#84cc16','#f97316'],borderWidth:0}]},options:{responsive:true,plugins:{legend:{position:'right',labels:{color:'#e0e0e8',font:{family:'Courier New'}}}}}})}

  const sevs=alertSummary.by_severity||{};
  if(Object.values(sevs).some(v=>v>0)){
    createChart('chart-severity',{type:'doughnut',data:{labels:['CRITICAL','HIGH','MEDIUM','LOW'],datasets:[{data:[sevs.CRITICAL||0,sevs.HIGH||0,sevs.MEDIUM||0,sevs.LOW||0],backgroundColor:['#ff4444','#ff8800','#ffcc00','#4ade80'],borderWidth:0}]},options:{responsive:true,plugins:{legend:{position:'bottom',labels:{color:'#e0e0e8',font:{family:'Courier New'}}}}}})}

  const topPorts=(stats.top_ports||[]).slice(0,10);
  if(topPorts.length){
    createChart('chart-ports',{type:'bar',data:{labels:topPorts.map(p=>':'+p.port),datasets:[{label:'Events',data:topPorts.map(p=>p.count),backgroundColor:'#60a5fa',borderRadius:4}]},options:{responsive:true,plugins:{legend:{display:false}},scales:{x:{ticks:{color:'#e0e0e8',font:{family:'Courier New',size:9}},grid:{color:'#1a1a2e'}},y:{ticks:{color:'#e0e0e8'},grid:{color:'#1a1a2e'}}}}})}

  const talkers=(stats.top_talkers||[]).slice(0,10);
  if(talkers.length){
    createChart('chart-talkers',{type:'bar',data:{labels:talkers.map(t=>t.ip),datasets:[{label:'Events',data:talkers.map(t=>t.count),backgroundColor:'#4ade80',borderRadius:4}]},options:{indexAxis:'y',responsive:true,plugins:{legend:{display:false}},scales:{x:{ticks:{color:'#e0e0e8'},grid:{color:'#1a1a2e'}},y:{ticks:{color:'#e0e0e8',font:{family:'Courier New',size:9}},grid:{color:'#1a1a2e'}}}}})}
}

async function refreshData(){
  try{
    const [statsRes,alertsRes]=await Promise.all([fetch(API+'/api/stats'),fetch(API+'/api/alerts')]);
    const stats=await statsRes.json();
    const alerts=await alertsRes.json();
    currentAlerts=alerts;

    document.getElementById('stat-events').textContent=(stats.total_events||0).toLocaleString();
    document.getElementById('stat-alerts').textContent=(stats.total_alerts||0);
    document.getElementById('stat-alert-sev').textContent=`${stats.high||0}H/${stats.critical||0}C`;
    document.getElementById('stat-critical').textContent=stats.critical||0;
    document.getElementById('stat-high').textContent=stats.high||0;
    document.getElementById('stat-ips').textContent=(stats.unique_src_ips||0)+(stats.unique_dst_ips||0);
    document.getElementById('stat-protocols').textContent=Object.keys(stats.protocols||{}).length;

    // Charts
    const bySev={};alerts.forEach(a=>{bySev[a.severity]=(bySev[a.severity]||0)+1});
    updateCharts(stats,bySev);

    // MITRE
    if(stats.mitre_mappings&&stats.mitre_mappings.length>0){
      document.getElementById('mitre-section').style.display='';
      document.getElementById('mitre-table').innerHTML=stats.mitre_mappings.map(m=>`<tr><td><span class="mitre-badge">${m.technique}</span></td><td>${m.tactic||''}</td><td>${m.subtechnique||''}</td><td style="color:#888">${(m.description||'').substring(0,80)}</td></tr>`).join('');
    }

    // IP Reputation
    if(stats.ip_reputation&&Object.keys(stats.ip_reputation).length>0){
      document.getElementById('ip-rep-section').style.display='';
      const sorted=Object.entries(stats.ip_reputation).sort((a,b)=>b[1]-a[1]);
      document.getElementById('ip-rep-table').innerHTML=sorted.map(([ip,score])=>{
        const cls=score>=8?'ip-rep-crit':score>=5?'ip-rep-high':score>=3?'ip-rep-med':'ip-rep-low';
        return `<tr><td>${ip}</td><td><span class="ip-rep-score ${cls}">${score}</span></td><td>-</td><td>-</td><td>-</td></tr>`;
      }).join('');
    }

    // Filters
    const tSet=new Set(),sSet=new Set();
    alerts.forEach(a=>{tSet.add(a.alert_type);sSet.add(a.severity)});
    document.getElementById('filter-type').innerHTML='<option value="">All Types</option>'+[...tSet].sort().map(t=>`<option value="${t}">${t}</option>`).join('');
    document.getElementById('filter-sev').innerHTML='<option value="">All Severities</option>'+[...sSet].sort().map(s=>`<option value="${s}">${s}</option>`).join('');

    renderAlertsTable(alerts);

    fetch(API+'/api/events?limit=50').then(r=>r.json()).then(evts=>{
      document.getElementById('events-table').innerHTML=(evts||[]).reverse().map(e=>`<tr><td>${e.event_id}</td><td>${new Date(e.timestamp).toLocaleString()}</td><td>${e.src_ip}:${e.src_port}</td><td>${e.dst_ip}:${e.dst_port}</td><td>${e.protocol}</td><td>${e.payload_size.toLocaleString()}</td></tr>`).join('')||'<tr><td colspan="6" style="text-align:center;padding:2rem;color:#8888a0">No events</td></tr>';
    });

    document.getElementById('status-badge').textContent='● Live';
  }catch(err){console.error('Refresh error:',err)}
}

function renderAlertsTable(alerts){
  const tf=document.getElementById('filter-type').value;
  const sf=document.getElementById('filter-sev').value;
  const filtered=alerts.filter(a=>(!tf||a.alert_type===tf)&&(!sf||a.severity===sf));
  document.getElementById('alerts-table').innerHTML=filtered.map(a=>`<tr><td>${a.alert_id}</td><td>${a.alert_type}</td><td><span class="mitre-badge">T???</span></td><td class="sev-${a.severity}">${a.severity}</td><td>${a.score.toFixed(0)}</td><td style="max-width:300px;overflow:hidden;text-overflow:ellipsis" title="${a.details}">${a.details}</td><td>${(a.ips||[]).join(', ')}</td><td class="status-${a.status.toLowerCase()}">${a.status}</td><td><button class="btn btn-sm btn-outline" onclick="resolveAlert('${a.alert_id}')">✓</button></td></tr>`).join('')||'<tr><td colspan="9" style="text-align:center;padding:2rem;color:#8888a0">No alerts</td></tr>';
}

function filterAlerts(){renderAlertsTable(currentAlerts)}

async function startCapture(){try{const r=await fetch(API+'/api/capture/start',{method:'POST'});document.getElementById('capture-status').className='capture-running';document.getElementById('capture-status').textContent='Capture: Running'}catch(err){alert('Failed: '+err)}}
async function stopCapture(){try{await fetch(API+'/api/capture/stop',{method:'POST'});document.getElementById('capture-status').className='capture-stopped';document.getElementById('capture-status').textContent='Capture: Stopped';refreshData()}catch(err){alert('Failed: '+err)}}
async function runAnalysis(){try{const r=await fetch(API+'/api/analyze',{method:'POST'});const d=await r.json();document.getElementById('capture-status').textContent=`Analysis: ${d.total_alerts} alerts / ${d.total_events} events`;refreshData()}catch(err){alert('Failed: '+err)}}
function exportHTML(){window.open(API+'/api/report','_blank')}
function exportPDF(){window.open(API+'/api/report/pdf','_blank')}
function exportCSV(){window.open(API+'/api/export/csv','_blank')}
async function clearData(){if(confirm('Clear all?')){await fetch(API+'/api/clear',{method:'POST'});refreshData()}}

async function addManualEvent(){
  const body={src_ip:document.getElementById('f-src').value,dst_ip:document.getElementById('f-dst').value,src_port:parseInt(document.getElementById('f-sport').value)||0,dst_port:parseInt(document.getElementById('f-dport').value)||0,protocol:document.getElementById('f-proto').value,payload_size:parseInt(document.getElementById('f-size').value)||0};
  try{await fetch(API+'/api/event',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});refreshData()}catch(err){alert('Failed: '+err)}
}

async function resolveAlert(id){try{await fetch(API+'/api/alert/'+id+'/status',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({status:'RESOLVED'})});refreshData()}catch(err){alert('Failed: '+err)}}

function updateClock(){document.getElementById('clock').textContent=new Date().toLocaleTimeString()}

// ── SSE: Real-time alert stream ──
let sseConnected = false;
function connectSSE(){
  if(typeof EventSource==='undefined')return;
  try{
    const es=new EventSource(API+'/api/stream/alerts');
    es.onmessage=function(evt){
      const d=JSON.parse(evt.data);
      if(d.type==='alert'){handleSSEAlert(d);return}
      if(d.type==='stats'){handleSSEStats(d);return}
    };
    es.addEventListener('alert',function(evt){
      const alert=JSON.parse(evt.data);
      handleSSEAlert(alert);
    });
    es.addEventListener('stats',function(evt){
      const stats=JSON.parse(evt.data);
      handleSSEStats(stats);
    });
    es.addEventListener('heartbeat',function(){
      document.getElementById('status-badge').textContent='● Live';
    });
    es.onopen=function(){sseConnected=true;console.log('SSE connected')};
    es.onerror=function(err){
      console.error('SSE error, retrying in 5s...',err);
      sseConnected=false;
      setTimeout(connectSSE,5000);
    };
  }catch(e){console.error('SSE failed:',e)}
}
function handleSSEAlert(alert){
  // Update alert count
  const el=document.getElementById('stat-alerts');
  if(el){let n=parseInt(el.textContent)||0;el.textContent=n+1}
  // Flash the alerts card
  const card=document.querySelector('.section-title');
  if(card)card.style.color='#ffcc00';
  setTimeout(()=>{if(card)card.style.color='#60a5fa'},2000);
  // Refresh alert table periodically
  refreshData();
}
function handleSSEStats(stats){
  document.getElementById('stat-alerts').textContent=stats.total_alerts||0;
  document.getElementById('stat-critical').textContent=stats.critical||0;
  document.getElementById('stat-high').textContent=stats.high||0;
}

setInterval(updateClock,1000);updateClock();
setInterval(refreshData,10000);refreshData();

// Auto-connect SSE after page load
window.addEventListener('load',function(){setTimeout(connectSSE,1000)});

// ── Auto-Ingest ──
async function ingestEvents(){
  try{
    const source=document.getElementById('ingest-source').value;
    const payload=JSON.parse(document.getElementById('ingest-payload').value);
    const resp=await fetch(API+'/api/ingest',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({events:payload,source:source})});
    const data=await resp.json();
    document.getElementById('ingest-status').innerHTML=`<span style="color:#4ade80">✓ Ingested ${data.ingested} events from ${data.source} (total: ${data.total_events})</span>`;
    refreshData();
  }catch(e){document.getElementById('ingest-status').innerHTML=`<span style="color:#ff4444">✗ Error: ${e.message}</span>`}
}
async function autoIngestTest(){
  const events=[];
  for(let i=0;i<10;i++){
    events.push({src_ip:`10.0.1.${i+1}`,dst_ip:'192.168.1.1',src_port:Math.floor(Math.random()*60000)+5000,dst_port:[80,443,22,53,8080,4444,3389,3306][i%8],protocol:['TCP','UDP','TCP','DNS','TCP','TCP','TCP','TCP'][i%8],payload_size:Math.floor(Math.random()*1000)});
  }
  document.getElementById('ingest-payload').value=JSON.stringify(events,null,2);
  document.getElementById('ingest-source').value='mirage';
  document.getElementById('ingest-status').textContent='Test events generated — click Push Ingest';
}

// ── Dedup ──
async function runDedup(){
  try{
    const resp=await fetch(API+'/api/dedup',{method:'POST'});
    const data=await resp.json();
    document.getElementById('dedup-status').innerHTML=`<span style="color:#4ade80">✓ Dedup: ${data.removed} removed, ${data.kept} kept</span>`;
    refreshData();
  }catch(e){document.getElementById('dedup-status').innerHTML=`<span style="color:#ff4444">✗ Error: ${e.message}</span>`}
}
async function showDedupStats(){
  try{
    const resp=await fetch(API+'/api/dedup/stats');
    const data=await resp.json();
    document.getElementById('dedup-status').innerHTML=`<span style="color:#8888a0">Active groups: ${data.active_groups}, Expired: ${data.expired_groups}, Window: ${data.window_seconds}s</span>`;
  }catch(e){document.getElementById('dedup-status').innerHTML=`<span style="color:#ff4444">✗ Error: ${e.message}</span>`}
}

</script>
</body>
</html>

"""

# ── SSE Alert Stream ──

# Queue for pushing alerts from analysis to SSE clients
_alert_queue: Queue = Queue()
_latest_alerts: list[dict] = []
_latest_stats: dict = {}


def get_analyzer() -> TrafficAnalyzer:
    """Get or create the global analyzer instance."""
    global analyzer
    if analyzer is None:
        analyzer = TrafficAnalyzer()
    return analyzer


@app.route('/')
def dashboard():
    """Main dashboard page."""
    return render_template_string(DASHBOARD_HTML)


@app.route('/api/health')
def health():
    """Health check endpoint."""
    a = get_analyzer()
    return jsonify({
        "status": "healthy",
        "tool": "Phantom",
        "version": "0.1.0",
        "events": a.get_stats()["total_events"],
        "alerts": a.get_stats()["total_alerts"],
    })


@app.route('/api/stats')
def get_stats():
    """Get analyzer statistics and latest analysis results."""
    a = get_analyzer()
    result = a.analyze()
    return jsonify({
        "total_events": result["total_events"],
        "total_alerts": result["total_alerts"],
        "critical": result["critical_alerts"],
        "high": result["high_alerts"],
        "medium": result["medium_alerts"],
        "low": result["low_alerts"],
        "unique_src_ips": len(set(e.src_ip for e in a.events)),
        "unique_dst_ips": len(set(e.dst_ip for e in a.events)),
        "protocols": result["statistics"].get("protocols", {}),
        "mitre_mappings": result.get("mitre_mappings", []),
        "ip_reputation": result.get("ip_reputation", {}),
    })


@app.route('/api/events', methods=["GET"])
def get_events():
    """Retrieve traffic events with optional filters."""
    a = get_analyzer()
    ip_filter = request.args.get("ip")
    proto_filter = request.args.get("protocol")
    limit = int(request.args.get("limit", 100))
    events = a.get_events(
        filter_ip=ip_filter,
        filter_protocol=proto_filter,
        limit=limit,
    )
    return jsonify(events)


@app.route('/api/event', methods=["POST"])
def add_event():
    """Add a new traffic event."""
    a = get_analyzer()
    data = request.get_json()
    if not data:
        return jsonify({"error": "JSON body required"}), 400

    required = ["src_ip", "dst_ip", "src_port", "dst_port", "protocol"]
    for field in required:
        if field not in data:
            return jsonify({"error": f"Missing required field: {field}"}), 400

    event = TrafficEvent(
        timestamp=data.get("timestamp", datetime.now().isoformat()),
        src_ip=data["src_ip"],
        dst_ip=data["dst_ip"],
        src_port=data["src_port"],
        dst_port=data["dst_port"],
        protocol=data["protocol"],
        direction=data.get("direction", "outbound"),
        payload_size=data.get("payload_size", 0),
        duration=data.get("duration", 0.0),
        raw_hex=data.get("raw_hex", ""),
        metadata=data.get("metadata"),
    )
    a.add_event(event)
    return jsonify({"status": "ok", "event_id": event.event_id}), 201


@app.route('/api/bulk-event', methods=["POST"])
def add_bulk_events():
    """Add multiple events at once (for PCAP import or bulk ingestion)."""
    a = get_analyzer()
    data = request.get_json()
    if not data or "events" not in data:
        return jsonify({"error": "JSON with 'events' array required"}), 400

    count = 0
    for ed in data["events"]:
        try:
            event = TrafficEvent(
                timestamp=ed.get("timestamp", datetime.now().isoformat()),
                src_ip=ed["src_ip"],
                dst_ip=ed["dst_ip"],
                src_port=ed.get("src_port", 0),
                dst_port=ed.get("dst_port", 0),
                protocol=ed.get("protocol", "TCP"),
                direction=ed.get("direction", "outbound"),
                payload_size=ed.get("payload_size", 0),
                raw_hex=ed.get("raw_hex", ""),
                metadata=ed.get("metadata"),
            )
            a.add_event(event)
            count += 1
        except Exception as e:
            logger.error(f"Failed to add event: {e}")

    return jsonify({"status": "ok", "events_added": count})


@app.route('/api/alerts', methods=["GET"])
def get_alerts():
    """Retrieve all alerts with optional filters."""
    a = get_analyzer()
    alert_type = request.args.get("type")
    severity = request.args.get("severity")
    alerts = a.get_alerts(filter_type=alert_type, filter_severity=severity)
    return jsonify(alerts)


@app.route('/api/alert/<alert_id>', methods=["GET"])
def get_alert(alert_id):
    """Get a specific alert by ID."""
    a = get_analyzer()
    for alert in a.alerts:
        if alert.alert_id == alert_id:
            return jsonify(alert.to_dict())
    return jsonify({"error": "Alert not found"}), 404


@app.route('/api/alert/<alert_id>/status', methods=["POST"])
def update_alert_status(alert_id):
    """Update alert status."""
    a = get_analyzer()
    data = request.get_json()
    if not data or "status" not in data:
        return jsonify({"error": "status field required"}), 400

    for alert in a.alerts:
        if alert.alert_id == alert_id:
            old_status = alert.status
            alert.status = data["status"]
            return jsonify({
                "status": "ok",
                "alert_id": alert_id,
                "old_status": old_status,
                "new_status": alert.status,
            })
    return jsonify({"error": "Alert not found"}), 404


@app.route('/api/analyze', methods=["POST"])
def trigger_analysis():
    """Run analysis on all ingested events."""
    a = get_analyzer()
    result = a.analyze()
    # SSE push is handled inside analyze() via engine

    return jsonify({
        "status": "complete",
        "total_events": result["total_events"],
        "total_alerts": result["total_alerts"],
        "critical_alerts": result["critical_alerts"],
        "high_alerts": result["high_alerts"],
        "medium_alerts": result["medium_alerts"],
        "low_alerts": result["low_alerts"],
        "alerts_count": len(result["alerts"]),
        "dedup_removed": result.get("dedup_stats", {}).get("removed", 0),
    })


@app.route('/api/report', methods=["GET"])
def generate_report():
    """Generate and download HTML traffic analysis report."""
    a = get_analyzer()
    a.analyze()
    filepath = a.generate_report()
    return jsonify({"status": "ok", "report_path": str(filepath), "filename": Path(filepath).name})


@app.route('/api/report/pdf', methods=["GET"])
def generate_pdf_report():
    """Generate and download PDF traffic analysis report."""
    a = get_analyzer()
    a.analyze()
    filepath = a.generate_pdf_report()
    return jsonify({"status": "ok", "report_path": str(filepath), "filename": Path(filepath).name})


@app.route('/api/report/json', methods=["GET"])
def generate_json_report():
    """Generate JSON traffic analysis report."""
    a = get_analyzer()
    result = a.analyze()
    return jsonify(result)


@app.route('/api/export/csv', methods=["GET"])
def export_csv():
    """Export events and alerts as CSV files."""
    a = get_analyzer()
    csv_path = a.export_csv()
    return jsonify({"status": "ok", "csv_path": str(csv_path), "filename": Path(csv_path).name})


@app.route('/api/capture/start', methods=["POST"])
def start_capture():
    """Start live packet capture (requires root/scapy)."""
    if not HAS_SCAPY:
        return jsonify({"error": "scapy not installed"}), 500

    a = get_analyzer()

    def on_packet(pkt):
        """Process a captured packet."""
        try:
            timestamp = datetime.now().isoformat()
            protocol = "OTHER"
            src_port = dst_port = 0
            payload_size = 0

            if pkt.haslayer(IP):
                src_ip = pkt[IP].src
                dst_ip = pkt[IP].dst

                if pkt.haslayer(TCP):
                    protocol = "TCP"
                    src_port = pkt[TCP].sport
                    dst_port = pkt[TCP].dport
                    payload_size = len(pkt[TCP].payload) if pkt[TCP].payload else 0
                elif pkt.haslayer(UDP):
                    protocol = "UDP"
                    src_port = pkt[UDP].sport
                    dst_port = pkt[UDP].dport
                    payload_size = len(pkt[UDP].payload) if pkt[UDP].payload else 0
                elif pkt.haslayer(ICMP):
                    protocol = "ICMP"
                    payload_size = len(pkt[ICMP].payload) if pkt[ICMP].payload else 0
                    src_port = dst_port = 0
                else:
                    src_ip = pkt[IP].src
                    dst_ip = pkt[IP].dst

                # Classify well-known ports
                if dst_port == 53 and protocol == "UDP":
                    protocol = "DNS"
                elif dst_port == 80:
                    protocol = "HTTP"
                elif dst_port == 443:
                    protocol = "TLS"
                elif dst_port == 22:
                    protocol = "SSH"

                event = TrafficEvent(
                    timestamp=timestamp,
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    src_port=src_port,
                    dst_port=dst_port,
                    protocol=protocol,
                    payload_size=payload_size,
                )
                a.add_event(event)
        except Exception as e:
            logger.debug(f"Packet processing error: {e}")

    try:
        # Start sniffing in a background thread
        import threading
        sniff_thread = threading.Thread(
            target=lambda: sniff(prn=on_packet, store=False, count=0),
            daemon=True,
        )
        sniff_thread.start()
        return jsonify({
            "status": "started",
            "message": "Packet capture started in background thread",
        })
    except PermissionError:
        return jsonify({"error": "Permission denied - run as root or with sudo"}), 403
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/api/capture/stop', methods=["POST"])
def stop_capture():
    """Stop live packet capture."""
    try:
        from scapy.all import conf
        conf.sniff_count = 0
        return jsonify({"status": "stopped"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/api/import/pcap', methods=["POST"])
def import_pcap():
    """Import a PCAP file for analysis."""
    if not HAS_SCAPY:
        return jsonify({"error": "scapy not installed"}), 500

    if "file" not in request.files:
        return jsonify({"error": "No file provided"}), 400

    pcap_file = request.files["file"]
    a = get_analyzer()

    try:
        from scapy.all import rdpcap
        packets = rdpcap(pcap_file)
        count = 0
        for pkt in packets:
            try:
                timestamp = datetime.fromtimestamp(float(pkt.time)).isoformat()
                protocol = "OTHER"
                src_port = dst_port = 0
                payload_size = 0

                if pkt.haslayer(IP):
                    src_ip = pkt[IP].src
                    dst_ip = pkt[IP].dst

                    if pkt.haslayer(TCP):
                        protocol = "TCP"
                        src_port = pkt[TCP].sport
                        dst_port = pkt[TCP].dport
                        payload_size = len(pkt[TCP].payload) if pkt[TCP].payload else 0
                    elif pkt.haslayer(UDP):
                        protocol = "UDP"
                        src_port = pkt[UDP].sport
                        dst_port = pkt[UDP].dport
                        payload_size = len(pkt[UDP].payload) if pkt[UDP].payload else 0
                    elif pkt.haslayer(ICMP):
                        protocol = "ICMP"
                        payload_size = len(pkt[ICMP].payload) if pkt[ICMP].payload else 0

                    if dst_port == 53:
                        protocol = "DNS"
                    elif dst_port == 80:
                        protocol = "HTTP"
                    elif dst_port == 443:
                        protocol = "TLS"

                    event = TrafficEvent(
                        timestamp=timestamp,
                        src_ip=src_ip,
                        dst_ip=dst_ip,
                        src_port=src_port,
                        dst_port=dst_port,
                        protocol=protocol,
                        payload_size=payload_size,
                    )
                    a.add_event(event)
                    count += 1
            except Exception:
                continue

        return jsonify({"status": "imported", "events": count})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/api/clear', methods=["POST"])
def clear_data():
    """Clear all events and alerts."""
    global analyzer
    a = get_analyzer()
    a.events.clear()
    a.alerts.clear()
    a.event_index.clear()
    a.alert_index.clear()
    return jsonify({"status": "cleared"})


@app.route('/api/logcorr/export', methods=["GET"])
def logcorr_export():
    """Export events in Log Correlator-compatible format."""
    a = get_analyzer()
    result = a.analyze()

    logcorr_events = []
    for event in a.events:
        logcorr_events.append({
            "source": "phantom",
            "event_type": event.protocol,
            "timestamp": event.timestamp,
            "src_ip": event.src_ip,
            "dst_ip": event.dst_ip,
            "src_port": event.src_port,
            "dst_port": event.dst_port,
            "payload_size": event.payload_size,
            "details": f"Traffic event: {event.protocol} from {event.src_ip}:{event.src_port} to {event.dst_ip}:{event.dst_port}",
        })

    # Also export alerts as incidents
    for alert in a.alerts:
        logcorr_events.append({
            "source": "phantom",
            "event_type": f"phantom_alert_{alert.alert_type}",
            "timestamp": alert.timestamp,
            "severity": alert.severity,
            "score": alert.score,
            "details": alert.details,
        })

    return jsonify({
        "tool": "phantom",
        "events": logcorr_events,
        "exported_at": datetime.now().isoformat(),
    })


# ── Auto-Ingest (push endpoint for other TrinTech tools) ──

@app.route('/api/ingest', methods=["POST"])
def ingest_events():
    """
    Accept traffic events from other TrinTech tools (Mirage, Specter, etc).
    Accepts: {"events": [...], "source": "mirage|specter|footprint|ti-corr", "timestamp": "ISO"}
    Each event in array: {"src_ip", "dst_ip", "src_port", "dst_port", "protocol", "timestamp?", "payload_size?", "metadata?"}
    """
    a = get_analyzer()
    data = request.get_json()
    if not data or "events" not in data:
        return jsonify({"error": "JSON with 'events' array required"}), 400

    source = data.get("source", "unknown")
    count = 0
    for ed in data["events"]:
        if not all(k in ed for k in ("src_ip", "dst_ip", "src_port", "dst_port", "protocol")):
            continue
        event = TrafficEvent(
            timestamp=ed.get("timestamp", datetime.now().isoformat()),
            src_ip=ed["src_ip"],
            dst_ip=ed["dst_ip"],
            src_port=ed["src_port"],
            dst_port=ed["dst_port"],
            protocol=ed["protocol"],
            direction=ed.get("direction", "outbound"),
            payload_size=ed.get("payload_size", 0),
            duration=ed.get("duration", 0.0),
            metadata=ed.get("metadata", {}),
        )
        # Tag with source info
        if event.metadata:
            event.metadata["ingest_source"] = source
        else:
            event.metadata = {"ingest_source": source}
        a.add_event(event)
        count += 1

    return jsonify({"status": "ok", "ingested": count, "source": source, "total_events": len(a.events)})


# ── Dedup Control ──

@app.route('/api/dedup', methods=["POST"])
def run_dedup():
    """Run alert deduplication manually."""
    a = get_analyzer()
    result = a.dedup_alerts()
    return jsonify({"status": "ok", **result})


@app.route('/api/dedup/stats', methods=["GET"])
def dedup_stats():
    """Get deduplication statistics."""
    a = get_analyzer()
    stats = a.get_dedup_stats()
    return jsonify({"status": "ok", **stats})


# ── SSE: Real-time alert stream ──

@app.route('/api/stream/alerts', methods=["GET"])
def stream_alerts():
    """
    Server-Sent Events endpoint for real-time alert delivery.
    Connects from browser: new EventSource('/api/stream/alerts')
    Sends: event: alert  data: {alert_dict}
           event: stats   data: {stats_dict}
           event: heartbeat
    """
    def event_stream():
        # Send initial stats
        a = get_analyzer()
        if a.events:
            _latest_stats = {
                "total_events": len(a.events),
                "total_alerts": len(a.alerts),
                "critical": sum(1 for al in a.alerts if al.severity == "CRITICAL"),
                "high": sum(1 for al in a.alerts if al.severity == "HIGH"),
                "medium": sum(1 for al in a.alerts if al.severity == "MEDIUM"),
                "low": sum(1 for al in a.alerts if al.severity == "LOW"),
            }
            yield f"event: stats\ndata: {_json_encode(_latest_stats)}\n\n"

        # Also send recent alerts
        with _alert_queue.mutex:
            recent = list(_latest_alerts[-50:]) if _latest_alerts else []
        for alert in recent:
            yield f"event: alert\ndata: {_json_encode(alert)}\n\n"

        # Then stream new alerts in real-time
        while True:
            try:
                alert_data = _alert_queue.get(timeout=30)
                if alert_data is None:
                    break  # Shutdown signal
                yield f"event: alert\ndata: {_json_encode(alert_data)}\n\n"
            except Empty:
                yield "event: heartbeat\ndata: {\"msg\": \"keepalive\"}\n\n"

    return Response(
        stream_with_context(event_stream()),
        mimetype="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
            "Connection": "keep-alive",
        },
    )


def _json_encode(obj: dict) -> str:
    """JSON encode without sorting keys."""
    return json.dumps(obj, default=str, separators=(",", ":"))


# ── CLI ──

def main():
    parser = argparse.ArgumentParser(description="Phantom - Network Traffic Analyzer")
    parser.add_argument("--port", type=int, default=5055, help="Server port (default: 5055)")
    parser.add_argument("--host", default="0.0.0.0", help="Server host (default: 0.0.0.0)")
    parser.add_argument("--capture", action="store_true", help="Start packet capture on launch")
    parser.add_argument("--analyze", action="store_true", help="Run analysis on startup")
    parser.add_argument("--pcap", type=str, help="Analyze a PCAP file")
    parser.add_argument("--db", type=str, help="Database path")
    parser.add_argument("--reports-dir", type=str, default="phantom/exports", help="Reports directory")
    args = parser.parse_args()

    # Initialize analyzer
    global analyzer
    analyzer = TrafficAnalyzer(
        db_path=args.db,
        reports_dir=args.reports_dir,
    )

    # Import PCAP if specified
    if args.pcap:
        if HAS_SCAPY:
            from scapy.all import rdpcap, IP, TCP, UDP, ICMP
            packets = rdpcap(args.pcap)
            count = 0
            for pkt in packets:
                try:
                    timestamp = datetime.fromtimestamp(float(pkt.time)).isoformat()
                    protocol = "OTHER"
                    src_port = dst_port = 0
                    payload_size = 0
                    src_ip = dst_ip = "unknown"

                    if pkt.haslayer(IP):
                        src_ip = pkt[IP].src
                        dst_ip = pkt[IP].dst
                        if pkt.haslayer(TCP):
                            protocol = "TCP"
                            src_port = pkt[TCP].sport
                            dst_port = pkt[TCP].dport
                            payload_size = len(pkt[TCP].payload) if pkt[TCP].payload else 0
                        elif pkt.haslayer(UDP):
                            protocol = "UDP"
                            src_port = pkt[UDP].sport
                            dst_port = pkt[UDP].dport
                            payload_size = len(pkt[UDP].payload) if pkt[UDP].payload else 0
                        elif pkt.haslayer(ICMP):
                            protocol = "ICMP"
                            payload_size = len(pkt[ICMP].payload) if pkt[ICMP].payload else 0

                        if dst_port == 53:
                            protocol = "DNS"
                        elif dst_port == 80:
                            protocol = "HTTP"
                        elif dst_port == 443:
                            protocol = "TLS"

                        event = TrafficEvent(
                            timestamp=timestamp,
                            src_ip=src_ip,
                            dst_ip=dst_ip,
                            src_port=src_port,
                            dst_port=dst_port,
                            protocol=protocol,
                            payload_size=payload_size,
                        )
                        analyzer.add_event(event)
                        count += 1
                except Exception:
                    continue
            print(f"Imported {count} events from {args.pcap}")

            if args.analyze:
                result = analyzer.analyze()
                print(f"Analysis complete: {result['total_alerts']} alerts from {result['total_events']} events")

                report_path = analyzer.generate_report()
                print(f"Report saved to: {report_path}")

            # Save to DB
            analyzer.save_events()
            stats = analyzer.get_stats()
            print(f"Stats: {json.dumps(stats, indent=2)}")
        else:
            print("Error: scapy required for PCAP analysis")
            return

    # Start Flask server
    logger.info(f"Starting Phantom API server on {args.host}:{args.port}")
    print(f"Phantom API server running at http://{args.host}:{args.port}")
    print(f"Dashboard: http://{args.host}:{args.port}/")
    print(f"API: http://{args.host}:{args.port}/api/")

    if args.capture and HAS_SCAPY:
        print("Starting packet capture...")
        import threading
        def start_sniff():
            from scapy.all import sniff
            sniff(prn=lambda p: (
                on_packet(p) if on_packet else None
            ), store=False, count=0)

        def on_packet(pkt):
            try:
                timestamp = datetime.now().isoformat()
                protocol = "OTHER"
                src_port = dst_port = 0
                payload_size = 0
                src_ip = dst_ip = "unknown"

                if pkt.haslayer(IP):
                    src_ip = pkt[IP].src
                    dst_ip = pkt[IP].dst
                    if pkt.haslayer(TCP):
                        protocol = "TCP"
                        src_port = pkt[TCP].sport
                        dst_port = pkt[TCP].dport
                        payload_size = len(pkt[TCP].payload) if pkt[TCP].payload else 0
                    elif pkt.haslayer(UDP):
                        protocol = "UDP"
                        src_port = pkt[UDP].sport
                        dst_port = pkt[UDP].dport
                        payload_size = len(pkt[UDP].payload) if pkt[UDP].payload else 0
                    elif pkt.haslayer(ICMP):
                        protocol = "ICMP"
                        payload_size = len(pkt[ICMP].payload) if pkt[ICMP].payload else 0
                    if dst_port == 53: protocol = "DNS"
                    elif dst_port == 80: protocol = "HTTP"
                    elif dst_port == 443: protocol = "TLS"

                    event = TrafficEvent(
                        timestamp=timestamp,
                        src_ip=src_ip,
                        dst_ip=dst_ip,
                        src_port=src_port,
                        dst_port=dst_port,
                        protocol=protocol,
                        payload_size=payload_size,
                    )
                    analyzer.add_event(event)
            except Exception as e:
                logger.debug(f"Packet error: {e}")

        t = threading.Thread(target=start_sniff, daemon=True)
        t.start()

    app.run(host=args.host, port=args.port, debug=False)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
TrinTech Digital Defense
Playbook Generator — Automated Incident Response

Takes incidents from Log Correlator and generates:
- MITRE ATT&CK technique mapping (20+ tags mapped)
- Containment, eradication, and recovery steps
- IOC extraction with SPECTER enrichment
- Escalation templates
- Playbook lifecycle management (status workflow)
- Playbook deduplication and merging
- Full text, JSON, and PDF reports
- Email/SMS notification templates

Integrates with: Log Correlator, SPECTER, Mirage, TI-Corr, FootprintScanner
"""

import argparse
import json
import logging
import os
import re
import sqlite3
import subprocess
import sys
import uuid
from collections import defaultdict, OrderedDict
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

# ────────────────────────────────────────────────────────────────
# Configuration
# ────────────────────────────────────────────────────────────────

BASE_DIR = Path(__file__).resolve().parent
REPORTS_DIR = BASE_DIR / "trintech_reports"
REPORTS_DIR.mkdir(exist_ok=True)

DB_PATH = REPORTS_DIR / "playbook_generator.db"
CONFIG_PATH = BASE_DIR / "playbook_config.json"

log = logging.getLogger("playbook")
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)

# ────────────────────────────────────────────────────────────────
# Customizable Configuration
# ────────────────────────────────────────────────────────────────

# Default config — can be overridden via playbook_config.json
DEFAULT_CONFIG = {
    "escalation_contacts": {
        "CISO": {"email": "ciso@example.com", "phone": "+1-555-0100"},
        "SOC Lead": {"email": "soc-lead@example.com", "phone": "+1-555-0101"},
        "Incident Commander": {"email": "ic@example.com", "phone": "+1-555-0102"},
        "Legal": {"email": "legal@example.com", "phone": "+1-555-0103"},
        "SOC Analyst On-Call": {"email": "soc-oncall@example.com", "phone": "+1-555-0200"},
        "SOC Analyst": {"email": "soc@example.com", "phone": "+1-555-0201"},
    },
    "default_email_domain": "example.com",
    "firewall_prefix": "iptables",
    "auto_block_all_ips": True,  # Auto-generate firewall rules for all attacker IPs
    "report_format": "text",  # text, json, pdf
    "pdf_defaults": {
        "font_size": 10,
        "font_name": "Helvetica",
        "margin": 60,
        "page_size": "A4",
    },
    "notification": {
        "email_enabled": True,
        "sms_enabled": False,
        "slack_enabled": False,
        "slack_webhook": "",
    },
    "dedup": {
        "enabled": True,
        "window_minutes": 30,  # Treat playbooks for same incident_id within this window as same
    },
}


def load_config() -> dict:
    """Load config from playbook_config.json, merging with defaults."""
    cfg = dict(DEFAULT_CONFIG)
    if CONFIG_PATH.exists():
        try:
            with open(CONFIG_PATH) as f:
                user_cfg = json.load(f)
            # Merge: top-level keys override defaults, nested dicts merge recursively
            for key, value in user_cfg.items():
                if isinstance(value, dict) and isinstance(cfg.get(key), dict):
                    cfg[key].update(value)
                else:
                    cfg[key] = value
            log.debug(f"Loaded config from {CONFIG_PATH}")
        except (json.JSONDecodeError, KeyError) as e:
            log.warning(f"Failed to load config from {CONFIG_PATH}, using defaults: {e}")
    return cfg


CONFIG = load_config()


def save_config(cfg: dict | None = None):
    """Save config to playbook_config.json."""
    if cfg is None:
        cfg = CONFIG
    with open(CONFIG_PATH, "w") as f:
        json.dump(cfg, f, indent=2)
    log.info(f"Config saved to {CONFIG_PATH}")


# ────────────────────────────────────────────────────────────────
# MITRE ATT&CK Mapping Database (20+ tags)
# ────────────────────────────────────────────────────────────────

MITRE_MAP = {
    "authentication_failure": {
        "technique": "T1110 — Brute Force",
        "tactic": "Credential Access",
        "steps": [
            "Reset affected user passwords immediately",
            "Enable multi-factor authentication (MFA) for targeted accounts",
            "Block source IP at firewall perimeter",
            "Enable account lockout policy (5 failed attempts, 30 min lockout)",
            "Review successful logins after failures — check for compromised accounts",
        ],
        "severity_weight": 7,
    },
    "privilege_escalation": {
        "technique": "T1068 — Exploitation for Privilege Escalation",
        "tactic": "Privilege Escalation",
        "steps": [
            "Isolate affected host from network immediately",
            "Terminate suspicious processes identified by SPECTER",
            "Audit sudo/privilege abuse logs",
            "Review and harden sudoers configuration",
            "Scan for rootkits and persistence mechanisms",
            "Capture forensic image before remediation",
        ],
        "severity_weight": 9,
    },
    "network_security": {
        "technique": "T1071 — Application Layer Protocol",
        "tactic": "Command and Control",
        "steps": [
            "Block C2 IPs at firewall (both ingress and egress)",
            "Inspect DNS logs for tunneling (unusual query lengths/types)",
            "Enable deep packet inspection on affected network segment",
            "Check for lateral movement to internal hosts",
            "Review proxy logs for unauthorized connections",
        ],
        "severity_weight": 6,
    },
    "rat_detected": {
        "technique": "T1547 — Boot or Logon Autostart Execution",
        "tactic": "Persistence",
        "steps": [
            "Immediately isolate affected host from network",
            "Capture memory dump for malware analysis",
            "Identify and delete RAT persistence mechanisms (registry, cron, systemd)",
            "Scan all hosts that communicated with this machine in past 72h",
            "Rotate all credentials that existed on this host",
            "Check for data exfiltration (network logs, DLP alerts)",
            "Report to threat intel team for IOCs",
        ],
        "severity_weight": 10,
    },
    "persistence_mechanism": {
        "technique": "T1543 — Create or Modify System Process",
        "tactic": "Persistence",
        "steps": [
            "Identify all persistence mechanisms on affected host",
            "Remove crontabs, systemd services, startup entries",
            "Check /etc/passwd, /etc/crontab, /etc/rc.local for tampering",
            "Audit scheduled tasks on Windows (schtasks, registry Run keys)",
            "Scan for kernel modules (lsmod, insmod anomalies)",
            "Verify system binaries with file integrity checker",
        ],
        "severity_weight": 9,
    },
    "deception_triggered": {
        "technique": "T1595 — Active Scanning",
        "tactic": "Reconnaissance",
        "steps": [
            "Capture full attacker network traffic (packets if possible)",
            "Record attacker IP — cross-reference with TI-Corr",
            "Map decoy interaction timeline to build attacker profile",
            "Check if attacker moved from decoy to production assets",
            "Alert SOC team — attacker is actively scanning",
            "Deploy additional decoys along expected lateral movement paths",
        ],
        "severity_weight": 5,
    },
    "threat_intel_match": {
        "technique": "Multiple — See TI-Corr Report",
        "tactic": "Various",
        "steps": [
            "Cross-reference TI-Corr confidence score with incident severity",
            "Block all known IOCs from threat intel report at perimeter",
            "Add high-confidence IPs to threat list in all security tools",
            "Share IOCs with industry ISAC if applicable",
            "Update detection signatures with observed adversary TTPs",
        ],
        "severity_weight": 8,
    },
    # ── New MITRE mappings (improvement #2: expand to 20+) ──
    "file_modification": {
        "technique": "T1083 — File and Directory Discovery",
        "tactic": "Discovery",
        "steps": [
            "Identify all modified files and their timestamps",
            "Compare against file integrity baselines (AIDE/Tripwire)",
            "Check for modified system binaries (use rpm -Va or debsums)",
            "Review auditd logs for unauthorized file access",
            "Identify if modified files contain sensitive data",
        ],
        "severity_weight": 6,
    },
    "port_scan": {
        "technique": "T1046 — Network Service Scanning",
        "tactic": "Discovery",
        "steps": [
            "Block source IP at perimeter firewall",
            "Review firewall logs for scan duration and ports targeted",
            "Check if any scanned ports responded with unexpected services",
            "Update IDS/IPS signatures for the scanning tool (Nmap, Masscan, etc.)",
            "Verify no service exploitation followed the scan",
        ],
        "severity_weight": 5,
    },
    "c2_beacon": {
        "technique": "T1071 — Application Layer Protocol",
        "tactic": "Command and Control",
        "steps": [
            "Immediately block C2 IPs/domains at all egress points",
            "Isolate host exhibiting beaconing behavior",
            "Capture full packet capture of beacon communication",
            "Analyze beacon intervals for C2 infrastructure mapping",
            "Check for data staged for exfiltration before beacon",
            "Scan internal network for other hosts beaconing to same infrastructure",
        ],
        "severity_weight": 10,
    },
    "data_exfiltration": {
        "technique": "T1048 — Exfiltration Over Alternative Protocol",
        "tactic": "Exfiltration",
        "steps": [
            "Block destination IP/domain immediately at all egress points",
            "Assess volume of data transferred (check DLP, proxy logs, DNS)",
            "Identify what data was on the affected system (fileshares, DBs)",
            "Notify DLP team and legal if PII/PHI was involved",
            "Preserve network logs for forensic timeline",
            "Check if attacker returned to the system for additional exfil",
        ],
        "severity_weight": 10,
    },
    "lateral_movement": {
        "technique": "T1021 — Remote Services",
        "tactic": "Lateral Movement",
        "steps": [
            "Disable compromised accounts that were used for lateral movement",
            "Block attacker IPs from accessing internal resources",
            "Check all systems the attacker reached for additional compromise",
            "Review RDP, SSH, WinRM, WMI logs for lateral spread",
            "Check for credential dumping tools (mimikatz, lsass dump)",
            "Force password reset on all accounts the attacker could access",
        ],
        "severity_weight": 9,
    },
    "credential_dump": {
        "technique": "T1003 — OS Credential Dumping",
        "tactic": "Credential Access",
        "steps": [
            "Isolate affected system immediately (memory contains credentials)",
            "Force password reset on ALL accounts that accessed the system",
            "Check for credential dumping tools (mimikatz, secretsdump)",
            "Review LSASS access in EDR/siem logs",
            "Rotate service account credentials used on the system",
            "Check if dumped credentials were used for lateral movement",
        ],
        "severity_weight": 9,
    },
    "malware_detected": {
        "technique": "T1204 — User Execution",
        "tactic": "Execution",
        "steps": [
            "Isolate affected host from network",
            "Quarantine the detected malware file",
            "Run full SPECTER scan on the host and all connected hosts",
            "Check SPECTER signature DB for similar malware family IOCs",
            "Kill the process and remove the malware binary",
            "Check persistence mechanisms for the malware (registry, cron, services)",
        ],
        "severity_weight": 8,
    },
    "unauthorized_access": {
        "technique": "T1078 — Valid Accounts",
        "tactic": "Initial Access",
        "steps": [
            "Disable the compromised account immediately",
            "Reset passwords for the account and any shared passwords",
            "Review all activity performed by the account",
            "Check if the account was used to access sensitive systems",
            "Enable MFA for the account if not already enabled",
            "Review access control lists for the account's permissions",
        ],
        "severity_weight": 8,
    },
    "ransomware": {
        "technique": "T1486 — Data Encrypted for Impact",
        "tactic": "Impact",
        "steps": [
            "ISOLATE AFFECTED HOSTS IMMEDIATELY — disconnect from network",
            "Identify ransomware variant (file extension, ransom note)",
            "Check NOEASY/IDRansom database for decryption availability",
            "Identify entry point and all affected systems",
            "Restore from offline/immutable backups",
            "Contact law enforcement and ransomware response team",
            "Notify affected individuals per regulatory requirements",
        ],
        "severity_weight": 10,
    },
    "insider_threat": {
        "technique": "T1078 — Valid Accounts",
        "tactic": "Initial Access",
        "steps": [
            "Disable the insider's access immediately (all systems)",
            "Preserve all activity logs and evidence",
            "Review data accessed/modified/exfiltrated by the insider",
            "Conduct interview with insider (HR/legal present)",
            "Check if data was shared externally (email, USB, cloud uploads)",
            "Review and tighten access controls and monitoring",
        ],
        "severity_weight": 9,
    },
    "dns_tunneling": {
        "technique": "T1071.004 — DNS",
        "tactic": "Command and Control",
        "steps": [
            "Block DNS requests to suspicious TLDs/domains at resolver level",
            "Inspect DNS logs for unusual query patterns (long subdomains, high entropy)",
            "Implement DNS response policy zones (RPZ) to block known C2 domains",
            "Monitor for encoded data in DNS queries/base64 subdomains",
            "Check for data exfiltration via DNS TXT record responses",
            "Deploy DNS-specific IDS rules for tunneling detection",
        ],
        "severity_weight": 8,
    },
    "unauthorized_software": {
        "technique": "T1587 — Develop Capabilities",
        "tactic": "Initial Access",
        "steps": [
            "Identify the unauthorized software and its source",
            "Remove the software from affected systems",
            "Scan all systems for the same unauthorized software",
            "Check if the software contains malware or backdoors",
            "Review software approval process and implement stricter controls",
            "Update whitelisting rules to prevent future unauthorized installs",
        ],
        "severity_weight": 5,
    },
    "supply_chain": {
        "technique": "T1195 — Supply Chain Compromise",
        "tactic": "Initial Access",
        "steps": [
            "Identify the compromised vendor/software component",
            "Isolate systems that installed the compromised update",
            "Check for indicators of the supply chain attack in SIEM",
            "Contact vendor for incident details and remediation guidance",
            "Implement software bill of materials (SBOM) verification",
            "Review all systems for signs of compromise from the supply chain",
        ],
        "severity_weight": 10,
    },
    "zero_day": {
        "technique": "T1200 — Hardware Additions",
        "tactic": "Collection",
        "steps": [
            "Isolate affected systems immediately",
            "Activate vendor-specific zero-day response protocol",
            "Deploy emergency mitigation (WAF rules, IPS signatures)",
            "Monitor for exploitation patterns matching observed behavior",
            "Coordinate with industry CERT and information sharing groups",
            "Prepare for potential patch rollout when available",
        ],
        "severity_weight": 10,
    },
    "cloud_compromise": {
        "technique": "T1528 — Steal Application Access Token",
        "tactic": "Credential Access",
        "steps": [
            "Revoke all access tokens and API keys associated with compromised account",
            "Enable additional MFA requirements across cloud services",
            "Review CloudTrail/Azure AD logs for unauthorized activity",
            "Check if attacker modified IAM policies or created backdoor accounts",
            "Enable cloud provider incident response procedures",
            "Assess data exposed via cloud storage or databases",
        ],
        "severity_weight": 9,
    },
    "email_attack": {
        "technique": "T1566 — Phishing",
        "tactic": "Initial Access",
        "steps": [
            "Block sender domain/IP at email gateway",
            "Quarantine and remove the phishing email from all mailboxes",
            "Identify all recipients who opened/clicked the email",
            "Reset passwords for affected user accounts",
            "Scan affected machines with SPECTER for follow-up malware",
            "Send awareness alert to all staff about the phishing campaign",
        ],
        "severity_weight": 7,
    },
    "brute_force_ssh": {
        "technique": "T1110.001 — Password Guessing",
        "tactic": "Credential Access",
        "steps": [
            "Block brute force source IP at firewall",
            "Disable accounts targeted in brute force attempts",
            "Enable SSH key-only authentication (disable password auth)",
            "Implement fail2ban or similar SSH brute force protection",
            "Check if any accounts were successfully compromised",
            "Rotate SSH keys for affected systems",
        ],
        "severity_weight": 6,
    },
}

# ────────────────────────────────────────────────────────────────
# MITIGATION MAP — response steps by tag
# ────────────────────────────────────────────────────────────────

MITIGATION_MAP = {
    "authentication_failure": {
        "containment": [
            "Block source IP at firewall immediately",
            "Force password reset for targeted accounts",
            "Enable conditional access policies",
        ],
        "eradication": [
            "Review all activity post-compromise for this account",
            "Check for created backdoor accounts",
            "Validate credential stores for exposure",
        ],
        "recovery": [
            "Re-enable account with MFA after investigation",
            "Deploy additional authentication monitoring",
            "Update brute-force detection signatures",
        ],
    },
    "privilege_escalation": {
        "containment": [
            "Isolate affected host from network",
            "Disable compromised user accounts",
            "Terminate suspicious processes",
        ],
        "eradication": [
            "Remove exploitation vulnerabilities (patch/upgrade)",
            "Delete persistence mechanisms",
            "Review and harden sudoers configuration",
            "Audit all accounts with elevated privileges",
        ],
        "recovery": [
            "Restore host from known-good backup if compromised deeply",
            "Apply security patches before reconnecting",
            "Implement additional monitoring on host",
        ],
    },
    "rat_detected": {
        "containment": [
            "Immediately isolate affected host (network disconnect)",
            "Block all C2 IPs at perimeter firewall",
            "Disable all user accounts on affected system",
        ],
        "eradication": [
            "Perform full malware analysis (SPECTER + external)",
            "Identify and remove all RAT components",
            "Check for lateral spread to other hosts",
            "Rotate ALL credentials from affected system",
        ],
        "recovery": [
            "Rebuild host from clean image (recommended)",
            "Restore data from verified-clean backups",
            "Implement enhanced endpoint detection (EDR)",
            "Conduct full network sweep for similar IOCs",
        ],
    },
    "persistence_mechanism": {
        "containment": [
            "Disable identified persistence mechanisms",
            "Block access to modified system files",
            "Monitor for reinfection attempts",
        ],
        "eradication": [
            "Full file integrity scan of affected system",
            "Check for rootkit/kernel compromise",
            "Audit all scheduled tasks and services",
            "Scan backup systems for persistence",
        ],
        "recovery": [
            "Replace modified system binaries",
            "Implement file integrity monitoring (AIDE/Tripwire)",
            "Deploy automated persistence detection",
        ],
    },
    "deception_triggered": {
        "containment": [
            "Capture full traffic from attacker IP",
            "Increase monitoring on production assets",
            "Check if attacker reached non-decoy systems",
        ],
        "eradication": [
            "Block attacker IP at all perimeter devices",
            "Update decoy configurations to trap future attempts",
            "Share IOCs with team",
        ],
        "recovery": [
            "Deploy additional decoys in high-value areas",
            "Refine detection rules based on attacker behavior",
            "Update incident response playbooks",
        ],
    },
    "threat_intel_match": {
        "containment": [
            "Block all TI-Corr matched IOCs at perimeter",
            "Add high-confidence indicators to SIEM correlation rules",
            "Alert all relevant security monitoring systems",
        ],
        "eradication": [
            "Remove all matching indicators from environment",
            "Update WAF/IPS rules with new TTPs",
            "Scan environment for additional traces of the threat actor",
        ],
        "recovery": [
            "Document lessons learned from threat intel match",
            "Update detection playbooks with new IOCs",
            "Share threat intel with industry ISAC if applicable",
        ],
    },
    # ── New mitigation entries (improvement #2) ──
    "file_modification": {
        "containment": ["Quarantine modified files", "Isolate affected host"],
        "eradication": ["Restore files from known-good backup", "Patch vulnerability that allowed modification"],
        "recovery": ["Deploy file integrity monitoring", "Alert on future unauthorized modifications"],
    },
    "port_scan": {
        "containment": ["Block scanning IP at perimeter", "Enable port scan detection alerts"],
        "eradication": ["Verify no services were exploited post-scan", "Update firewall rules"],
        "recovery": ["Review IDS/IPS detection rules", "Conduct vulnerability scan on targeted hosts"],
    },
    "c2_beacon": {
        "containment": ["Block C2 IPs/domains at all egress points", "Isolate beaconing host"],
        "eradication": ["Remove malware causing beacon", "Kill C2 process and clean persistence"],
        "recovery": ["Monitor for C2 reconection", "Deploy network detection for beacon patterns"],
    },
    "data_exfiltration": {
        "containment": ["Block destination IP/domain", "Isolate source host"],
        "eradication": ["Identify and remove data access mechanisms", "Revoke compromised credentials"],
        "recovery": ["Assess data breach impact", "Notify affected parties per compliance requirements"],
    },
    "lateral_movement": {
        "containment": ["Disable compromised accounts", "Block attacker IPs from internal access"],
        "eradication": ["Clean all affected systems", "Check for additional compromise"],
        "recovery": ["Implement network segmentation", "Deploy internal threat hunting"],
    },
    "credential_dump": {
        "containment": ["Isolate system immediately", "Force password reset on all affected accounts"],
        "eradication": ["Remove credential dumping tools", "Patch vulnerable services"],
        "recovery": ["Implement credential guard/DPAPI protection", "Monitor for use of old credentials"],
    },
    "malware_detected": {
        "containment": ["Isolate host", "Quarantine malware file"],
        "eradication": ["Remove malware and all associated artifacts", "Run full SPECTER scan on host and peers"],
        "recovery": ["Implement enhanced EDR monitoring", "Update SPECTER signatures if novel malware"],
    },
    "unauthorized_access": {
        "containment": ["Disable compromised account", "Block unauthorized access source"],
        "eradication": ["Remove any unauthorized changes", "Audit account permissions"],
        "recovery": ["Implement least-privilege access controls", "Enable account activity logging"],
    },
    "ransomware": {
        "containment": ["ISOLATE ALL AFFECTED HOSTS IMMEDIATELY", "Block all egress to prevent C2 communication"],
        "eradication": ["Identify ransomware variant", "Remove malware and persistence", "Patch entry point"],
        "recovery": ["Restore from offline backups", "Implement backup immutability", "Deploy ransomware-specific EDR rules"],
    },
    "insider_threat": {
        "containment": ["Disable insider access immediately", "Preserve all evidence"],
        "eradication": ["Conduct interview with insider (HR/legal)", "Remove unauthorized software/access"],
        "recovery": ["Implement enhanced access monitoring", "Review and tighten RBAC policies"],
    },
    "dns_tunneling": {
        "containment": ["Block suspicious DNS queries at resolver", "Isolate affected host"],
        "eradication": ["Remove tunneling software", "Block C2 domains at DNS level"],
        "recovery": ["Deploy DNS monitoring and filtering", "Implement DNS response policy zones"],
    },
    "unauthorized_software": {
        "containment": ["Disable the unauthorized software", "Block installation source"],
        "eradication": ["Remove software from all affected systems"],
        "recovery": ["Implement software whitelisting", "Review software approval workflow"],
    },
    "supply_chain": {
        "containment": ["Isolate systems with compromised component", "Block download from compromised source"],
        "eradication": ["Remove/rollback compromised software update", "Scan for supply chain implant"],
        "recovery": ["Implement SBOM verification", "Adopt software provenance monitoring"],
    },
    "zero_day": {
        "containment": ["Isolate affected systems", "Deploy emergency WAF/IPS rules"],
        "eradication": ["Apply vendor-provided mitigation", "Remove exploitation artifacts"],
        "recovery": ["Monitor for exploitation of zero-day in environment", "Prepare for emergency patch"],
    },
    "cloud_compromise": {
        "containment": ["Revoke all cloud access tokens/keys", "Isolate compromised cloud account"],
        "eradication": ["Remove attacker access (IAM policies, backdoor accounts)", "Rotate all credentials"],
        "recovery": ["Implement cloud access monitoring", "Enable cloud threat detection rules"],
    },
    "email_attack": {
        "containment": ["Block sender domain/IP at email gateway", "Quarantine phishing email"],
        "eradication": ["Remove malicious attachments/links from all inboxes", "Reset affected account passwords"],
        "recovery": ["Send phishing awareness alert", "Update email gateway filters"],
    },
    "brute_force_ssh": {
        "containment": ["Block brute force source IP", "Disable targeted accounts"],
        "eradication": ["Remove unauthorized SSH keys", "Patch SSH vulnerabilities"],
        "recovery": ["Enable SSH key-only authentication", "Implement fail2ban for SSH"],
    },
}

# ────────────────────────────────────────────────────────────────
# SPECTER Integration — enrichment of IOC data with SPECTER DB
# ────────────────────────────────────────────────────────────────

SPECTER_DB_PATH = None  # Set by playbook_server.py

SPECTER_SIGNATURES: dict = {}  # Populated from SPECTER DB


def _load_specter_signatures() -> dict:
    """Load SPECTER signature DB for IOC enrichment."""
    global SPECTER_SIGNATURES
    if SPECTER_SIGNATURES:
        return SPECTER_SIGNATURES

    db_path = SPECTER_DB_PATH or str(Path(__file__).parent.parent / "SPECTER-THREAT" / "trintech_reports" / "specter_signatures.db")
    sig_path = Path(__file__).parent.parent / "SPECTER-THREAT" / "trintech_reports" / "signatures.json"

    if sig_path.exists():
        try:
            with open(sig_path) as f:
                SPECTER_SIGNATURES = json.load(f)
            log.debug(f"Loaded {len(SPECTER_SIGNATURES)} SPECTER signatures from {sig_path}")
        except (json.JSONDecodeError, KeyError):
            log.warning(f"Failed to load SPECTER signatures from {sig_path}")
    else:
        log.debug(f"SPECTER signatures DB not found at {sig_path}, continuing without enrichment")

    return SPECTER_SIGNATURES


def enrich_iocs_with_specter(iocs: dict) -> dict:
    """Enrich IOC data with SPECTER signature matching."""
    enriched = {**iocs, "specter_matches": [], "risk_scores": {}}
    sigs = _load_specter_signatures()
    if not sigs:
        return enriched

    # Match IPs against SPECTER C2 database
    if "c2_ips" in sigs:
        for ip in iocs["ips"]:
            if ip in sigs["c2_ips"]:
                entry = sigs["c2_ips"][ip]
                enriched["specter_matches"].append({
                    "ioc_type": "ip",
                    "ioc_value": ip,
                    "signature": entry.get("name", "Unknown C2"),
                    "severity": entry.get("severity", "HIGH"),
                    "family": entry.get("family", "Unknown"),
                    "confidence": entry.get("confidence", "high"),
                })
                enriched["risk_scores"][ip] = entry.get("severity_score", 7)

    # Match files against SPECTER malware hashes/names
    if "file_signatures" in sigs:
        for f in iocs["files"]:
            fname = Path(f).name.lower()
            for sig_name, sig_data in sigs["file_signatures"].items():
                if fname in sig_data.get("aliases", [sig_name]) or fname == sig_name:
                    enriched["specter_matches"].append({
                        "ioc_type": "file",
                        "ioc_value": f,
                        "signature": sig_name,
                        "severity": sig_data.get("severity", "HIGH"),
                        "family": sig_data.get("family", "Unknown"),
                        "confidence": "high",
                    })
                    enriched["risk_scores"][f] = sig_data.get("severity_score", 7)

    # Match processes against SPECTER process DB
    if "process_signatures" in sigs:
        for p in iocs["processes"]:
            pname = p.lower()
            for sig_name, sig_data in sigs["process_signatures"].items():
                if pname == sig_name or pname in sig_data.get("aliases", []):
                    enriched["specter_matches"].append({
                        "ioc_type": "process",
                        "ioc_value": p,
                        "signature": sig_name,
                        "severity": sig_data.get("severity", "HIGH"),
                        "family": sig_data.get("family", "Unknown"),
                        "confidence": "high",
                    })
                    enriched["risk_scores"][p] = sig_data.get("severity_score", 7)

    return enriched


# ────────────────────────────────────────────────────────────────
# Incident Status Lifecycle (improvement #3)
# ────────────────────────────────────────────────────────────────

VALID_STATUSES = ["GENERATED", "INVESTIGATING", "CONTAINED", "RESOLVED", "CLOSED"]
STATUS_TRANSITIONS = {
    "GENERATED": ["INVESTIGATING"],
    "INVESTIGATING": ["CONTAINED", "CLOSED"],
    "CONTAINED": ["RESOLVED"],
    "RESOLVED": ["CLOSED"],
}


class PlaybookStatusError(Exception):
    """Raised when an invalid status transition is attempted."""
    pass


def transition_playbook_status(current_status: str, new_status: str, reason: str = "") -> str:
    """Validate and perform a status transition. Returns new_status or raises."""
    if new_status not in VALID_STATUSES:
        raise PlaybookStatusError(f"Invalid status: {new_status}")
    if current_status not in STATUS_TRANSITIONS:
        raise PlaybookStatusError(f"No transitions from status: {current_status}")
    if new_status not in STATUS_TRANSITIONS[current_status]:
        valid_next = STATUS_TRANSITIONS.get(current_status, [])
        raise PlaybookStatusError(
            f"Invalid transition {current_status} → {new_status}. "
            f"Valid next statuses: {valid_next}"
        )
    return new_status


# ────────────────────────────────────────────────────────────────
# Data Model
# ────────────────────────────────────────────────────────────────

class Playbook:
    """A generated response playbook for an incident."""

    def __init__(self, incident, events=None, links=None, title=None, status=None):
        self.playbook_id = f"pb-{uuid.uuid4().hex[:8]}"
        if hasattr(incident, 'incident_id'):
            self.incident_id = incident.incident_id
        elif isinstance(incident, dict):
            self.incident_id = incident.get('incident_id', 'unknown')
        else:
            self.incident_id = str(incident)
        self.title = title or f"Response Playbook: {incident.tags[0] if hasattr(incident,'tags') and incident.tags else 'Security Incident'}"
        self.severity = incident.severity if hasattr(incident, 'severity') else incident.get('severity', 'UNKNOWN')
        self.status = status or "GENERATED"
        self.generated_at = datetime.now().isoformat()
        self.mitre_mappings: list[dict] = []
        self.containment_steps: list[dict] = []
        self.eradication_steps: list[dict] = []
        self.recovery_steps: list[dict] = []
        self.escalation: dict = {}
        self.iocs: dict = {"ips": [], "files": [], "processes": [], "users": []}
        self.affected_assets: list[str] = []
        self.playbook_text: str = ""
        self.notes: list[dict] = []
        self.status_history: list[dict] = [
            {"status": self.status, "timestamp": self.generated_at, "reason": "playbook generated"}
        ]
        self.enriched_iocs: dict = {}

        evts = events or []
        if not evts:
            if isinstance(incident, dict):
                evts = incident.get("events", [])
            elif hasattr(incident, "events"):
                evts = incident.events
        lnks = links or []
        if not lnks and isinstance(incident, dict):
            lnks = incident.get("links", [])
        elif not lnks and hasattr(incident, "links"):
            lnks = incident.links
        self._analyze(incident, evts, lnks)

    def _analyze(self, incident, events, links):
        self._stored_events = list(events)  # Store events for timeline rendering
        self._map_mitre(incident, events)
        self._extract_iocs(events)
        self._identify_assets(events)
        self.escalation = SEVERITY_ESCALATION.get(self.severity, SEVERITY_ESCALATION["INFO"])
        self._generate_response_steps(incident, events)
        self.playbook_text = self._render_text()

    def _map_mitre(self, incident, events):
        all_tags = set()
        if isinstance(incident, dict):
            all_tags.update(incident.get("tags", []))
        elif hasattr(incident, 'tags'):
            all_tags.update(incident.tags)
        for e in events:
            if isinstance(e, dict):
                all_tags.update(e.get("tags", []))
            elif hasattr(e, 'tags'):
                all_tags.update(e.tags)

        for tag in all_tags:
            if tag in MITRE_MAP:
                mapping = dict(MITRE_MAP[tag])
                mapping["matched_tag"] = tag
                self.mitre_mappings.append(mapping)

        if not self.mitre_mappings:
            if self.severity == "CRITICAL":
                self.mitre_mappings.append({
                    "technique": "T1059 — Command and Scripting Interpreter",
                    "tactic": "Execution",
                    "steps": SEVERITY_ESCALATION["CRITICAL"]["actions"],
                    "severity_weight": 10,
                })
            else:
                self.mitre_mappings.append({
                    "technique": "Multiple — See Investigation Notes",
                    "tactic": "Various",
                    "steps": ["Investigate event content manually", "Check for additional indicators"],
                    "severity_weight": 3,
                })

    def _extract_iocs(self, events):
        for e in events:
            if isinstance(e, dict):
                fields = e.get("fields") or {}
            elif hasattr(e, 'fields'):
                fields = e.fields or {}
            else:
                continue

            ip = fields.get("ip")
            if ip and ip not in self.iocs["ips"]:
                self.iocs["ips"].append(ip)

            file_path = fields.get("file")
            if file_path and file_path not in self.iocs["files"]:
                self.iocs["files"].append(file_path)

            process = fields.get("process")
            if process and process not in self.iocs["processes"]:
                self.iocs["processes"].append(process)

            user = fields.get("user")
            if user and user not in self.iocs["users"]:
                self.iocs["users"].append(user)

    def _identify_assets(self, events):
        """Identify affected assets from event fields and messages."""
        seen = set()
        for e in events:
            if isinstance(e, dict):
                fields = e.get("fields") or {}
                hostname = fields.get("hostname")
            elif hasattr(e, 'fields'):
                fields = e.fields or {}
                hostname = fields.get("hostname") if fields else None
            else:
                continue

            if hostname and hostname not in seen:
                self.affected_assets.append(hostname)
                seen.add(hostname)

            if isinstance(e, dict):
                msg = e.get("raw_message", "")
            elif hasattr(e, 'raw_message'):
                msg = e.raw_message
            else:
                msg = ""
            for m in re.findall(r'\b(?:host|server|workstation|node)[=: ]*([\w\.-]+)', msg, re.I):
                if m not in seen:
                    self.affected_assets.append(f"{m} (from log)")
                    seen.add(m)

    def _generate_response_steps(self, incident, events):
        """Generate containment, eradication, and recovery steps."""
        all_tags = set()
        if isinstance(incident, dict):
            all_tags.update(incident.get("tags", []))
        elif hasattr(incident, 'tags'):
            all_tags.update(incident.tags)
        for e in events:
            if isinstance(e, dict):
                all_tags.update(e.get("tags", []))
            elif hasattr(e, 'tags'):
                all_tags.update(e.tags)

        containment_set = set()
        eradication_set = set()
        recovery_set = set()

        for tag in all_tags:
            if tag in MITIGATION_MAP:
                for s in MITIGATION_MAP[tag]["containment"]:
                    containment_set.add(s)
                for s in MITIGATION_MAP[tag]["eradication"]:
                    eradication_set.add(s)
                for s in MITIGATION_MAP[tag]["recovery"]:
                    recovery_set.add(s)

        if self.iocs["ips"]:
            for ip in self.iocs["ips"]:
                block_action = f"Block IP {ip} at firewall (ingress and egress)"
                if block_action not in containment_set:
                    containment_set.add(block_action)

        self.containment_steps = [{"step": s, "order": i+1} for i, s in enumerate(sorted(containment_set))]
        self.eradication_steps = [{"step": s, "order": i+1} for i, s in enumerate(sorted(eradication_set))]
        self.recovery_steps = [{"step": s, "order": i+1} for i, s in enumerate(sorted(recovery_set))]

    # ── New methods (improvements #3, #4, #6, #10) ──

    def add_note(self, note: str, source: str = "system"):
        """Add a note to the playbook with timestamp."""
        self.notes.append({
            "time": datetime.now().isoformat(),
            "note": note,
            "source": source,
        })

    def transition_status(self, new_status: str, reason: str = ""):
        """Transition playbook to a new status with validation and audit trail."""
        current = self.status
        new_status = transition_playbook_status(current, new_status, reason)
        self.status = new_status
        self.status_history.append({
            "status": new_status,
            "timestamp": datetime.now().isoformat(),
            "previous_status": current,
            "reason": reason,
        })
        log.info(f"Playbook {self.playbook_id} transitioned: {current} → {new_status} ({reason})")
        return new_status

    def _build_timeline(self) -> list[dict]:
        """Build a timeline from incident events."""
        timeline = []
        for e in self._get_all_events():
            timeline.append({
                "time": e.get("timestamp", "unknown"),
                "source": e.get("source", "unknown"),
                "message": e.get("raw_message", ""),
                "severity": e.get("severity", "unknown"),
            })
        timeline.sort(key=lambda x: x["time"])
        return timeline

    def _get_all_events(self) -> list[dict]:
        """Get all events from incident (dict or object)."""
        # This is called during __init__, so self has incident info stored
        return getattr(self, "_stored_events", [])

    def render_text_with_timeline(self) -> str:
        """Render playbook text with embedded timeline view."""
        events = getattr(self, "_stored_events", [])
        if not events:
            return self.playbook_text

        lines = [self.playbook_text]  # Full text first
        lines.append("")
        lines.append("-" * 70)
        lines.append("  EVENT TIMELINE")
        lines.append("-" * 70)

        timeline = sorted(events, key=lambda e: e.get("timestamp", ""))
        for e in timeline:
            sev = e.get("severity", "INFO")[:4]
            lines.append(
                f"  {e.get('timestamp', '?')} [{sev}] {e.get('source', '?'):15s} — {e.get('raw_message', '')}"
            )

        return "\n".join(lines)

    def export_pdf(self) -> str:
        """Export playbook as PDF text placeholder.

        Returns the PDF content as bytes (or raises if reportlab not installed).
        """
        try:
            from reportlab.lib.pagesizes import A4
            from reportlab.pdfgen import canvas
            from io import BytesIO

            buf = BytesIO()
            c = canvas.Canvas(buf, pagesize=A4)
            width, height = A4

            c.setFont("Helvetica", CONFIG["pdf_defaults"]["font_size"])
            y = height - CONFIG["pdf_defaults"]["margin"]

            # Title
            c.setFont("Helvetica-Bold", 16)
            c.drawString(40, y, self.title)
            y -= 30

            # Metadata
            c.setFont("Helvetica", 9)
            c.drawString(40, y, f"Playbook ID: {self.playbook_id} | Severity: {self.severity} | Status: {self.status}")
            y -= 20
            c.drawString(40, y, f"Generated: {self.generated_at} | Incident: {self.incident_id}")
            y -= 40

            # Escalation
            c.setFont("Helvetica-Bold", 12)
            c.drawString(40, y, "Escalation")
            y -= 18
            esc = self.escalation
            c.setFont("Helvetica", 10)
            c.drawString(40, y, f"Priority: {esc.get('priority', '')} | Response: {esc.get('response_time', '')} | Notify: {', '.join(esc.get('notify', []))}")
            y -= 25

            # Sections
            sections = [
                ("MITRE ATT&CK Mappings", self.mitre_mappings, "mitre"),
                ("Indicators of Compromise", self.iocs, "iocs"),
                ("Containment Steps", self.containment_steps, "steps"),
                ("Eradication Steps", self.eradication_steps, "steps"),
                ("Recovery Steps", self.recovery_steps, "steps"),
            ]

            for section_name, data, fmt in sections:
                if not data:
                    continue

                if y < CONFIG["pdf_defaults"]["margin"] + 30:
                    c.showPage()
                    c.setFont("Helvetica-Bold", 12)
                    c.drawString(40, height - CONFIG["pdf_defaults"]["margin"], section_name)
                    y = height - CONFIG["pdf_defaults"]["margin"] - 20

                c.setFont("Helvetica-Bold", 12)
                c.drawString(40, y, section_name)
                y -= 20
                c.setFont("Helvetica", 10)

                if fmt == "mitre" and isinstance(data, list):
                    for m in data:
                        c.drawString(50, y, f"• {m.get('technique', '')} [{m.get('tactic', '')}]")
                        y -= 14
                        for s in m.get("steps", []):
                            c.drawString(60, y, f"  ▸ {s}")
                            y -= 14
                            if y < CONFIG["pdf_defaults"]["margin"] + 20:
                                c.showPage()
                                y = height - CONFIG["pdf_defaults"]["margin"]
                elif fmt == "iocs" and isinstance(data, dict):
                    for ioc_type in ["ips", "files", "processes", "users"]:
                        items = data.get(ioc_type, [])
                        if items:
                            c.drawString(50, y, f"{ioc_type.replace('_', ' ').title()}:")
                            y -= 14
                            for item in items:
                                c.drawString(60, y, f"  • {item}")
                                y -= 14
                elif fmt == "steps" and isinstance(data, list):
                    for s in data:
                        c.drawString(50, y, f"[{s.get('order', '')}] {s.get('step', '')}")
                        y -= 14

                y -= 15

            # Footer
            c.setFont("Helvetica-Oblique", 8)
            c.drawString(40, 20, f"TrinTech Playbook Generator — {datetime.now().strftime('%Y-%m-%d %H:%M')}")

            c.save()
            buf.seek(0)
            return buf.getvalue()

        except ImportError:
            log.warning("reportlab not installed. Install with: pip install reportlab")
            # Return plain text fallback
            return self.render_text_with_timeline().encode("utf-8")

    def _render_text(self) -> str:
        """Render full playbook as text."""
        lines = []
        lines.append("=" * 70)
        lines.append(f"  {self.title}")
        lines.append(f"  Playbook ID: {self.playbook_id}")
        lines.append(f"  Severity: {self.severity}")
        lines.append(f"  Status: {self.status}")
        lines.append(f"  Generated: {self.generated_at}")
        lines.append("=" * 70)
        lines.append("")

        # Escalation
        esc = self.escalation
        lines.append(f"  ESCALATION: {esc.get('priority', 'P5')}")
        lines.append(f"  Response Time: {esc.get('response_time', 'N/A')}")
        lines.append(f"  Notify: {', '.join(esc.get('notify', []))}")
        lines.append("")
        lines.append("  Immediate Actions:")
        for a in esc.get("actions", []):
            lines.append(f"    ▸ {a}")
        lines.append("")

        # MITRE
        lines.append("-" * 70)
        lines.append("  MITRE ATT&CK MAPPINGS")
        lines.append("-" * 70)
        for m in self.mitre_mappings:
            lines.append(f"  Technique: {m['technique']}")
            lines.append(f"  Tactic:    {m['tactic']}")
            for s in m["steps"]:
                lines.append(f"    ▸ {s}")
            lines.append("")

        # IOCs
        lines.append("-" * 70)
        lines.append("  INDICATORS OF COMPROMISE (IOCs)")
        lines.append("-" * 70)
        if self.iocs["ips"]:
            lines.append("  Attacker IPs:")
            for ip in self.iocs["ips"]:
                lines.append(f"    ⚠ {ip}")
        if self.iocs["files"]:
            lines.append("  Compromised Files:")
            for f in self.iocs["files"]:
                lines.append(f"    ⚠ {f}")
        if self.iocs["processes"]:
            lines.append("  Malicious Processes:")
            for p in self.iocs["processes"]:
                lines.append(f"    ⚠ {p}")
        if self.iocs["users"]:
            lines.append("  Affected Users:")
            for u in self.iocs["users"]:
                lines.append(f"    ⚠ {u}")
        if not any(self.iocs.values()):
            lines.append("  No specific IOCs extracted. Review event content.")
        lines.append("")

        # SPECTER enrichment
        if self.enriched_iocs.get("specter_matches"):
            lines.append("-" * 70)
            lines.append("  SPECTER ENRICHMENT")
            lines.append("-" * 70)
            for match in self.enriched_iocs["specter_matches"]:
                lines.append(f"  {match['ioc_type'].upper()} {match['ioc_value']}:")
                lines.append(f"    Signature: {match['signature']}")
                lines.append(f"    Family: {match['family']} | Severity: {match['severity']}")
                lines.append(f"    Confidence: {match['confidence']}")
                lines.append("")

        # Affected Assets
        if self.affected_assets:
            lines.append("-" * 70)
            lines.append("  AFFECTED ASSETS")
            lines.append("-" * 70)
            for a in self.affected_assets:
                lines.append(f"  🖥 {a}")
            lines.append("")

        # Timeline
        lines.append("-" * 70)
        lines.append("  EVENT TIMELINE")
        lines.append("-" * 70)
        for e in getattr(self, "_stored_events", []):
            if isinstance(e, dict):
                sev = e.get("severity", "INFO")[:4]
                lines.append(
                    f"  {e.get('timestamp', '?')} [{sev}] {e.get('source', '?'):15s} — {e.get('raw_message', '')}"
                )
            elif hasattr(e, 'severity'):
                lines.append(
                    f"  {getattr(e, 'timestamp', '?')} [{e.severity}] {getattr(e, 'source', '?'):15s} — {getattr(e, 'raw_message', '')}"
                )
        lines.append("")

        # Containment
        lines.append("-" * 70)
        lines.append("  PHASE 1: CONTAINMENT")
        lines.append("-" * 70)
        for s in self.containment_steps:
            lines.append(f"  [{s['order']}] {s['step']}")
        lines.append("")

        # Eradication
        lines.append("-" * 70)
        lines.append("  PHASE 2: ERADICATION")
        lines.append("-" * 70)
        for s in self.eradication_steps:
            lines.append(f"  [{s['order']}] {s['step']}")
        lines.append("")

        # Recovery
        lines.append("-" * 70)
        lines.append("  PHASE 3: RECOVERY")
        lines.append("-" * 70)
        for s in self.recovery_steps:
            lines.append(f"  [{s['order']}] {s['step']}")
        lines.append("")

        # Firewall rules
        if self.iocs["ips"]:
            lines.append("-" * 70)
            lines.append("  AUTO-GENERATED FIREWALL RULES")
            lines.append("-" * 70)
            for ip in self.iocs["ips"]:
                lines.append(f"  iptables -A INPUT -s {ip} -j DROP")
                lines.append(f"  iptables -A OUTPUT -d {ip} -j DROP")
            lines.append("")

        # Status history / notes
        if self.status_history:
            lines.append("-" * 70)
            lines.append("  STATUS HISTORY")
            lines.append("-" * 70)
            for sh in self.status_history:
                lines.append(f"  {sh['timestamp']} [{sh['status']}] {sh.get('reason', '')}")
            lines.append("")

        if self.notes:
            lines.append("-" * 70)
            lines.append("  NOTES")
            lines.append("-" * 70)
            for note in self.notes:
                lines.append(f"  {note['time']} [{note.get('source', 'system')}] {note['note']}")
            lines.append("")

        lines.append("=" * 70)
        lines.append("  END OF PLAYBOOK")
        lines.append("=" * 70)

        return "\n".join(lines)

    def to_dict(self) -> dict:
        """Serialize playbook to dictionary (for API/DB storage)."""
        return {
            "playbook_id": self.playbook_id,
            "incident_id": self.incident_id,
            "title": self.title,
            "severity": self.severity,
            "status": self.status,
            "generated_at": self.generated_at,
            "mitre_mappings": self.mitre_mappings,
            "containment_steps": self.containment_steps,
            "eradication_steps": self.eradication_steps,
            "recovery_steps": self.recovery_steps,
            "escalation": self.escalation,
            "iocs": self.iocs,
            "affected_assets": self.affected_assets,
            "playbook_text": self.playbook_text,
            "notes": self.notes,
            "status_history": self.status_history,
            "enriched_iocs": self.enriched_iocs,
        }

    def to_dict_full(self) -> dict:
        """Full serialization including raw events for reconstitution."""
        d = self.to_dict()
        d["events"] = getattr(self, "_stored_events", [])
        return d


# ────────────────────────────────────────────────────────────────
# Escalation Templates (severity → notification actions)
# ────────────────────────────────────────────────────────────────

SEVERITY_ESCALATION = {
    "CRITICAL": {
        "priority": "P1 — IMMEDIATE",
        "response_time": "15 minutes",
        "notify": ["CISO", "SOC Lead", "Incident Commander", "Legal"],
        "actions": [
            "Activate incident response team immediately",
            "Isolate affected network segment",
            "Preserve all evidence (memory, disk, network)",
            "Begin external communication plan (regulatory if data breach)",
            "Engage external forensics firm if internal capability exceeded",
        ],
    },
    "HIGH": {
        "priority": "P2 — URGENT",
        "response_time": "1 hour",
        "notify": ["SOC Lead", "Incident Commander"],
        "actions": [
            "Assign senior analyst to investigation",
            "Implement containment measures",
            "Begin forensic data collection",
            "Update threat hunting queries with new IOCs",
        ],
    },
    "MEDIUM": {
        "priority": "P3 — STANDARD",
        "response_time": "4 hours",
        "notify": ["SOC Analyst On-Call"],
        "actions": [
            "Add to investigation queue",
            "Review related events in timeline",
            "Update detection rules if pattern is novel",
        ],
    },
    "LOW": {
        "priority": "P4 — LOW",
        "response_time": "24 hours",
        "notify": ["SOC Analyst"],
        "actions": ["Review during next shift", "Archive if confirmed false positive", "Use for detection tuning"],
    },
    "INFO": {
        "priority": "P5 — INFORMATIONAL",
        "response_time": "No immediate action",
        "notify": ["System Log Only"],
        "actions": ["Log for trend analysis", "Review quarterly"],
    },
}

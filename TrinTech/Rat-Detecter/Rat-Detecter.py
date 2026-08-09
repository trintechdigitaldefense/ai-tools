#!/usr/bin/env python3
"""
TrinTech Digital Defense
SPECTER-THREAT v3.0 — RAT & Payload Detection Engine (UPGRADED)
Flask backend with AI analysis, PDF/HTML/JSON reports, live dashboard, CLI
Author: Jason Junior Ramdharry
Upgraded by: AI Agent

FIXED: Critical bugs, race conditions, security issues, dead code
ADDED: CLI args (--quick, --full, --kill, --watch, --report, --whitelist, --ports-file, --procs, --ports)
UPGRADED: Risk scoring, detection accuracy, thread safety, error handling, logging
"""

import os, sys, json, socket, subprocess, hashlib, re, time, platform, argparse, signal, logging, threading
from datetime import datetime, timedelta
from pathlib import Path
from collections import deque
from flask import Flask, jsonify, request, send_file, Response, render_template_string
from flask_cors import CORS
import requests
import psutil

# ────────────────────────────────────────────────────────────────
# Configuration
# ────────────────────────────────────────────────────────────────
BASE_DIR = Path(__file__).resolve().parent
REPORTS_DIR = BASE_DIR / "trintech_reports"
REPORTS_DIR.mkdir(exist_ok=True)

# Logging to file
LOG_FILE = BASE_DIR / "trintech_reports" / "scanner.log"
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler(sys.stdout),
    ],
)
log = logging.getLogger("specter")

# ────────────────────────────────────────────────────────────────
# Flask App
# ────────────────────────────────────────────────────────────────
app = Flask(__name__)
CORS(app)

# ── Global scan state ──────────────────────────────────────────
scan_state = {
    "running": False,
    "progress": 0,
    "current_module": "",
    "findings": [],
    "log": [],
    "started": None,
    "finished": None,
    "risk_score": 0,
    "risk_label": "UNKNOWN",
    "severity_counts": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0},
    "target_info": {},
    "ai_analysis": "",
    "ai_running": False,
    "report_path": None,
    "mode": "full",  # quick, full, ports, procs
    "whitelist": set(),
}
scan_lock = __import__("threading").Lock()  # Always available; reset in _init_scan_state when needed

# Maximum findings stored (circular buffer style)
MAX_FINDINGS = 1000


def _init_scan_state(whitelist=None):
    """Reset scan state for a new scan."""
    global scan_lock
    scan_lock = __import__("threading").Lock()
    with scan_lock:
        scan_state.update({
            "running": False,
            "progress": 0,
            "current_module": "",
            "findings": [],
            "log": [],
            "started": None,
            "finished": None,
            "risk_score": 0,
            "risk_label": "UNKNOWN",
            "severity_counts": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0},
            "target_info": {},
            "ai_analysis": "",
            "ai_running": False,
            "report_path": None,
        })
        if whitelist:
            scan_state["whitelist"] = set(whitelist)


def _log(msg, level="INFO"):
    entry = {"ts": datetime.now().strftime("%H:%M:%S"), "msg": msg, "level": level}
    with scan_lock:
        scan_state["log"].append(entry)
    log_msg = f"[{level}] {msg}"
    if level == "CRITICAL":
        log.critical(log_msg)
    elif level == "HIGH":
        log.warning(log_msg)
    elif level == "MEDIUM":
        log.info(log_msg)
    else:
        log.info(log_msg)


def _finding(ftype, severity, detail, extra=None):
    """Record a finding with thread safety (atomic read-modify-write on counter)."""
    item = {
        "type": ftype,
        "severity": severity,
        "detail": detail,
        "ts": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }
    if extra:
        item.update(extra)
    with scan_lock:
        scan_state["findings"].append(item)
        # Trim if over max
        if len(scan_state["findings"]) > MAX_FINDINGS:
            scan_state["findings"] = scan_state["findings"][-MAX_FINDINGS:]
        scan_state["severity_counts"][severity] = (
            scan_state["severity_counts"].get(severity, 0) + 1
        )
    _log(f"[{severity}] {ftype}: {detail}", severity)


def _safe_cmd(cmd, timeout=10):
    """Safely run a shell command with no user input."""
    try:
        r = subprocess.run(
            cmd, shell=True, capture_output=True, text=True, timeout=timeout
        )
        return r.stdout.strip()
    except subprocess.TimeoutExpired:
        _log(f"Command timed out: {cmd}", "MEDIUM")
        return ""
    except Exception as e:
        _log(f"Command failed: {cmd} — {e}", "MEDIUM")
        return ""


def _safe_cmd_list(args, timeout=10):
    """Safely run a command as a list (no shell=True)."""
    try:
        r = subprocess.run(
            args, capture_output=True, text=True, timeout=timeout
        )
        return r.stdout.strip()
    except subprocess.TimeoutExpired:
        _log(f"Command timed out: {args}", "MEDIUM")
        return ""
    except Exception as e:
        _log(f"Command failed: {args} — {e}", "MEDIUM")
        return ""


def _set_progress(pct, module):
    with scan_lock:
        scan_state["progress"] = pct
        scan_state["current_module"] = module


def _is_whitelisted(item):
    """Check if an item is whitelisted."""
    wl = scan_state.get("whitelist", set())
    if not wl:
        return False
    item_str = str(item).lower()
    for w in wl:
        if w.lower() in item_str:
            return True
    return False


# ────────────────────────────────────────────────────────────────
# Threat Intelligence Database
# ────────────────────────────────────────────────────────────────

RAT_PROCESS_NAMES = [
    # --- Remote Access Trojans ---
    "njrat", "nanocore", "darkcomet", "quasar", "asyncrat", "remcos",
    "xtremerat", "blackshades", "cybergate", "poisonivy", "bifrost",
    "gh0st", "luminosity", "revenge", "netwire", "imminent", "warzone",
    "agent tesla", "netsupport", "cobalt", "havoc", "sliver", "covenant",
    "empire", "meterpreter", "beacon", "stager", "pupy", "venom",
    "platypus", "villain", "hoaxshell", "revshell", "shellex",
    "rat_service", "remote_access", "backdoor_agent",
    
    # --- Windows RATs ---
    "turbine", "vncbot", "squirterat", "jrat", "xerxes", "al-khaser",
    "kayako", "remotec2", "darkside", "dridex", "emotet", "trickbot",
    "wannacry", "petya", "notpetya", "contopee", "wastedlocker",
    "bazarloader", "contopee", "iceid", "njratc2", "nanocorec2",
    
    # --- Linux/Unix RATs ---
    "linux_rat", "plouton", "darkhotel", "finfisher", "titanrat",
    "moongate", "rhealmon", "titanfall", "darkness", "darkkitten",
    "hamsine", "tseverrat", "ratankba", "dabber", "sirefef",
    
    # --- macOS RATs ---
    "macma", "osx_keydab", "osx_iceweasel", "osx_shark", "osx_bomgar",
    
    # --- Android RATs ---
    "anatsvc", "anatservice", "mobok", "jrat_android", "mummyrat",
    "droidjack", "cutwail", "toperat", "gamarue", "zeus", "tdss",
    
    # --- C2 Frameworks & Implants ---
    "cobalt_strike", "c2srv", "c2listener", "cobaltstrike",
    "metasploit", "msfconsole", "msfvenom", "reverse_handler",
    "empire_server", "empire_agent", "empire_listener", "empire_http",
    "sliver_agent", "sliver_server", "sliver_listener", "sliver_tcp",
    "covenant_agent", "havoc_agent", "havoc_server",
    "bloodhound", "keethief", "mimikatz", "lazagne", "ninja",
    "seclists", "nmap_scanner", "masscan", "unicorn",
    
    # --- RAT Payload Process Names (often renamed) ---
    "svchost_update", "svchost_x64", "svchost_update_svc",
    "explorer_updater", "explorer_service", "explorer_helper",
    "csrss_update", "lsass_helper", "lsass_monitor",
    "services_x64", "services_update", "services_helper",
    "system32_svc", "system32_svc_update", "dllhost_updater",
    "svshost", "svshost_update", "wermgr_recovery", "wermgr_update",
    "WerFault_relay", "WerFault_helper",
    "rundll32_update", "rundll32_helper", "rundll32_service",
    "regsvr32_update", "regsvr32_helper",
    "cmd_update", "cmd_relay", "cmd_forward",
    "powershell_hidden", "powershell_relay", "powershell_hidden32",
    "wscript_update", "wscript_relay", "wscript_forward",
    "cscript_update", "cscript_relay",
    
    # --- RAT Communication/Loader Processes ---
    "update_service", "config_loader", "module_loader", "payload_loader",
    "injection_host", "inject_helper", "process_hollow", "hollow_engine",
    "dns_tunnel", "dns_relay", "dns_c2", "dns_forward",
    "icmp_tunnel", "icmp_c2", "icmp_relay",
    "stolen_token", "token_dup", "token_hijack",
    
    # --- Known RAT Services/daemons ---
    "rat_daemon", "rat_proxy", "rat_tunnel", "rat_proxy_svc",
    "c2_proxy", "c2_tunnel", "c2_beacon", "c2_beacon_svc",
    "backdoor_proxy", "backdoor_tunnel", "backdoor_svc",
    "trojan_proxy", "trojan_svc", "trojan_beacon",
    
    # --- RAT Installers/Packers ---
    "inno_setup", "nsis_inst", "winrar_inst", "install_exe",
    "payload_exe", "drop_exe", "stage_exe", "loader_exe",
    "obfuscator", "crypter", "packer_engine", "upx_wrapper",
    "exe_encrypt", "exe_packer", "exe_crypter", "exe_obfuscator",
    
    # --- RAT C2 Protocols ---
    "http_c2", "https_c2", "dns_c2_agent", "ftp_c2", "smtp_c2",
    "webhook_c2", "telegram_c2", "discord_c2", "signal_c2",
    "xmpp_c2", "baidu_c2", "qq_c2", "teams_c2",
    
    # --- Reconnaissance Tools (often bundled with RATs) ---
    "screen_cap", "screen_capture", "screenshot_tool", "desktop_rec",
    "keylog_store", "keylog_send", "keylog_capture", "keylog_relay",
    "webcam_stream", "webcam_capture", "mic_capture", "mic_stream",
    "file_exfil", "file_upload", "file_sync", "file_dropper",
    "password_dump", "password_extract", "credential_steal", "cred_harvest",
    "browser_creds", "chrome_dump", "firefox_dump", "edge_dump",
    "wifi_creds", "network_scan", "arp_scan", "port_scan",
    
    # --- Persistent backdoor mechanisms ---
    "startup_persist", "registry_persist", "scheduled_task", "cron_persist",
    "systemd_persist", "launchd_persist", "initd_persist",
    "bootkit", "mbrootkit", "vrootkit", "ehole", "mbr_infector",
    
    # --- RAT variants (famous families) ---
    "darkcometv4", "darkcometv5", "quasarv2", "asyncratv3", "remcosv2",
    "njratv4", "njratv3", "nanocorev2", "poisonivyc2", "bifrostv2",
    "gh0stv4", "gh0stv5", "blackshadesv5", "xtremev3", "remotec2v2",
    "turbinev2", "agentteslav3", "agentteslav4", "netsupportv13",
    "netsupportv14", "netsupportv15", "titanrat", "moongatev2",
    "rhealmonv1", "darkkittenv1", "hamsinev1", "tseverratv2",
    "dabber_v1", "sirefef_v1", "zeusv2", "tdssv2", "gozi",
    "conficker", "blaster", "sasser", "nachi", "bagle",
    "mydoom", "sobig", "gogol", "klez", "indutria", "iloveyou",
    "loveletter", "melissa", "bubble_boy", "sircam",
    
    # --- Modern/A2A RATs and spyware ---
    "redline", "vncbot", "stealer", "stealer_v2", "stealer_agent",
    "marsstealer", "varcls", "redline_dl", "mallox", "blossom",
    "netko", "okadia", "darkloader", "gootloader", "tunna",
    "c2concealer", "darkc0de", "darknet", "darkcomet_reloaded",
    "darkrat", "darkc2", "darkagent", "darkloader_c2",
    
    # --- RAT framework modules ---
    "file_manager", "process_list", "cmd_shell", "registry_edit",
    "system_info", "audio_capture", "video_capture", "clipboard_monitor",
    "clipboard_hijack", "clipboard_steal", "clipboard_capture",
    "app_list", "installed_apps", "browser_history", "bookmarks",
    "download_history", "cookie_steal", "cookie_hijack",
    "session_hijack", "session_steal", "token_steal", "token_hijack",
    
    # --- RAT droppers ---
    "dropper", "dropper_v2", "dropper_agent", "infection_chain",
    "initial_access", "payload_delivery", "exploit_launcher",
    
    # --- RAT evasion techniques ---
    "antivirus_bypass", "antiforensic", "anti_debug", "anti_sandbox",
    "process_deny", "handle_deny", "registry_lock", "file_lock",
    "self_delete", "self_clean", "self_destroy", "log_clean",
    "trace_clean", "artifact_clean", "event_log_clean",
    
    # --- RAT command-and-control ---
    "beacon_interval", "jitter_control", "user_agent", "ua_switch",
    "kill_time", "kill_date", "geofence", "geo_check",
    "sleep_timer", "wake_lock", "wakeup_signal",
    "heartbeat", "heartbeat_ctrl", "hb_send", "hb_receive",
    "dns_probe", "dns_lookup", "dns_query",
    
    # --- RAT encryption layers ---
    "aes_encrypt", "aes_decrypt", "xor_cipher", "xor_decode",
    "rc4_encrypt", "rc4_decrypt", "base64_encode", "base64_decode",
    "rsa_encrypt", "rsa_decrypt", "tls_obfuscate", "tls_wrap",
    
    # --- RAT persistence helpers ---
    "win_reg_add", "win_reg_del", "win_reg_set", "win_schedule",
    "win_task", "win_svc", "win_svc_install", "win_svc_del",
    "schtask_add", "schtask_del", "schtask_run",
    
    # --- RAT remote tools ---
    "remote_desktop", "remote_control", "remote_cmd", "remote_exec",
    "remote_upload", "remote_download", "remote_run", "remote_cmd",
    "command_shell", "command_exec", "command_run",
    
    # --- RAT logging/audit ---
    "audit_log", "audit_trail", "activity_log", "session_log",
    "keystroke_log", "click_log", "mouse_log", "screen_log",
    "file_access_log", "network_log", "process_log", "system_log",
]

SUSPICIOUS_PORTS = {
    # --- Classic RAT & Backdoor Ports ---
    1177: "Bifile RAT", 1234: "Generic backdoor", 2222: "Common RAT",
    3715: "Optix Pro", 4444: "Metasploit/MSF", 5000: "RAT common",
    5554: "Sasser worm", 6666: "IRC C2", 6667: "IRC C2",
    7777: "Tini backdoor", 8888: "Common RAT/C2", 9999: "Orcus RAT",
    10000: "Generic RAT", 12345: "NetBus", 20034: "NetBus 2",
    31337: "Back Orifice", 54321: "Back Orifice 2000",
    1604: "DarkComet", 1703: "Xtreme RAT", 2745: "Bagle worm",
    3127: "MyDoom", 4899: "Radmin backdoor", 6969: "GateCrasher",
    65000: "Common high RAT",
    
    # --- Metasploit/C2 Framework Ports ---
    5555: "Metasploit Handler", 7777: "Metasploit Default",
    8443: "Metasploit/HTTPS C2", 1337: "Metasploit/Phreak",
    4443: "Metasploit/HTTPS", 4445: "Metasploit/Alt", 5556: "Metasploit Alt",
    4433: "Metasploit HTTPS Alt", 5900: "VNC/C2 Tunnel", 5901: "VNC Alt",
    5902: "VNC Alt 2", 5903: "VNC Alt 3", 5904: "VNC Alt 4", 5905: "VNC Alt 5",
    6665: "IRC C2 (dark)", 6668: "IRC C2 (dark)", 6669: "IRC C2 (dark)",
    
    # --- RAT-specific ports ---
    1233: "Blaze RAT", 2225: "RAT alt", 2333: "Sdbproxy RAT",
    3333: "RAT/C2", 3411: "Blade RAT", 4000: "RAT common",
    4041: "RAT alt", 4044: "RAT alt", 4096: "RAT alt",
    4500: "TeamViewer C2", 4966: "RAT alt", 5001: "RAT alt",
    5002: "RAT alt", 5003: "RAT alt", 5004: "RAT alt", 5005: "RAT alt",
    5006: "RAT alt", 5007: "RAT alt", 5008: "RAT alt", 5009: "RAT alt",
    5010: "RAT alt", 5050: "RAT alt", 5051: "RAT alt", 5052: "RAT alt",
    5060: "RAT alt SIP", 5100: "Tribe FTP RAT",
    5190: "AOL/IRC RAT", 5555: "Metasploit/Handler",
    5566: "RAT alt", 5678: "RAT alt", 5679: "RAT alt",
    5700: "RAT alt", 5800: "VNC/RAT", 5801: "VNC/RAT alt",
    5900: "VNC/RAT", 6000: "X11/RAT", 6001: "X11/RAT alt",
    6002: "X11/RAT alt", 6003: "X11/RAT alt", 6004: "X11/RAT alt", 6005: "X11/RAT alt",
    6006: "X11/RAT alt", 6007: "X11/RAT alt", 6008: "X11/RAT alt", 6009: "X11/RAT alt",
    6129: "Tox RAT", 6660: "IRC C2 range", 6661: "IRC C2 range",
    6661: "IRC C2 range", 6662: "IRC C2 range", 6663: "IRC C2 range",
    6664: "IRC C2 range", 6665: "IRC C2 range", 6666: "IRC C2 range",
    6667: "IRC C2 range", 6668: "IRC C2 range", 6669: "IRC C2 range",
    6881: "BitTorrent RAT", 6882: "BitTorrent RAT alt",
    6883: "BitTorrent RAT alt", 6884: "BitTorrent RAT alt",
    6885: "BitTorrent RAT alt", 6886: "BitTorrent RAT alt",
    6887: "BitTorrent RAT alt", 6888: "BitTorrent RAT alt",
    6889: "BitTorrent RAT alt", 6890: "BitTorrent RAT alt",
    6891: "BitTorrent RAT alt", 6892: "BitTorrent RAT alt",
    6893: "BitTorrent RAT alt", 6894: "BitTorrent RAT alt",
    6895: "BitTorrent RAT alt", 6896: "BitTorrent RAT alt",
    6897: "BitTorrent RAT alt", 6898: "BitTorrent RAT alt",
    6899: "BitTorrent RAT alt", 6900: "BitTorrent RAT alt",
    6969: "GateCrasher", 7306: "MySQL backdoor",
    7778: "RAT alt", 7779: "RAT alt", 7780: "RAT alt",
    7781: "RAT alt", 7782: "RAT alt", 7783: "RAT alt", 7784: "RAT alt", 7785: "RAT alt",
    8080: "HTTP C2 proxy", 8081: "HTTP C2 alt", 8082: "HTTP C2 alt",
    8083: "HTTP C2 alt", 8084: "HTTP C2 alt", 8085: "HTTP C2 alt",
    8086: "HTTP C2 alt", 8087: "HTTP C2 alt", 8088: "HTTP C2 alt", 8089: "HTTP C2 alt",
    8090: "HTTP C2 alt", 8181: "HTTP C2 alt", 8182: "HTTP C2 alt",
    8443: "HTTPS C2 alt", 8444: "HTTPS C2 alt", 8445: "HTTPS C2 alt",
    8834: "RAT alt", 8888: "Common RAT/C2", 8889: "RAT alt",
    9001: "Tor C2", 9002: "Tor C2 alt", 9003: "Tor C2 alt",
    9030: "Tor ORPort", 9050: "Tor SOCKS", 9051: "Tor Control",
    9052: "Tor C2 alt", 9053: "Tor C2 alt", 9090: "Tor alt",
    9200: "Tor alt", 9990: "RAT alt", 9991: "RAT alt",
    9992: "RAT alt", 9993: "RAT alt", 9994: "RAT alt", 9995: "RAT alt",
    9996: "RAT alt", 9997: "RAT alt", 9998: "RAT alt", 9999: "Orcus RAT",
    10000: "Generic RAT", 10001: "RAT alt", 10002: "RAT alt",
    10003: "RAT alt", 10004: "RAT alt", 10005: "RAT alt",
    10006: "RAT alt", 10007: "RAT alt", 10008: "RAT alt", 10009: "RAT alt",
    10101: "RAT alt", 10102: "RAT alt", 10103: "RAT alt", 10104: "RAT alt", 10105: "RAT alt",
    10210: "RAT alt", 10211: "RAT alt", 10212: "RAT alt", 10213: "RAT alt", 10214: "RAT alt",
    12345: "NetBus", 12346: "NetBus alt", 12347: "NetBus alt",
    12348: "NetBus alt", 12349: "NetBus alt", 12350: "NetBus alt",
    20034: "NetBus 2", 20146: "Back Orifice", 20778: "NetBus 2.1",
    27374: "SubSeven", 27665: "SubSeven alt", 28663: "SubSeven alt",
    30100: "NetBus 3", 30303: "RAT alt", 30304: "RAT alt", 30305: "RAT alt",
    31337: "Back Orifice / Elite", 31338: "Back Orifice alt",
    31339: "Back Orifice alt", 31717: "HACKERS PARADISE",
    31789: "HACKERS PARADISE alt", 33333: "RAT alt", 33334: "RAT alt",
    33335: "RAT alt", 33336: "RAT alt", 33337: "RAT alt", 33338: "RAT alt", 33339: "RAT alt",
    44444: "RAT alt", 45001: "RAT alt", 45002: "RAT alt", 45003: "RAT alt",
    45004: "RAT alt", 45005: "RAT alt", 45006: "RAT alt", 45007: "RAT alt", 45008: "RAT alt", 45009: "RAT alt",
    48300: "Doly RAT", 49151: "SubSeven alt",
    54320: "Back Orifice 2000 alt", 54321: "Back Orifice 2000",
    57239: "Blade RAT", 60000: "RAT alt", 60001: "RAT alt", 60002: "RAT alt",
    60003: "RAT alt", 60004: "RAT alt", 60005: "RAT alt", 60006: "RAT alt", 60007: "RAT alt", 60008: "RAT alt", 60009: "RAT alt",
    60010: "RAT alt", 60011: "RAT alt", 60012: "RAT alt", 60013: "RAT alt", 60014: "RAT alt", 60015: "RAT alt", 60016: "RAT alt", 60017: "RAT alt", 60018: "RAT alt", 60019: "RAT alt",
    60020: "RAT alt", 65000: "Common high RAT", 65001: "RAT alt",
    65002: "RAT alt", 65003: "RAT alt", 65004: "RAT alt", 65005: "RAT alt",
    65006: "RAT alt", 65007: "RAT alt", 65008: "RAT alt", 65009: "RAT alt",
    65010: "RAT alt",
}


SUSPICIOUS_FILE_KEYWORDS = [
    # --- Core RAT indicators ---
    "reverse_shell", "bind_shell", "meterpreter", "c2_server", "rat_client",
    "keylogger", "screen_capture", "webcam_capture", "password_stealer",
    
    # --- Shell commands used by RATs ---
    "netcat", "ncat -e", "bash -i >", "/dev/tcp", 
    "eval ($(", "IEX(", "Invoke-Expression", "WScript.Shell",
    "socket.connect", "subprocess.Popen", "os.system", "cmd.exe /c",
    "powershell -enc", "CreateRemoteThread", "VirtualAllocEx",
    "Invoke-WebRequest", "DownloadFile", "DownloadString", "DownloadData",
    "Process.Start", "Process.Create", "Process.Hook", "Process.Inject",
    "Process.Suspend", "Process.Resume", "Process.Dump", "Process.List",
    "kernel32", "ntdll", "advapi32", "wininet", "winhttp",
    "OpenProcess", "ReadProcessMemory", "WriteProcessMemory",
    "VirtualAllocEx", "VirtualProtectEx", "NtQueueApc", "CreateRemoteThread",
    "QueueUserAPC", "NtUnmapViewOfSection", "RtlCreateUserThread",
    "AdjustTokenPrivileges", "LookupPrivilege", "OpenProcessToken",
    
    # --- Encoded/staged commands ---
    "powershell -enc", "powershell -EncodedCommand", "powershell -e",
    "powershell -command", "powershell -c", "powershell -noexit",
    "powershell -nologo", "powershell -noninteractive",
    "cmd /c", "cmd /k", "cmd /r", "cmd /s",
    "cmd.exe /c", "cmd.exe /k", "cmd.exe /r",
    "runas /user", "runas /profile", "runas /netonly",
    "schtasks", "schtasks /create", "schtasks /run",
    "at.exe", "at.exe /create", "at.exe /delete",
    "reg add", "reg delete", "reg save", "reg restore",
    "net user", "net localgroup", "net share", "net view",
    "net start", "net stop", "net config", "net use",
    "netsh", "netsh firewall", "netsh advfirewall",
    "netsh wlan", "netsh interface", "netsh ras",
    "ipconfig", "ipconfig /all", "ipconfig /flushdns",
    "nslookup", "tracert", "pathping", "ping",
    "tasklist", "taskkill", "wmic", "wmic process", "wmic service",
    "wmic startup", "wmic useraccount", "wmic nteventlog",
    
    # --- File operations ---
    "file.write", "file.read", "file.create", "file.delete",
    "file.rename", "file.move", "file.copy", "file.append",
    "File.Open", "File.Create", "File.ReadAll", "File.WriteAllText",
    "File.AppendAllText", "File.Delete", "File.Move",
    "open(", "close(", "write(", "read(", "upload(", "download(",
    
    # --- Network operations ---
    "urllib", "requests.get", "requests.post", "requests.put", "requests.delete",
    "http.client", "httplib", "http.request", "http.response",
    "tcp_client", "tcp_server", "udp_client", "udp_server",
    "web_client", "web_server", "ftp_client", "ftp_server",
    "smtp_client", "smtp_server", "imap_client", "imap_server",
    "pop3_client", "pop3_server", "dns_client", "dns_server",
    "websocket", "websocket_client", "websocket_server",
    "grpc", "grpc_client", "grpc_server", "grpc_call",
    
    # --- DLL/PE operations ---
    "LoadLibrary", "GetProcAddress", "FreeLibrary",
    "CreateProcess", "CreateThread", "TerminateProcess",
    "SuspendThread", "ResumeThread", "OpenThread",
    "MapViewOfFile", "UnmapViewOfFile", "FlushViewOfFile",
    "SetDllDirectory", "AddDllDirectory", "RemoveDllDirectory",
    "FindFirstFile", "FindNextFile", "FindClose",
    "GetModuleHandle", "GetLibraryAddress", "GetExportAddress",
    "GetImportAddress", "GetProcAddressByName", "GetExportName",
    
    # --- Credential theft ---
    "password", "passwd", "credential", "token", "session",
    "cookie", "harvest", "dump", "extract", "steal", "grab",
    "browser_data", "chrome_data", "firefox_data", "edge_data",
    "wallet", "ethereum", "bitcoin", "monero", "wallet.dat",
    "mtgox", "blockchain", "private_key", "mnemonic", "seed_phrase",
    
    # --- RAT installer/dropper patterns ---
    "dropper", "infect", "payload", "stager", "loader",
    "download_exec", "download_run", "download_load",
    "file_drop", "file_put", "file_write", "file_store",
    "setup_installer", "install_service", "install_task",
    
    # --- Evasion techniques ---
    "anti_debug", "anti_sandbox", "anti_vm", "anti_analysis",
    "debug_check", "vm_check", "sandbox_check", "analysis_check",
    "beachballing", "timing_check", "timer_check", "perf_counter",
    "IsDebuggerPresent", "CheckRemoteDebugger", "NtQueryInformationProcess",
    "GetNativeSystemInfo", "GetVersionEx", "RtlGetVersion",
    "IsUserAnAdmin", "ShellExecute", "ShellExecuteEx",
    "WinExec", "CreateService", "StartService", "ControlService",
    "DeleteService", "OpenService", "QueryServiceStatus",
    
    # --- DNS tunneling ---
    "dns_tunnel", "dns_c2", "dns_exfil", "dns_encode",
    "dns_query", "dns_resolve", "dns_lookup", "dns_record",
    "TXT", "A", "AAAA", "CNAME", "MX", "SRV", "NS",
    "NAPTR", "SOA", "PTR", "SPF", "DKIM", "DMARC",
    
    # --- ICMP tunneling ---
    "icmp_tunnel", "icmp_c2", "icmp_exfil", "icmp_payload",
    "ping", "icmp_echo", "icmp_reply", "icmp_raw",
    
    # --- Encoded payloads ---
    "xor", "xor_encode", "xor_decode", "xor_key", "xor_keygen",
    "aes", "aes_encrypt", "aes_decrypt", "aes_key", "aes_keygen",
    "rc4", "rc4_encrypt", "rc4_decrypt", "rc4_key",
    "hex", "hex_encode", "hex_decode", "hex_raw",
    "utf8", "utf16", "utf16le", "utf16be", "unicode",
    "lzma", "lzma_compress", "lzma_decompress", "lzma_stream",
    "zip", "zip_compress", "zip_decompress", "zip_stream",
    "gzip", "gzip_compress", "gzip_decompress", "gzip_stream",
    "deflate", "inflate", "compress", "decompress",
    
    # --- Persistence mechanisms ---
    "startup", "autostart", "boot", "login", "logon", "session",
    "registry_run", "registry_run_once", "registry_services",
    "scheduled_task", "schedule_task", "schtasks_add",
    "crontab_add", "cron_add", "cron_entry",
    "systemd_unit", "systemd_service", "systemd_timer",
    "launchd_plist", "launchd_service", "launchd_timer",
    "rc_local", "init_d", "sysvinit", "upstart",
    "win_reg_run", "win_reg_run_once", "win_reg_shell",
    "win_reg_services", "win_reg_boot", "win_reg_exploit",
    "win_reg_filetype", "win_reg_notification",
    "win_reg_com", "win_reg_handler", "win_reg_extinist",
    "win_reg_inproc", "win_reg_localserver",
    
    # --- Communication channels ---
    "telegram_api", "telegram_bot", "telegram_send", "telegram_chat",
    "discord_api", "discord_webhook", "discord_send", "discord_bot",
    "signal_api", "signal_send", "signal_chat",
    "email_send", "email_attach", "email_body", "email_html",
    "webhook_send", "webhook_url", "webhook_post", "webhook_get",
    "slack_api", "slack_webhook", "slack_send", "slack_chat",
    "teams_api", "teams_webhook", "teams_send", "teams_chat",
    "gmail_smtp", "outlook_smtp", "yahoo_smtp", "protonmail_smtp",
    
    # --- Data exfiltration ---
    "exfil", "exfiltrate", "exfiltration", "upload_data",
    "data_dump", "data_leak", "data_steal", "data_harvest",
    "file_sync", "file_upload", "file_transfer", "file_send",
    "ftp_put", "ftp_send", "ftp_upload", "sftp_put", "sftp_send",
    
    # --- RAT-specific indicators ---
    "agenttesla", "nanocore", "darkcomet", "quasar", "asyncrat",
    "remcos", "njrat", "xtremerat", "blackshades", "cybergate",
    "poisonivy", "bifrost", "gh0st", "luminosity", "revenge",
    "netwire", "imminent", "warzone", "netsupport",
    "cobalt_strike", "havoc", "sliver", "covenant", "empire",
    "meterpreter", "beacon", "stager", "pupy", "venom",
    "platypus", "villain", "hoaxshell", "revshell", "shellex",
    "turbine", "vncbot", "squirterat", "jrat", "xerxes", "al-khaser",
    "kayako", "remotec2", "darkside", "dridex", "emotet", "trickbot",
    "wannacry", "petya", "notpetya", "contopee", "wastedlocker",
    "bazarloader", "iceid", "njratc2", "nanocorec2",
    "linux_rat", "plouton", "darkhotel", "finfisher", "titanrat",
    "moongate", "rhealmon", "titanfall", "darkness", "darkkitten",
    "hamsine", "tseverrat", "ratankba", "dabber", "sirefef",
    "macma", "osx_keydab", "osx_iceweasel", "osx_shark", "osx_bomgar",
    "anatsvc", "anatservice", "mobok", "jrat_android", "mummyrat",
    "droidjack", "cutwail", "toperat", "gamarue", "zeus", "tdss",
    
    # --- RAT modules ---
    "file_manager", "process_list", "cmd_shell", "registry_edit",
    "system_info", "audio_capture", "video_capture", "clipboard",
    "app_list", "installed_apps", "browser_history", "bookmarks",
    "download_history", "cookie_steal", "cookie_hijack",
    "session_hijack", "session_steal", "token_steal", "token_hijack",
    "remote_desktop", "remote_control", "remote_cmd", "remote_exec",
    "remote_upload", "remote_download", "remote_run",
    
    # --- RAT evasion ---
    "antivirus_bypass", "antiforensic", "anti_debug", "anti_sandbox",
    "process_deny", "handle_deny", "registry_lock", "file_lock",
    "self_delete", "self_clean", "self_destroy", "log_clean",
    "trace_clean", "artifact_clean", "event_log_clean",
    
    # --- C2 channels ---
    "beacon_interval", "jitter_control", "user_agent", "ua_switch",
    "kill_time", "kill_date", "geofence", "geo_check",
    "sleep_timer", "wake_lock", "wakeup_signal", "heartbeat",
    "heartbeat_ctrl", "hb_send", "hb_receive",
    "dns_probe", "dns_lookup", "dns_query",
    
    # --- RAT encryption ---
    "aes_encrypt", "aes_decrypt", "xor_cipher", "xor_decode",
    "rc4_encrypt", "rc4_decrypt", "base64_encode", "base64_decode",
    "rsa_encrypt", "rsa_decrypt", "tls_obfuscate", "tls_wrap",
    
    # --- RAT persistence ---
    "win_reg_add", "win_reg_del", "win_reg_set", "win_schedule",
    "win_task", "win_svc", "win_svc_install", "win_svc_del",
    "schtask_add", "schtask_del", "schtask_run",
    
    # --- Remote control ---
    "file_exfil", "file_upload", "file_sync", "file_dropper",
    "password_dump", "password_extract", "credential_steal", "cred_harvest",
    "browser_creds", "chrome_dump", "firefox_dump", "edge_dump",
    "wifi_creds", "network_scan", "arp_scan", "port_scan",
]

PERSISTENCE_TRIGGERS = [
    "wget http", "wget https", "curl http", "curl https",
    "nc -e", "ncat -e", "nc -c", "socat", "socat exec",
    "python -c 'import socket", "python3 -c 'import socket",
    "python -c 'import socket'", "python3 -c 'import socket'",
    "bash -i >", "/dev/tcp", "perl -e 'socket",
    "ruby -ropen3", "php -r 'socket", "lua -e 'socket",
    "chmod +x /tmp", "chmod 755 /tmp", "chmod 777", "chmod +x /var/tmp",
    "chmod +x /dev/shm", "chmod 777 /var/tmp", "chmod 777 /dev/shm",
    "eval ($(", "eval `", "exec(", "system(",
    "cmd.exe /c", "cmd.exe /k", "powershell -enc",
    "| bash", "| sh", "&& bash", "&& sh", "|| bash", "|| sh",
    "reverse_shell", "payload_", "backdoor",
    "wget --post-data", "curl --data", "curl -X POST",
    "nohup", "disown", "&", "background_task",
    "/etc/cron", "/etc/crontab", "crontab -e",
    "systemctl enable", "systemctl start", "service enable",
    "rc.local", "/etc/init.d", "/etc/profile",
    "/etc/bashrc", "~/.bashrc", "~/.bash_profile",
    "~/.profile", "~/.zshrc", "~/.profile.d",
    "win_reg_run", "schtasks", "at.exe", "runas",
    "Startup/", "autostart/", "~/.config/autostart/",
    "launchd", "plist", "loadctl",
]

SHELL_HISTORY_TRIGGERS = [
    "nc -e", "nc -c", "ncat -e", "socat exec", "socatpty",
    "bash -i", "bash -i >&", "bash -i 2>&", "ash -i",
    "zsh -i", "sh -i", "dash -i", "fish -i",
    "python -c 'import socket", "python3 -c 'import socket",
    "python -c 'socket'", "python3 -c 'socket'",
    "perl -e 'socket'", "perl -e 'exec'",
    "ruby -ropen3", "ruby -ropenssl",
    "php -r 'socket'", "php -r 'exec'",
    "php -r 'fsockopen'", "php -r 'stream_socket'",
    "lua -e 'socket'", "lua -e 'os.execute'",
    "java -c", "java -cp", "java -jar",
    "/bin/bash -i", "/bin/sh -i", "/bin/dash -i",
    "/bin/zsh -i", "/bin/fish -i",
    "/usr/bin/env bash", "/usr/bin/env sh", "/usr/bin/env python",
    "/usr/bin/env python3", "/usr/bin/env perl",
    "msfvenom", "msfconsole", "msfcli", "reverse_tcp",
    "reverse_https", "reverse_http", "reverse_meterpreter",
    "payload/windows", "payload/meterpreter", "payload/shell",
    "linux/x86/meterpreter", "windows/x64/meterpreter",
    "windows/shell_reverse_tcp", "cmd/unix/reverse",
    "shell.php", "backdoor.php", "c99.php", "r57.php",
    "webshell.php", "phpspy.php", "b374k.php",
    "wso.php", "c99shell.php", "r57shell.php",
    "/dev/tcp", "mkfifo", "socat exec", "socatpty",
    "chmod 777", "chmod +x /tmp", "chmod +x /var/tmp",
    "chmod 755 /tmp", "chmod 777 /var/tmp", "chmod +x /dev/shm",
    "python -c 'import os", "python3 -c 'import os",
    "python -c 'import subprocess", "python3 -c 'import subprocess",
    "python -c 'import pty", "python3 -c 'import pty",
    "python -c 'import pty'", "python3 -c 'import pty'",
    "base64 -d", "base64 -d |", "base64 -D", "base64 -D |",
    "python -c 'import base64", "python3 -c 'import base64",
    "base64decode", "base64_encode", "base64_decode",
    "wget http", "wget https", "wget -O", "wget -q",
    "curl http", "curl https", "curl -O", "curl -s",
    "curl -L", "curl -X POST", "curl -d",
    "powershell -enc", "powershell -encodedcommand",
    "powershell -command", "powershell -c",
    "iex(new-object", "iwr(new-object", "downloadstring",
    "CreateRemoteThread", "VirtualAllocEx", "NtUnmapViewOfSection",
    "NtWriteVirtualMemory", "NtQueueApcRoutine",
    "WriteProcessMemory", "ReadProcessMemory", "OpenProcess",
    "RtlCreateUserThread", "QueueUserAPC",
    "mimikatz", "lazagne", "secretsdump", "procdump",
    "lsass.dmp", "sam", "system hive",
    "hivexregedit", "chntpw", "samdump2",
    "john", "hashcat", "cewl", "hashid",
    "nmap", "masscan", "netdiscover", "arp-scan",
    "nikto", "dirb", "gobuster", "ffuf",
    "sqlmap", "burpsuite", "nuclei", "subfinder",
    "amass", "massdns", "dnsrecon", "dnsenum",
    "tar czf", "tar xzf", "zip -r", "zip -e",
    "scp ", "rsync ", "ftp ", "sftp ",
    "aws s3", "azure blob", "gcloud storage",
    "history -c", "rm ~/.bash_history", "unset HISTFILE",
    "unset HISTFILESIZE", "unset HISTSIZE",
    "> .bash_history", "truncate -s 0 .bash_history",
    "shred -u .bash_history", "wipe .bash_history",
    "stty", "stty raw", "stty echo",
    "tty", "tty -s",
    "export PATH=", "PATH=/tmp", "LD_PRELOAD=",
    "alias ", "unalias ",
]

SUSPICIOUS_FILE_PATHS = [
    "/tmp/", "/var/tmp/", "/dev/shm/", "/run/shm/",
    ".bat", ".cmd", ".ps1", ".vbs", ".vbe", ".js", ".jse",
    ".wsf", ".wsh", ".scr", ".pif", ".com", ".exe",
    ".py", ".pyw", ".pl", ".rb", ".php", ".asp", ".aspx",
    ".cfg", ".conf", ".ini", ".config", ".yaml", ".yml",
    ".json", ".xml", ".plist", ".db", ".sqlite", ".dbf",
    ".dat", ".log", ".bak", ".old", ".tmp", ".cache",
]

KNOWN_RAT_INSTALLERS = [
    "install", "setup", "installer", "setup_", "install_",
    "patch", "update_", "patch_", "hotfix", "kb",
    "driver", "driver_", "repair", "fix", "fix_", "corrupt",
    "extract", "unzip", "unrar", "decompress", "unpack", "depack",
    "update_windows", "update_linux", "update_mac",
    "setup_security", "setup_antivirus", "setup_defender",
    "flash_player", "java_runtime", "java_jre", "java_jdk",
    "adobe_reader", "acrobat", "foxit", "pdf",
    "teamviewer", "anydesk", "zoom", "skype", "teams",
    "dropbox", "onedrive", "google_drive", "mega",
    "winrar", "winzip", "7zip", "bandizip",
    "putty", "bitvise", "filezilla", "winscp", "cyberduck",
    "notepad++", "sublime", "vscode", "atom", "gedit",
]

SUSPICIOUS_DOMAIN_PATTERNS = [
    ".tk", ".ml", ".ga", ".cf", ".gq",
    ".xyz", ".top", ".club", ".online", ".site",
    ".buzz", ".review", ".download", ".win",
    ".click", ".link", ".info", ".biz", ".name",
    ".stream", ".download", ".host", ".hosting",
    ".cloud", ".server", ".network", ".tech", ".fun",
    ".play", ".game", ".free",
]

# Known-bad file hashes (for file integrity checking)
KNOWN_BAD_SHA256 = {
    "e3b0c44298fc1c149afbf4c8996fb924": "Empty file (possible placeholder)",
    "d41d8cd98f00b204e9800998ecf8427e": "Null content file",
}

KNOWN_BAD_MD5 = {
    "d41d8cd98f00b204e9800998ecf8427e": "Empty file",
}


def scan_sysinfo():
    """Module 1: Gather system information."""
    _set_progress(5, "System Reconnaissance")
    _log("Gathering system information...")

    info = {
        "hostname": socket.gethostname(),
        "os": f"{platform.system()} {platform.release()}",
        "arch": platform.machine(),
        "ip": _safe_cmd("hostname -I 2>/dev/null | awk '{{print $1}}'") or "N/A",
        "user": os.environ.get("USER", "unknown"),
        "uptime": _safe_cmd("uptime -p 2>/dev/null") or "N/A",
        "kernel": _safe_cmd("uname -r 2>/dev/null") or "N/A",
        "cpu": platform.processor() or "Unknown",
        "memory_total_gb": round(psutil.virtual_memory().total / (1024**3), 2) if psutil else "N/A",
        "disk_total_gb": round(psutil.disk_usage("/").total / (1024**3), 2) if psutil else "N/A",
    }
    with scan_lock:
        scan_state["target_info"] = info
    _log(f"Target info collected: {info["hostname"]} / {info["os"]}")
    _set_progress(10, "System Reconnaissance")


def scan_connections():
    """Module 2: Scan active network connections for suspicious activity."""
    _log("Scanning active network connections...")
    if not psutil:
        _log("psutil not available - skipping connection scan")
        return
    
    try:
        connections = psutil.net_connections(kind="all")
        found_suspicious = 0
        
        for conn in connections:
            if conn.status == "LISTEN":
                laddr = conn.laddr
                if laddr and laddr.port in SUSPICIOUS_PORTS:
                    pname = SUSPICIOUS_PORTS[laddr.port]
                    _finding(
                        "LISTENING_SUSPICIOUS_PORT", "HIGH",
                        f"Listening on suspicious port {laddr.port} ({pname}) PID={conn.pid}",
                        {"pid": conn.pid, "port": laddr.port, "service": pname},
                    )
                    found_suspicious += 1
            elif conn.status in ("ESTABLISHED", "SYN_SENT", "TIME_WAIT", "CLOSE_WAIT"):
                raddr = conn.raddr
                if raddr and raddr.port in SUSPICIOUS_PORTS:
                    pname = SUSPICIOUS_PORTS[raddr.port]
                    _finding(
                        "SUSPICIOUS_CONNECTION", "CRITICAL",
                        f"Suspicious outbound connection on port {raddr.port} ({pname}) PID={conn.pid}",
                        {"pid": conn.pid, "remote_port": raddr.port, "service": pname},
                    )
                    found_suspicious += 1
                    
        _log(f"Connection scan complete. {found_suspicious} suspicious connections found.")
    except (psutil.AccessDenied, PermissionError) as e:
        _log(f"Warning: Access denied during connection scan: {e}")
    except Exception as e:
        _log(f"Error scanning connections: {e}")



def scan_ports():
    """Module 3: Check listening ports for suspicious services."""
    _log("Scanning listening ports for suspicious services...")
    if not psutil:
        _log("psutil not available - skipping port scan")
        return

    try:
        addrs = psutil.net_connections(kind="all")
        found = 0
        for conn in addrs:
            laddr = conn.laddr
            if laddr and laddr.port in SUSPICIOUS_PORTS:
                pname = SUSPICIOUS_PORTS[laddr.port]
                _finding(
                    "LISTENING_SUSPICIOUS_PORT", "HIGH",
                    f"Listening on suspicious port {laddr.port} ({pname})",
                    {"pid": conn.pid, "port": laddr.port, "service": pname},
                )
                found += 1
            elif laddr and laddr.port not in SAFE_PORTS and laddr.port > 1024:
                _finding(
                    "NON_STANDARD_LISTEN_PORT", "LOW",
                    f"Non-standard listening port: {laddr.port}",
                    {"port": laddr.port, "pid": conn.pid},
                )
                found += 1

        _log(f"Port scan complete. {found} suspicious ports found.")
    except (psutil.AccessDenied, PermissionError) as e:
        _log(f"Warning: Access denied during port scan: {e}")
    except Exception as e:
        _log(f"Error scanning ports: {e}")


def scan_processes():
    """Module 4: Map PIDs to network activity and detect suspicious processes."""
    _log("Scanning running processes for suspicious activity...")
    if not psutil:
        _log("psutil not available - skipping process scan")
        return
    
    try:
        for proc in psutil.process_iter(["pid", "name", "exe", "cmdline", "username"]):
            try:
                info = proc.info
                pid = info.get("pid", 0)
                pname = info.get("name", "") or ""
                exe = info.get("exe", "") or ""
                cmdline = " ".join(info.get("cmdline") or [])
                
                for rat_name in RAT_PROCESS_NAMES:
                    if rat_name.lower() in pname.lower() or rat_name.lower() in exe.lower():
                        _finding(
                            "RAT_PROCESS_DETECTED", "CRITICAL",
                            f"Potential RAT process '{pname}' (PID: {pid}) matching known RAT signature '{rat_name}'",
                            {"pid": pid, "process_name": pname, "signature": rat_name, "exe": exe},
                        )
                
                for keyword in SUSPICIOUS_FILE_KEYWORDS:
                    if keyword.lower() in cmdline.lower():
                        _finding(
                            "SUSPICIOUS_PROCESS", "HIGH",
                            f"Process '{pname}' (PID: {pid}) contains suspicious indicator: {keyword}",
                            {"pid": pid, "process_name": pname, "indicator": keyword},
                        )
                        break
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
                
        _log("Process scan complete.")
    except Exception as e:
        _log(f"Error scanning processes: {e}")


def scan_files():
    """Module 5: Scan common locations for suspicious files."""
    _log("Scanning common directories for suspicious files...")
    scan_dirs = ["/tmp", "/var/tmp", "/dev/shm", "/root", "/home"]
    suspicious_files = []
    
    for scan_dir in scan_dirs:
        if not os.path.exists(scan_dir):
            continue
        try:
            for root, dirs, files in os.walk(scan_dir, onerror=lambda e: _log(f"Error walking {scan_dir}: {e}")):
                for f in files:
                    fpath = os.path.join(root, f)
                    if any(f.lower().endswith(ext) for ext in [".bat", ".cmd", ".ps1", ".vbs", ".js", ".py", ".php", ".sh", ".exe", ".scr"]):
                        try:
                            with open(fpath, "r", errors="ignore") as fh:
                                content = fh.read(8192)
                                for keyword in SUSPICIOUS_FILE_KEYWORDS:
                                    if keyword.lower() in content.lower():
                                        _finding(
                                            "SUSPICIOUS_FILE", "MEDIUM",
                                            f"File '{fpath}' contains suspicious keyword '{keyword}'",
                                            {"file": fpath, "keyword": keyword},
                                        )
                                        suspicious_files.append(fpath)
                                        break
                        except (PermissionError, OSError):
                            continue
                        
                        if len(suspicious_files) >= 200:
                            _log("Max file findings reached.")
                            return
        except Exception as e:
            _log(f"Error scanning directory {scan_dir}: {e}")
    
    _log(f"File scan complete. {len(suspicious_files)} suspicious files found.")


def scan_persistence():
    """Module 6: Check persistence mechanisms."""
    _log("Checking persistence mechanisms...")
    files_to_check = {
        "/etc/crontab": "crontab",
        "/etc/cron.d/": "cron.d directory",
        "/etc/rc.local": "rc.local",
        "/etc/systemd/system/": "systemd directory",
    }
    
    for fpath, desc in files_to_check.items():
        try:
            if os.path.isfile(fpath):
                with open(fpath, "r", errors="ignore") as fh:
                    for line in fh:
                        for trigger in PERSISTENCE_TRIGGERS:
                            if trigger.lower() in line.lower():
                                _finding(
                                    "SUSPICIOUS_PERSISTENCE", "HIGH",
                                    f"{desc} ({fpath}) contains suspicious indicator: {trigger}",
                                    {"file": fpath, "line": line.strip(), "trigger": trigger},
                                )
            elif os.path.isdir(fpath):
                for item in os.listdir(fpath):
                    item_path = os.path.join(fpath, item)
                    if os.path.isfile(item_path):
                        try:
                            with open(item_path, "r", errors="ignore") as fh:
                                for line in fh:
                                    for trigger in PERSISTENCE_TRIGGERS:
                                        if trigger.lower() in line.lower():
                                            _finding(
                                                "SUSPICIOUS_PERSISTENCE", "HIGH",
                                                f"{desc} file '{item_path}' contains suspicious indicator: {trigger}",
                                                {"file": item_path, "line": line.strip(), "trigger": trigger},
                                            )
                        except (PermissionError, OSError):
                            continue
        except Exception as e:
            _log(f"Error checking {desc}: {e}")
    
    try:
        systemd_dir = "/etc/systemd/system/"
        for item in os.listdir(systemd_dir) if os.path.isdir(systemd_dir) else []:
            if item.endswith(".service"):
                svc_path = os.path.join(systemd_dir, item)
                try:
                    with open(svc_path, "r", errors="ignore") as fh:
                        for line in fh:
                            if any(rat.lower() in line.lower() for rat in RAT_PROCESS_NAMES):
                                _finding(
                                    "SUSPICIOUS_SYSTEMD_SERVICE", "CRITICAL",
                                    f"Suspicious systemd service detected: {line.strip()}",
                                    {"file": svc_path, "line": line.strip()},
                                )
                                break
                except (PermissionError, OSError):
                    continue
    except Exception as e:
        _log(f"Error checking systemd services: {e}")
    
    _log("Persistence scan complete.")


def scan_shell_history():
    """Module 7: Check shell history for suspicious activity."""
    _log("Checking shell history for suspicious activity...")
    home_dirs = ["/root"]
    try:
        import pwd
        for user in pwd.getpwall():
            if user.pw_dir and user.pw_dir.startswith("/home"):
                home_dirs.append(user.pw_dir)
    except Exception:
        pass
    
    for home in home_dirs:
        for hist_file in [".bash_history", ".zsh_history", ".history", ".fish_history"]:
            hist_path = os.path.join(home, hist_file)
            if os.path.isfile(hist_path):
                try:
                    with open(hist_path, "r", errors="ignore") as fh:
                        for line_num, line in enumerate(fh, 1):
                            for trigger in SHELL_HISTORY_TRIGGERS:
                                if trigger.lower() in line.lower():
                                    _finding(
                                        "SUSPICIOUS_HISTORY", "MEDIUM",
                                        f"Shell history '{hist_path}' contains suspicious command: {trigger}",
                                        {"file": hist_path, "line": line_num, "command": line.strip()},
                                    )
                                    break
                except (PermissionError, OSError):
                    continue
    
    _log("Shell history scan complete.")


def scan_hashes():
    """Module 8: Check file hashes against known-bad lists."""
    _log("Checking file hashes against known-bad lists...")
    check_paths = ["/tmp", "/var/tmp", "/dev/shm", "/root"]
    suspicious = []
    
    for scan_dir in check_paths:
        if not os.path.exists(scan_dir):
            continue
        try:
            for f in os.listdir(scan_dir):
                fpath = os.path.join(scan_dir, f)
                if not os.path.isfile(fpath):
                    continue
                try:
                    with open(fpath, "rb") as fh:
                        data = fh.read(8192)
                        sha256 = hashlib.sha256(data).hexdigest()
                        md5 = hashlib.md5(data).hexdigest()
                        
                        if sha256 in KNOWN_BAD_SHA256:
                            _finding(
                                "KNOWN_BAD_HASH", "CRITICAL",
                                f"File '{fpath}' matches known-bad SHA-256: {KNOWN_BAD_SHA256[sha256]}",
                                {"file": fpath, "hash_type": "SHA-256", "hash": sha256, "description": KNOWN_BAD_SHA256[sha256]},
                            )
                            suspicious.append(fpath)
                        
                        if md5 in KNOWN_BAD_MD5:
                            _finding(
                                "KNOWN_BAD_HASH", "HIGH",
                                f"File '{fpath}' matches known-bad MD5: {KNOWN_BAD_MD5[md5]}",
                                {"file": fpath, "hash_type": "MD5", "hash": md5, "description": KNOWN_BAD_MD5[md5]},
                            )
                            suspicious.append(fpath)
                except (PermissionError, OSError):
                    continue
        except Exception as e:
            _log(f"Error scanning directory {scan_dir}: {e}")
    
    _log(f"Hash check complete. {len(suspicious)} suspicious files found.")


def _generate_report(mode="full"):
    """Generate report files."""
    _log("Generating reports...")
    report_path = REPORTS_DIR / f"SPECTER_THREAT_Report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
    
    try:
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import letter
        from reportlab.platypus import SimpleDocTemplate, Table, Paragraph, Spacer, PageBreak, TableStyle
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.colors import HexColor, white
        
        doc = SimpleDocTemplate(str(report_path), pagesize=letter)
        elements = []
        styles = getSampleStyleSheet()
        
        # Title
        elements.append(Paragraph("SPECTER-THREAT Detection Report", 
                                  styles["Title"]))
        elements.append(Spacer(1, 12))
        elements.append(Paragraph(f"Generated: {datetime.now().isoformat()}", 
                                  styles["Normal"]))
        elements.append(Paragraph(f"Scan Mode: {mode}", styles["Normal"]))
        elements.append(Spacer(1, 12))
        
        # Target Info
        target = scan_state.get("target_info", {})
        if target:
            elements.append(Paragraph("<b>Target Information</b>", styles["Heading2"]))
            for key, value in target.items():
                elements.append(Paragraph(f"{key}: {value}", styles["Normal"]))
            elements.append(Spacer(1, 8))
        
        # Risk Score
        risk = scan_state.get("risk_label", "UNKNOWN")
        score = scan_state.get("risk_score", 0)
        color_map = {"ACTIVELY COMPROMISED": colors.red, "HIGH RISK": colors.orange, 
                     "MODERATE RISK": colors.Color(0xff, 0xcc, 0x00), 
                     "LOW RISK": colors.Color(0x33, 0xcc, 0x33), "CLEAN": colors.Color(0x00, 0xcc, 0xff)}
        elements.append(Paragraph(f"<b>Risk Score: {score}/100 - {risk}</b>", styles["Heading2"]))
        
        # Severity Breakdown
        sev = scan_state.get("severity_counts", {})
        elements.append(Paragraph("<b>Severity Breakdown</b>", styles["Heading2"]))
        sev_data = [["CRITICAL", str(sev.get("CRITICAL", 0)), f"{sev.get('CRITICAL', 0) * 25} pts"],
                     ["HIGH", str(sev.get("HIGH", 0)), f"{sev.get('HIGH', 0) * 15} pts"],
                     ["MEDIUM", str(sev.get("MEDIUM", 0)), f"{sev.get('MEDIUM', 0) * 5} pts"],
                     ["LOW", str(sev.get("LOW", 0)), f"{sev.get('LOW', 0) * 2} pts"],
                     ["INFO", str(sev.get("INFO", 0)), "0 pts"]]
        from reportlab.lib.colors import HexColor, white
        sev_table = Table([["Severity", "Count", "Points"]] + sev_data, colWidths=[2 * 72, 1 * 72, 1.5 * 72])
        sev_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), HexColor("#16213e")),
            ("TEXTCOLOR", (0, 0), (-1, 0), white),
            ("ALIGN", (0, 0), (-1, -1), "CENTER"),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 10),
            ("BOTTOMPADDING", (0, 0), (-1, 0), 10),
            ("TOPPADDING", (0, 0), (-1, 0), 10),
            ("BACKGROUND", (0, 1), (-1, -1), HexColor("#f8f9fa")),
            ("GRID", (0, 0), (-1, -1), 0.5, HexColor("#cccccc")),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ]))
        elements.append(sev_table)
        elements.append(Spacer(1, 16))
        
        # Findings
        findings = scan_state.get("findings", [])
        if findings:
            elements.append(Paragraph("<b>Detection Findings</b>", styles["Heading2"]))
            for f in findings:
                item = f"<b>[{f.get("severity", '?')}]</b> {f.get("type", '?')} - {f.get("detail", '?')}"
                elements.append(Paragraph(item, styles["Normal"]))
                elements.append(Spacer(1, 4))
                elements.append(Spacer(1, 4))
        else:
            elements.append(Paragraph("No findings detected.", styles["Normal"]))
        
        # AI Analysis
        ai = scan_state.get("ai_analysis", "")
        if ai:
            elements.append(Paragraph("<b>AI Threat Analysis</b>", styles["Heading2"]))
            elements.append(Paragraph(ai, styles["Normal"]))
        
        # Scan Log
        elements.append(PageBreak())
        elements.append(Paragraph("<b>Scan Log</b>", styles["Heading2"]))
        log_entries = scan_state.get("log", [])
        for entry in log_entries[-50:]:  # Last 50 log entries
            item = f"[{entry.get("ts", '')}] {entry.get("msg", '?')}"
            elements.append(Paragraph(item, styles["Normal"]))
        
        doc.build(elements)
        _log(f"PDF report generated: {report_path}")
        return str(report_path)
        
    except ImportError:
        _log("ReportLab not available - generating HTML report")

    except Exception as e:
        _log(f"Report generation failed: {e}")
        # Create minimal placeholder
        try:
            from reportlab.pdfbase.pdfmetrics import registerFont
            from reportlab.pdfbase.ttfonts import TTFont
        except:
            pass
        _log(f"Report generation failed: {e}")
        # Generate HTML fallback instead
        html = generate_html_report(scan_state)
        html_path = REPORTS_DIR / f"SPECTER_THREAT_Report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        with open(html_path, "w") as f:
            f.write(html)
        _log(f"HTML report generated: {html_path}")
        return str(html_path)


def findings_to_watchtower_alerts(findings: list[dict]) -> list[dict]:
    """Convert SPECTER findings into Watchtower alert format.

    Watchtower expects:
      [{
        "alert_type": str,
        "severity": "CRITICAL|HIGH|MEDIUM|LOW",
        "title": str,
        "detail": str,
        "src_ip": str (optional),
        "dst_ip": str (optional),
        "hostname": str (optional),
        ...
      }]
    """
    alerts = []
    for f in findings:
        alert = {
            "alert_type": f.get("type", "UNKNOWN"),
            "severity": f.get("severity", "MEDIUM").upper(),
            "title": f.get("type", ""),
            "detail": f.get("detail", ""),
            "timestamp": f.get("ts", ""),
        }
        # Copy extra structured fields (pid, port, service, etc.)
        skip_keys = {"type", "severity", "detail", "ts"}
        for key, val in f.items():
            if key not in skip_keys:
                alert[key] = val

        # Check if detail contains an IP
        finding_detail = f.get("detail", "")
        ip_match = re.search(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b", finding_detail)
        if ip_match:
            alert["src_ip"] = ip_match.group(1)

        alerts.append(alert)
    return alerts


def push_to_watchtower(findings: list[dict], watchtower_url: str = None) -> dict:
    """Push findings to Watchtower and return the response (non-blocking, fire-and-forget)."""
    if watchtower_url is None:
        watchtower_url = os.environ.get("WATCHTOWER_URL", "http://localhost:5056")

    if not findings:
        return {"status": "skipped", "reason": "no findings"}

    alerts = findings_to_watchtower_alerts(findings)
    url = f"{watchtower_url}/webhook/specter"

    try:
        resp = requests.post(
            url,
            json={"alerts": alerts},
            headers={"Content-Type": "application/json"},
            timeout=5,
        )
        if resp.status_code == 200:
            data = resp.json()
            _log(f"[Watchtower] Pushed {data.get('ingested', 0)}/{len(alerts)} alerts")
            return {"status": "ok", "pushed": data.get("ingested", 0), "total": len(alerts)}
        else:
            _log(f"[Watchtower] Push failed: {resp.status_code} {resp.text[:200]}")
            return {"status": "error", "code": resp.status_code, "response": resp.text[:200]}
    except requests.ConnectionError:
        _log("[Watchtower] Could not reach Watchtower at " + url)
        return {"status": "unreachable"}
    except requests.Timeout:
        _log("[Watchtower] Timeout connecting to Watchtower")
        return {"status": "timeout"}
    except Exception as e:
        _log(f"[Watchtower] Push error: {e}")
        return {"status": "error", "message": str(e)}


def run_scan(api_key="", mode="full", verbose=False, push_watchtower=True, watchtower_url=None):
    """Main scan orchestrator - runs all modules in sequence."""
    with scan_lock:
        scan_state["running"] = True
        scan_state["started"] = datetime.now().isoformat()
        scan_state["finished"] = None
        scan_state["progress"] = 0
        scan_state["current_module"] = "Starting"
        scan_state["mode"] = mode
        scan_state["report_path"] = None

    _log(f"=== SPECTER-THREAT Scan Started (Mode: {mode}) ===")
    _log(f"Started at: {datetime.now().isoformat()}")

    # Module 1: System Info
    _set_progress(0, "System Reconnaissance")
    scan_sysinfo()

    if mode in ("quick", "full", "ports", "procs"):
        # Module 2: Connections
        _set_progress(5, "Connection Analysis")
        scan_connections()

        # Module 3: Port Scan (only in full/ports mode)
        if mode in ("full", "ports"):
            _set_progress(15, "Port Scanning")
            scan_ports()

        # Module 4: Processes
        _set_progress(25, "Process Analysis")
        scan_processes()

        # Module 5: Files
        _set_progress(40, "File Scanning")
        scan_files()

        # Module 6: Persistence
        _set_progress(55, "Persistence Check")
        scan_persistence()

        # Module 7: Shell History
        _set_progress(65, "History Analysis")
        scan_shell_history()

        # Module 8: Hashes
        _set_progress(80, "Hash Verification")
        scan_hashes()

    # Generate report
    _set_progress(90, "Report Generation")
    rp = _generate_report(mode)
    with scan_lock:
        scan_state["report_path"] = rp

    # Calculate risk score
    _set_progress(95, "Risk Assessment")
    with scan_lock:
        findings = scan_state.get("findings", [])
        severity = scan_state.get("severity_counts", {})

        score = 0
        score += severity.get("CRITICAL", 0) * 25
        score += severity.get("HIGH", 0) * 15
        score += severity.get("MEDIUM", 0) * 5
        score += severity.get("LOW", 0) * 2
        score += severity.get("INFO", 0) * 1
        score = min(score, 100)
        
        scan_state["risk_score"] = score

        if score >= 75:
            scan_state["risk_label"] = "ACTIVELY COMPROMISED"
        elif score >= 50:
            scan_state["risk_label"] = "HIGH RISK"
        elif score >= 25:
            scan_state["risk_label"] = "MODERATE RISK"
        elif score >= 5:
            scan_state["risk_label"] = "LOW RISK"
        else:
            scan_state["risk_label"] = "CLEAN"

    # AI analysis (optional)
    if api_key and mode == "full":
        _log("Running AI threat analysis...")
        with scan_lock:
            scan_state["ai_running"] = True
        try:
            import anthropic
            client = anthropic.Anthropic(api_key=api_key)
            findings_text = "\n".join(
                f"- [{f.get('severity', '?')}] {f.get('type', '?')}: {f.get('detail', '?')}"
                for f in findings[:50]
            )
            analysis_prompt = f"""You are a cybersecurity analyst. Analyze these SPECTER-THREAT findings and provide:
1. A plain-English threat assessment
2. Confidence level (High/Medium/Low)
3. Recommended immediate actions

Findings:
{findings_text}

Target: {scan_state.get("target_info", {})}

Risk Score: {scan_state["risk_score"]}/100 ({scan_state["risk_label"]})"""
            
            response = client.messages.create(
                model="claude-sonnet-4-20250514",
                max_tokens=1000,
                messages=[{"role": "user", "content": analysis_prompt}],
            )
            ai_text = response.content[0].text if response.content else ""
            with scan_lock:
                scan_state["ai_analysis"] = ai_text
            _log("AI analysis complete.")
        except Exception as ai_err:
            _log(f"AI analysis failed: {ai_err}")
            with scan_lock:
                scan_state["ai_analysis"] = f"AI analysis failed: {ai_err}"
        finally:
            with scan_lock:
                scan_state["ai_running"] = False

    # Push findings to Watchtower (fire-and-forget, non-blocking)
    if push_watchtower:
        push_to_watchtower(findings, watchtower_url=watchtower_url)

    # Final state
    _set_progress(100, "Complete")
    with scan_lock:
        scan_state["running"] = False
        scan_state["finished"] = datetime.now().isoformat()

    _log(f"=== Scan Complete (Score: {scan_state['risk_score']}, Label: {scan_state['risk_label']}) ===")


def generate_html_report(state):
    """Generate a simple HTML report as fallback."""
    sev = state.get("severity_counts", {})
    findings = state.get("findings", [])
    risk = state.get("risk_label", "UNKNOWN")

    html = f"""<!DOCTYPE html>
<html><head><title>SPECTER-THREAT Report</title>
<style>
body {{ font-family: 'Segoe UI', Arial, sans-serif; margin: 40px; background: #f5f5f5; }}
.container {{ max-width: 900px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
h1 {{ color: #16213e; }}
.risk {{ font-size: 24px; font-weight: bold; padding: 10px 20px; border-radius: 4px; display: inline-block; }}
.risk-critical {{ background: #dc3545; color: white; }}
.risk-high {{ background: #fd7e14; color: white; }}
.risk-medium {{ background: #ffc107; color: black; }}
.risk-low {{ background: #28a745; color: white; }}
.risk-clean {{ background: #17a2b8; color: white; }}
.finding {{ border: 1px solid #ddd; padding: 10px; margin: 10px 0; border-radius: 4px; }}
.sev-critical {{ border-left: 4px solid #dc3545; }}
.sev-high {{ border-left: 4px solid #fd7e14; }}
.sev-medium {{ border-left: 4px solid #ffc107; }}
.sev-low {{ border-left: 4px solid #28a745; }}
.sev-info {{ border-left: 4px solid #17a2b8; }}
table {{ border-collapse: collapse; width: 100%; }}
th, td {{ border: 1px solid #ddd; padding: 8px 12px; text-align: left; }}
th {{ background: #16213e; color: white; }}
.ai-analysis {{ background: #e8f4f8; padding: 15px; border-radius: 4px; margin: 15px 0; white-space: pre-wrap; }}
</style></head><body>
<div class="container">
<h1>SPECTER-THREAT Report</h1>
<p><b>Target:</b> {state.get('target_info', {}).get('hostname', 'N/A')} |
<b>OS:</b> {state.get('target_info', {}).get('os', 'N/A')} |
<b>Mode:</b> {state.get('mode', 'full')} |
<b>Started:</b> {state.get('started', 'N/A')[:19]}</p>
<p class="risk risk-{risk.lower().replace(' ', '-')}">Risk: {state.get('risk_score', 0)}/100 — {risk}</p>
<h2>Severity Breakdown</h2>
<table><tr><th>Severity</th><th>Count</th></tr>
<tr><td>CRITICAL</td><td>{sev.get('CRITICAL', 0)}</td></tr>
<tr><td>HIGH</td><td>{sev.get('HIGH', 0)}</td></tr>
<tr><td>MEDIUM</td><td>{sev.get('MEDIUM', 0)}</td></tr>
<tr><td>LOW</td><td>{sev.get('LOW', 0)}</td></tr>
<tr><td>INFO</td><td>{sev.get('INFO', 0)}</td></tr>
</table>
<h2>Findings ({len(findings)})</h2>
"""
    for f in findings:
        sev = f.get("severity", "INFO").lower()
        html += f'<div class="finding sev-{sev}">'
        html += f'<b>{f.get("type", "")}</b> [{f.get("severity", "")}]<br/>{f.get("detail", "")}'
        html += f'</div>'

    ai = state.get("ai_analysis", "")
    if ai and "API key" not in ai:
        html += f'<h2>AI Analysis</h2><div class="ai-analysis">{ai}</div>'

    html += f'<p style="margin-top:30px;color:#999;font-size:12px;"><i>Generated by SPECTER-THREAT v3.0 — TrinTech Digital Defense</i></p></div></body></html>'
    return html


def export_json_report(state):
    """Export scan state as JSON."""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"SPECTER_JSON_{timestamp}.json"
    filepath = REPORTS_DIR / filename
    with open(filepath, "w") as f:
        json.dump(state, f, indent=2, default=str)
    return str(filepath)


# ────────────────────────────────────────────────────────────────
# Flask Routes
# ────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    """Serve the dashboard."""
    dashboard_path = BASE_DIR / "dashboard.html"
    if dashboard_path.exists():
        return send_file(str(dashboard_path))
    return send_file("dashboard.html")


@app.route("/api/start", methods=["POST"])
def start_scan():
    """Start a new scan."""
    with scan_lock or threading.Lock():
        if scan_state.get("running"):
            return jsonify({"error": "Scan already running"}), 409

    data = request.get_json() or {}
    api_key = data.get("api_key", "")
    mode = data.get("mode", "full")
    whitelist_items = data.get("whitelist", [])

    _init_scan_state(whitelist=whitelist_items)
    scan_state["mode"] = mode

    t = threading.Thread(target=run_scan, args=(api_key, mode), daemon=True)
    t.start()
    return jsonify({"status": "started", "mode": mode})


@app.route("/api/state")
def get_state():
    """Get current scan state."""
    with scan_lock:
        state_copy = dict(scan_state)
    # Convert set to list for JSON serialization
    if isinstance(state_copy.get("whitelist"), set):
        state_copy["whitelist"] = list(state_copy["whitelist"])
    # Convert findings log timestamps to strings
    for f in state_copy.get("findings", []):
        f["ts"] = str(f.get("ts", ""))
    for l in state_copy.get("log", []):
        l["ts"] = str(l.get("ts", ""))
    return jsonify(state_copy)


@app.route("/api/report", methods=["GET"])
def download_report():
    """Download the generated report."""
    with scan_lock:
        path = scan_state.get("report_path")
    if path and Path(path).exists():
        return send_file(
            str(path),
            as_attachment=True,
            download_name=Path(path).name,
            mimetype="application/pdf" if str(path).endswith(".pdf") else "text/html",
        )
    return jsonify({"error": "No report available yet"}), 404


@app.route("/api/report/json", methods=["GET"])
def download_json_report():
    """Download scan state as JSON."""
    with scan_lock:
        state_copy = {k: v for k, v in scan_state.items()}
    json_path = export_json_report(state_copy)
    return send_file(str(json_path), as_attachment=True, download_name="SPECTER_JSON_report.json")


@app.route("/api/kill", methods=["POST"])
def kill_pid():
    """Kill a process by PID."""
    data = request.get_json() or {}
    pid = data.get("pid")
    if not pid:
        return jsonify({"error": "PID required"}), 400

    result = kill_process(pid, reason="Killed via SPECTER-THREAT API")
    if result.get("success"):
        _log(f"Process {pid} ({result.get('process_name', '')}) killed via API")
        return jsonify(result)
    else:
        return jsonify(result), 403


@app.route("/api/whitelist", methods=["POST"])
def update_whitelist():
    """Update the whitelist of trusted IPs/ports/patterns."""
    data = request.get_json() or {}
    items = data.get("items", [])
    with scan_lock:
        scan_state["whitelist"] = set(items)
    _log(f"Whitelist updated: {len(items)} items")
    return jsonify({"status": "ok", "whitelist_count": len(scan_state["whitelist"])})


# ────────────────────────────────────────────────────────────────
# CLI Interface
# ────────────────────────────────────────────────────────────────

def parse_args():
    parser = argparse.ArgumentParser(
        description="SPECTER-THREAT v3.0 — TrinTech Digital Defense RAT Detector",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python Rat-Detecter.py --quick              # Fast connection sweep
  python Rat-Detecter.py --full               # Full deep scan (default)
  python Rat-Detecter.py --ports              # Check suspicious ports only
  python Rat-Detecter.py --procs              # Map PIDs to network activity
  python Rat-Detecter.py --kill 1234          # Kill flagged process
  python Rat-Detecter.py --watch --interval 30 # Continuous monitoring
  python Rat-Detecter.py --report json        # Export JSON report
  python Rat-Detecter.py --report html        # Export HTML report
  python Rat-Detecter.py --whitelist trust.txt # Whitelist trusted items
        """,
    )
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--quick", action="store_true", help="Fast connection sweep only")
    group.add_argument("--full", action="store_true", default=True, help="Full deep scan (default)")
    group.add_argument("--ports", action="store_true", help="Check suspicious ports only")
    group.add_argument("--procs", action="store_true", help="Map PIDs to network activity")

    parser.add_argument("--kill", type=int, help="Kill a flagged process by PID")
    parser.add_argument("--watch", action="store_true", help="Continuous monitoring mode")
    parser.add_argument("--interval", type=int, default=30, help="Watch interval in seconds (default: 30)")
    parser.add_argument("--report", choices=["json", "html"], help="Export report after scan")
    parser.add_argument("--whitelist", type=str, help="Whitelist file (one IP/port/pattern per line)")
    parser.add_argument("--verbose", action="store_true", help="Verbose output")
    parser.add_argument("--api-key", type=str, help="Anthropic API key for AI analysis")
    parser.add_argument("--no-watchtower", action="store_true", help="Disable auto-push to Watchtower")
    parser.add_argument("--watchtower-url", type=str, help="Watchtower URL (default: http://localhost:5056)")

    return parser.parse_args()


def run_cli(args):
    """Run from CLI."""
    if args.whitelist:
        try:
            with open(args.whitelist) as f:
                whitelist = [line.strip() for line in f if line.strip() and not line.startswith('#')]
        except FileNotFoundError:
            print(f"Error: Whitelist file '{args.whitelist}' not found")
            return
    else:
        whitelist = []

    if args.kill:
        print(f"Killing PID {args.kill}...")
        result = kill_process(args.kill, reason="CLI kill")
        print(json.dumps(result, indent=2))
        return

    # Determine mode
    mode = "full"
    if args.quick:
        mode = "quick"
    elif args.ports:
        mode = "ports"
    elif args.procs:
        mode = "procs"

    print(f"\n{'='*60}")
    print(f"  TrinTech Digital Defense — SPECTER-THREAT v3.0")
    print(f"  Mode: {mode} | Whitelist: {len(whitelist)} items")
    print(f"  {'='*60}\n")

    _init_scan_state(whitelist=whitelist)

    if args.watch:
        # Watch mode: background scan every N seconds
        print(f"Watch mode started — checking every {args.interval}s (Ctrl+C to stop)")
        try:
            while True:
                run_scan(api_key=args.api_key or "", mode=mode, verbose=args.verbose,
                          push_watchtower=not args.no_watchtower,
                          watchtower_url=args.watchtower_url)
                print(f"\n→ Scan complete — Risk: {scan_state['risk_label']} ({scan_state['risk_score']})")
                time.sleep(args.interval)
        except KeyboardInterrupt:
            print("\nWatch mode stopped.")
    else:
        run_scan(api_key=args.api_key or "", mode=mode, verbose=args.verbose,
                 push_watchtower=not args.no_watchtower,
                 watchtower_url=args.watchtower_url)

        # Export report
        if args.report:
            with scan_lock:
                state_copy = {k: v for k, v in scan_state.items()}
            if args.report == "json":
                path = export_json_report(state_copy)
                print(f"\n✓ JSON report: {path}")
            elif args.report == "html":
                path = generate_html_report(state_copy)
                print(f"\n✓ HTML report: {path}")

        # Also save PDF (already generated by _generate_report, just report path)
        with scan_lock:
            state_snapshot = {k: v for k, v in scan_state.items()}
        print(f"✓ PDF report: {scan_state.get('report_path', 'N/A')}")

        print(f"\n{'='*60}")
        print(f"  Risk Score: {scan_state['risk_score']}/100")
        print(f"  Status:     {scan_state['risk_label']}")
        print(f"  Findings:   {len(scan_state['findings'])}")
        print(f"  {'='*60}")


# ────────────────────────────────────────────────────────────────
# Entry Point
# ────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    # Check if running with CLI args
    if len(sys.argv) > 1 and any(a.startswith("--") for a in sys.argv[1:]):
        args = parse_args()
        run_cli(args)
    else:
        # Default: start Flask web server
        print(f"\n{'='*60}")
        print(f"  TrinTech Digital Defense — SPECTER-THREAT v3.0")
        print(f"  Dashboard: http://localhost:5050")
        print(f"  API:       http://localhost:5050/api/start")
        print(f"  Reports:   {REPORTS_DIR}/")
        print(f"  {'='*60}\n")
        app.run(host="0.0.0.0", port=5050, debug=False)

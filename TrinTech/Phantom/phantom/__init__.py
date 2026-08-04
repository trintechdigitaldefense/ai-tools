"""
Phantom — Network Traffic Analyzer & Protocol Auditor

Captures, classifies, and detects anomalies in network traffic.
Detects suspicious protocols, covert channels, beaconing, and anomalous
traffic patterns. Feeds events into Log Correlator.

Usage:
  python3 phantom_server.py              # Start Flask API (port 5055)
  python3 phantom_server.py --capture    # Start packet capture
  python3 phantom_server.py --analyze --pcap file.pcap  # Analyze PCAP file
"""
__version__ = "2.0.0"

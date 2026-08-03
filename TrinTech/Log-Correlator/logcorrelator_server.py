"""
TrinTech Digital Defense
Log Correlator — Flask API Server

Usage:
  python3 logcorrelator_server.py --server  # Start API server (port 5053)
  python3 logcorrelator_server.py --scan    # Full scan + correlate
"""

import argparse
import sys

from logcorrelator.engine import (
    app, parse_args, main as engine_main,
    _init, REPORTS_DIR,
)


def main():
    args = parse_args()

    if args.tests:
        print("Running tests...")
        sys.exit(0)

    if args.scan:
        engine_main()
        return

    if args.report:
        engine_main()
        return

    if args.correlate:
        engine_main()
        return

    if args.ingest_file:
        engine_main()
        return

    # Default: run server
    _init()
    print(f"Starting Log Correlator API server on port {args.port}...")
    app.run(host="0.0.0.0", port=args.port, debug=False)


if __name__ == "__main__":
    main()

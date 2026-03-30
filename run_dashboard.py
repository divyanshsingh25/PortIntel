#!/usr/bin/env python3


import sys
import os
import argparse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from port_scanner.dashboard import run_dashboard


def main():
    parser = argparse.ArgumentParser(description="PortIntel Web Dashboard")
    parser.add_argument("--host", default="127.0.0.1", help="Host to bind (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=5000, help="Port to bind (default: 5000)")
    parser.add_argument("--debug", action="store_true", help="Enable Flask debug mode")
    args = parser.parse_args()
    run_dashboard(host=args.host, port=args.port, debug=args.debug)


if __name__ == "__main__":
    main()

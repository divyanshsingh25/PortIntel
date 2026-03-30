#!/usr/bin/env python3
"""
run_scanner.py - Convenience entry point for PortIntel.

Usage:
    python run_scanner.py 192.168.1.1
    python run_scanner.py example.com -p 1-1024 --json --txt
    python run_scanner.py --help
"""

import sys
import os

# Ensure the project root is on sys.path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from port_scanner.cli import main

if __name__ == "__main__":
    main()

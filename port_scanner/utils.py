"""
utils.py - Utility helpers for PortIntel.

Contains functions for:
  • Target parsing  (single IP, domain, CIDR, range)
  • Host-alive checks (ICMP / TCP ping)
  • OS fingerprinting via TTL heuristic
  • Miscellaneous formatting helpers
"""

import ipaddress
import os
import platform
import re
import socket
import struct
import subprocess
import time
from typing import List, Optional, Tuple

from port_scanner.config import TTL_OS_MAP


# ═══════════════════════════════════════════════════════════════════════
#  TARGET PARSING
# ═══════════════════════════════════════════════════════════════════════

def resolve_target(target: str) -> str:
    """
    Resolve a hostname / domain to its IPv4 address.
    Returns the original string if it is already an IP.
    """
    try:
        ipaddress.ip_address(target)
        return target                         # already an IP
    except ValueError:
        pass
    try:
        return socket.gethostbyname(target)   # DNS lookup
    except socket.gaierror:
        raise ValueError(f"Cannot resolve hostname: {target}")


def parse_targets(target_str: str) -> List[str]:
    """
    Parse a flexible target specification into a list of IP strings.

    Supported formats
    -----------------
    * Single IP            – ``192.168.1.1``
    * Domain name          – ``example.com``
    * Dash-range           – ``192.168.1.1-50``
    * CIDR                 – ``192.168.1.0/24``
    * Comma-separated      – ``192.168.1.1,192.168.1.2``

    Returns
    -------
    list[str]
        Deduplicated list of IPv4 address strings.
    """
    targets: List[str] = []

    # Handle comma-separated list
    for part in target_str.split(","):
        part = part.strip()
        if not part:
            continue

        # CIDR notation
        if "/" in part:
            try:
                network = ipaddress.ip_network(part, strict=False)
                targets.extend(str(ip) for ip in network.hosts())
                continue
            except ValueError:
                pass

        # Dash range  e.g.  192.168.1.1-50
        dash_match = re.match(
            r"^(\d{1,3}\.\d{1,3}\.\d{1,3})\.(\d{1,3})-(\d{1,3})$", part
        )
        if dash_match:
            prefix, start, end = dash_match.groups()
            for octet in range(int(start), int(end) + 1):
                if 0 <= octet <= 255:
                    targets.append(f"{prefix}.{octet}")
            continue

        # Single IP or domain
        try:
            targets.append(resolve_target(part))
        except ValueError as exc:
            raise ValueError(str(exc))

    # Deduplicate while preserving order
    seen = set()
    unique: List[str] = []
    for t in targets:
        if t not in seen:
            seen.add(t)
            unique.append(t)
    return unique


# ═══════════════════════════════════════════════════════════════════════
#  HOST-ALIVE CHECKS
# ═══════════════════════════════════════════════════════════════════════

def is_host_alive(ip: str, timeout: float = 2.0) -> Tuple[bool, Optional[int]]:
    """
    Determine if a host is reachable.

    Strategy
    --------
    1. Try an ICMP ping (requires appropriate privileges on some OSes).
    2. Fall back to a TCP connect on port 80/443.

    Returns
    -------
    (alive: bool, ttl: int | None)
        ``ttl`` is extracted from the ping reply when available.
    """
    alive, ttl = _ping(ip, timeout)
    if alive:
        return True, ttl

    # Fallback: quick TCP probe on common ports
    for port in (80, 443, 22, 8080):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((ip, port))
            sock.close()
            if result == 0:
                return True, None
        except (socket.error, OSError):
            continue

    return False, None


def _ping(ip: str, timeout: float) -> Tuple[bool, Optional[int]]:
    """
    Send an ICMP echo request via the system ``ping`` command.
    Parses TTL from the output for OS fingerprinting.
    """
    try:
        param = "-n" if platform.system().lower() == "windows" else "-c"
        timeout_param = "-w" if platform.system().lower() == "windows" else "-W"
        timeout_val = str(int(timeout * 1000)) if platform.system().lower() == "windows" else str(int(timeout))

        cmd = ["ping", param, "1", timeout_param, timeout_val, ip]
        result = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout + 2,
            creationflags=subprocess.CREATE_NO_WINDOW if platform.system().lower() == "windows" else 0,
        )
        output = result.stdout.decode("utf-8", errors="ignore")

        if result.returncode == 0:
            # Extract TTL
            ttl_match = re.search(r"ttl[=:](\d+)", output, re.IGNORECASE)
            ttl = int(ttl_match.group(1)) if ttl_match else None
            return True, ttl
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        pass

    return False, None


# ═══════════════════════════════════════════════════════════════════════
#  OS FINGERPRINTING
# ═══════════════════════════════════════════════════════════════════════

def guess_os(ttl: Optional[int]) -> str:
    """
    Guess the remote operating system family based on the TTL value
    observed in an ICMP echo reply.

    TTL defaults:
        64  → Linux / Unix / macOS
        128 → Windows
        255 → Cisco / network device

    Returns ``"Unknown"`` if the TTL doesn't match a known pattern.
    """
    if ttl is None:
        return "Unknown"

    # TTL values may be decremented by intermediate routers, so we
    # compare against the nearest known default.
    closest = min(TTL_OS_MAP.keys(), key=lambda k: abs(k - ttl))
    if abs(closest - ttl) <= 30:          # allow up to ~30 hops
        return TTL_OS_MAP[closest]
    return "Unknown"


# ═══════════════════════════════════════════════════════════════════════
#  FORMATTING HELPERS
# ═══════════════════════════════════════════════════════════════════════

def format_duration(seconds: float) -> str:
    """Return a human-readable duration string."""
    if seconds < 60:
        return f"{seconds:.2f}s"
    mins, secs = divmod(seconds, 60)
    return f"{int(mins)}m {secs:.2f}s"


def get_port_range(port_spec: str) -> List[int]:
    """
    Parse a port specification string.

    Examples
    --------
    ``"80"``           → [80]
    ``"1-1024"``       → [1..1024]
    ``"80,443,8080"``  → [80, 443, 8080]
    ``"1-100,443"``    → [1..100, 443]
    ``"common"``       → COMMON_PORTS from config
    ``"all"``          → 1-65535
    """
    from port_scanner.config import COMMON_PORTS, ALL_PORTS, WELL_KNOWN_PORTS

    spec = port_spec.strip().lower()
    if spec == "common":
        return COMMON_PORTS[:]
    if spec == "all":
        return ALL_PORTS[:]
    if spec == "well-known":
        return WELL_KNOWN_PORTS[:]

    ports: List[int] = []
    for segment in spec.split(","):
        segment = segment.strip()
        if "-" in segment:
            lo, hi = segment.split("-", 1)
            lo, hi = int(lo), int(hi)
            if lo > hi:
                lo, hi = hi, lo
            ports.extend(range(lo, hi + 1))
        else:
            ports.append(int(segment))

    # Validate & deduplicate
    valid = sorted(set(p for p in ports if 1 <= p <= 65535))
    if not valid:
        raise ValueError(f"Invalid port specification: {port_spec}")
    return valid

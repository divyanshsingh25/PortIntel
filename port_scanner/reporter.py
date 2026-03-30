"""
reporter.py - Output formatting and file export for PortIntel.

Generates:
  • Pretty-printed terminal tables with ANSI colours
  • JSON export
  • TXT report
"""

import json
import os
import time
from datetime import datetime
from typing import List

from port_scanner.scanner import ScanResult, PortResult
from port_scanner.utils import format_duration
from port_scanner.logger import setup_logger

logger = setup_logger()


# ═══════════════════════════════════════════════════════════════════════
#  ANSI COLOUR HELPERS
# ═══════════════════════════════════════════════════════════════════════

class Colours:
    """ANSI escape codes for terminal colouring."""
    RESET   = "\033[0m"
    BOLD    = "\033[1m"
    DIM     = "\033[2m"
    RED     = "\033[91m"
    GREEN   = "\033[92m"
    YELLOW  = "\033[93m"
    BLUE    = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN    = "\033[96m"
    WHITE   = "\033[97m"
    BG_GREEN  = "\033[42m"
    BG_RED    = "\033[41m"
    BG_YELLOW = "\033[43m"


def _state_colour(state: str) -> str:
    """Return the ANSI colour for a port state."""
    return {
        "open":     Colours.GREEN,
        "closed":   Colours.RED,
        "filtered": Colours.YELLOW,
    }.get(state, Colours.WHITE)


# ═══════════════════════════════════════════════════════════════════════
#  TERMINAL OUTPUT
# ═══════════════════════════════════════════════════════════════════════

def print_results(result: ScanResult, show_closed: bool = False):
    """
    Pretty-print scan results to the terminal.

    Parameters
    ----------
    result : ScanResult
        Completed scan result.
    show_closed : bool
        If True, also display closed ports.
    """
    C = Colours

    # Header
    print(f"\n{C.BOLD}{C.CYAN}{'═' * 72}{C.RESET}")
    print(f"{C.BOLD}{C.CYAN}  SCAN RESULTS — {result.ip}{C.RESET}")
    print(f"{C.BOLD}{C.CYAN}{'═' * 72}{C.RESET}")

    # Summary bar
    print(f"\n  {C.BOLD}Target:{C.RESET}    {result.target} ({result.ip})")
    print(f"  {C.BOLD}OS Guess:{C.RESET}  {result.os_guess}")
    if result.ttl is not None:
        print(f"  {C.BOLD}TTL:{C.RESET}       {result.ttl}")
    print(f"  {C.BOLD}Duration:{C.RESET}  {format_duration(result.duration)}")
    print(f"  {C.BOLD}Scanned:{C.RESET}   {result.total_scanned} ports")
    print(
        f"  {C.GREEN}● Open: {result.open_ports}{C.RESET}  "
        f"{C.RED}● Closed: {result.closed_ports}{C.RESET}  "
        f"{C.YELLOW}● Filtered: {result.filtered_ports}{C.RESET}"
    )

    # Table
    ports_to_show = [
        p for p in result.ports
        if p.state == "open" or p.state == "filtered" or show_closed
    ]

    if not ports_to_show:
        print(f"\n  {C.YELLOW}No open or filtered ports found.{C.RESET}\n")
        return

    # Column widths
    header = f"  {'PORT':<10}{'STATE':<12}{'SERVICE':<18}{'VERSION':<25}{'BANNER'}"
    print(f"\n{C.BOLD}{C.WHITE}{header}{C.RESET}")
    print(f"  {'-' * 70}")

    for p in ports_to_show:
        state_c = _state_colour(p.state)
        state_str = f"{state_c}{p.state.upper()}{C.RESET}"

        # Truncate banner for display
        banner_display = p.banner.replace("\r", "").replace("\n", " ")[:40]
        if len(p.banner) > 40:
            banner_display += "…"

        port_str = f"{p.port}/tcp"
        print(
            f"  {port_str:<10}"
            f"{state_str:<21}"       # 12 chars + ANSI escape overhead
            f"{p.service:<18}"
            f"{p.version:<25}"
            f"{C.DIM}{banner_display}{C.RESET}"
        )

    print(f"\n{C.BOLD}{C.CYAN}{'═' * 72}{C.RESET}\n")


# ═══════════════════════════════════════════════════════════════════════
#  JSON EXPORT
# ═══════════════════════════════════════════════════════════════════════

def save_json(result: ScanResult, filepath: str):
    """
    Export scan results to a JSON file.
    """
    data = {
        "scan_info": {
            "target": result.target,
            "ip": result.ip,
            "os_guess": result.os_guess,
            "ttl": result.ttl,
            "scan_time": datetime.fromtimestamp(result.start_time).isoformat(),
            "duration_seconds": round(result.duration, 2),
            "total_scanned": result.total_scanned,
            "open_ports": result.open_ports,
            "closed_ports": result.closed_ports,
            "filtered_ports": result.filtered_ports,
        },
        "ports": [
            {
                "port": p.port,
                "state": p.state,
                "service": p.service,
                "version": p.version,
                "banner": p.banner,
                "response_time": p.response_time,
            }
            for p in result.ports
            if p.state in ("open", "filtered")
        ],
    }

    os.makedirs(os.path.dirname(filepath) if os.path.dirname(filepath) else ".", exist_ok=True)
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

    logger.info(f"JSON report saved to {filepath}")


# ═══════════════════════════════════════════════════════════════════════
#  TXT REPORT
# ═══════════════════════════════════════════════════════════════════════

def save_txt(result: ScanResult, filepath: str):
    """
    Export scan results as a human-readable plain-text report.
    """
    lines: List[str] = []
    lines.append("=" * 72)
    lines.append("  PORTINTEL — PORT SCAN REPORT")
    lines.append("=" * 72)
    lines.append(f"  Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append(f"  Target:    {result.target} ({result.ip})")
    lines.append(f"  OS Guess:  {result.os_guess}")
    if result.ttl is not None:
        lines.append(f"  TTL:       {result.ttl}")
    lines.append(f"  Duration:  {format_duration(result.duration)}")
    lines.append(f"  Scanned:   {result.total_scanned} ports")
    lines.append(f"  Open:      {result.open_ports}")
    lines.append(f"  Closed:    {result.closed_ports}")
    lines.append(f"  Filtered:  {result.filtered_ports}")
    lines.append("-" * 72)
    lines.append(f"  {'PORT':<10}{'STATE':<12}{'SERVICE':<18}{'VERSION':<25}BANNER")
    lines.append("-" * 72)

    for p in result.ports:
        if p.state in ("open", "filtered"):
            banner_clean = p.banner.replace("\r", "").replace("\n", " ")[:50]
            lines.append(
                f"  {p.port:<10}{p.state.upper():<12}{p.service:<18}"
                f"{p.version:<25}{banner_clean}"
            )

    lines.append("=" * 72)
    lines.append("  END OF REPORT")
    lines.append("=" * 72)

    os.makedirs(os.path.dirname(filepath) if os.path.dirname(filepath) else ".", exist_ok=True)
    with open(filepath, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")

    logger.info(f"TXT report saved to {filepath}")

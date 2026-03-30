import argparse
import sys
import time
import threading

"""
cli.py - Command-line interface for PortIntel.
"""

from port_scanner.config import (
    BANNER,
    WARNING_BANNER,
    DEFAULT_TIMEOUT,
    DEFAULT_THREADS,
    DEFAULT_RETRIES,
    RATE_LIMIT_DELAY,
    JSON_OUTPUT_FILE,
    TXT_OUTPUT_FILE,
)
from port_scanner.logger import setup_logger
from port_scanner.utils import parse_targets, is_host_alive, guess_os, get_port_range
from port_scanner.scanner import PortScanner, ScanResult
from port_scanner.reporter import print_results, save_json, save_txt, Colours


def build_parser() -> argparse.ArgumentParser:
    
    parser = argparse.ArgumentParser(
        prog="portintel",
        description="PortIntel — Autonomous Port Scanner & Network Intelligence Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python -m port_scanner 192.168.1.1\n"
            "  python -m port_scanner example.com -p 1-1024\n"
            "  python -m port_scanner 192.168.1.1-50 -p common --autonomous\n"
            "  python -m port_scanner 10.0.0.1 -p all -o results --json --txt\n"
        ),
    )

    # Positional
    parser.add_argument(
        "target",
        help=(
            "Target to scan. Accepts: single IP, domain, "
            "dash-range (192.168.1.1-50), CIDR (/24), or comma-list"
        ),
    )

    # Port specification
    parser.add_argument(
        "-p", "--ports",
        default="common",
        help=(
            "Ports to scan. "
            "'common' (default), 'well-known' (1-1023), 'all' (1-65535), "
            "or explicit: 80,443  or  1-1024  or  1-100,443,8080"
        ),
    )

    # Performance
    parser.add_argument(
        "-t", "--threads",
        type=int,
        default=DEFAULT_THREADS,
        help=f"Number of concurrent threads (default: {DEFAULT_THREADS})",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=DEFAULT_TIMEOUT,
        help=f"Connection timeout in seconds (default: {DEFAULT_TIMEOUT})",
    )
    parser.add_argument(
        "--retries",
        type=int,
        default=DEFAULT_RETRIES,
        help=f"Retry count for timed-out ports (default: {DEFAULT_RETRIES})",
    )
    parser.add_argument(
        "--rate-limit",
        type=float,
        default=RATE_LIMIT_DELAY,
        help=f"Delay between probes in seconds (default: {RATE_LIMIT_DELAY})",
    )

    # Autonomous mode
    parser.add_argument(
        "--autonomous",
        action="store_true",
        default=True,
        help="Enable autonomous mode (dynamic thread/timeout adjustment)",
    )
    parser.add_argument(
        "--no-autonomous",
        action="store_true",
        help="Disable autonomous mode",
    )

    # Output
    parser.add_argument(
        "-o", "--output-dir",
        default=".",
        help="Directory for output files (default: current directory)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Save results as JSON",
    )
    parser.add_argument(
        "--txt",
        action="store_true",
        help="Save results as TXT report",
    )
    parser.add_argument(
        "--show-closed",
        action="store_true",
        help="Show closed ports in terminal output",
    )

    # Verbosity
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose (DEBUG) logging",
    )

    # Skip host discovery
    parser.add_argument(
        "--skip-ping",
        action="store_true",
        help="Skip host-alive check and scan directly",
    )

    return parser


# ═══════════════════════════════════════════════════════════════════════
#  PROGRESS BAR
# ═══════════════════════════════════════════════════════════════════════

class ProgressBar:
    

    def __init__(self, total: int, bar_length: int = 40):
        self.total = total
        self.bar_length = bar_length
        self._lock = threading.Lock()
        self._start = time.time()

    def update(self, current: int, total: int):
        
        with self._lock:
            pct = current / total if total > 0 else 1.0
            filled = int(self.bar_length * pct)
            bar = "█" * filled + "░" * (self.bar_length - filled)

            elapsed = time.time() - self._start
            if current > 0:
                eta = (elapsed / current) * (total - current)
                eta_str = f"ETA {eta:.0f}s"
            else:
                eta_str = "ETA --"

            line = (
                f"\r  {Colours.CYAN}Scanning:{Colours.RESET} "
                f"|{Colours.GREEN}{bar}{Colours.RESET}| "
                f"{current}/{total} ({pct:.1%}) "
                f"[{elapsed:.0f}s / {eta_str}]"
            )
            sys.stderr.write(line)
            sys.stderr.flush()

            if current >= total:
                sys.stderr.write("\n")


# ═══════════════════════════════════════════════════════════════════════
#  MAIN ENTRY POINT
# ═══════════════════════════════════════════════════════════════════════

def main(args=None):
    
    parser = build_parser()
    opts = parser.parse_args(args)

    # Setup logging
    logger = setup_logger(verbose=opts.verbose)

    # Print banners
    C = Colours
    print(f"{C.CYAN}{BANNER}{C.RESET}")
    print(f"{C.YELLOW}{WARNING_BANNER}{C.RESET}")

    # ── Autonomous flag ──────────────────────────────────────────────
    autonomous = opts.autonomous and not opts.no_autonomous

    # ── Parse targets ────────────────────────────────────────────────
    try:
        targets = parse_targets(opts.target)
    except ValueError as exc:
        print(f"{C.RED}  ✗ Error: {exc}{C.RESET}")
        sys.exit(1)

    print(f"  {C.BOLD}Targets:{C.RESET} {len(targets)} host(s)")

    # ── Parse ports ──────────────────────────────────────────────────
    try:
        ports = get_port_range(opts.ports)
    except ValueError as exc:
        print(f"{C.RED}  ✗ Error: {exc}{C.RESET}")
        sys.exit(1)

    print(f"  {C.BOLD}Ports:{C.RESET}   {len(ports)} port(s) to scan")
    print()

    # ── Scan each target ─────────────────────────────────────────────
    all_results: list[ScanResult] = []

    for idx, ip in enumerate(targets, 1):
        print(f"{C.BOLD}{C.BLUE}  [{idx}/{len(targets)}] Scanning {ip}…{C.RESET}")

        # Host-alive check
        if not opts.skip_ping:
            alive, ttl = is_host_alive(ip, timeout=opts.timeout)
            if not alive:
                print(f"  {C.YELLOW}⚠ Host {ip} appears down. Skipping.{C.RESET}\n")
                logger.warning(f"Host {ip} is unreachable, skipping.")
                continue
            os_guess = guess_os(ttl)
            print(
                f"  {C.GREEN}✓ Host is UP{C.RESET}"
                f" | TTL: {ttl or 'N/A'}"
                f" | OS: {os_guess}"
            )
        else:
            ttl = None
            os_guess = "Unknown"
            print(f"  {C.DIM}(host discovery skipped){C.RESET}")

        # Progress bar
        progress = ProgressBar(total=len(ports))

        # Run scanner
        scanner = PortScanner(
            target_ip=ip,
            ports=ports,
            timeout=opts.timeout,
            threads=opts.threads,
            retries=opts.retries,
            rate_limit=opts.rate_limit,
            autonomous=autonomous,
            progress_callback=progress.update,
        )

        result = scanner.scan()
        result.os_guess = os_guess
        result.ttl = ttl

        # Display
        print_results(result, show_closed=opts.show_closed)

        # Export
        import os
        if opts.json:
            json_path = os.path.join(opts.output_dir, f"scan_{ip.replace('.', '_')}.json")
            save_json(result, json_path)
            print(f"  {C.GREEN}✓ JSON saved:{C.RESET} {json_path}")

        if opts.txt:
            txt_path = os.path.join(opts.output_dir, f"scan_{ip.replace('.', '_')}.txt")
            save_txt(result, txt_path)
            print(f"  {C.GREEN}✓ TXT saved:{C.RESET}  {txt_path}")

        all_results.append(result)

    # ── Summary ──────────────────────────────────────────────────────
    if len(all_results) > 1:
        total_open = sum(r.open_ports for r in all_results)
        print(f"\n{C.BOLD}{C.CYAN}{'═' * 72}{C.RESET}")
        print(f"  {C.BOLD}SCAN SUMMARY{C.RESET}")
        print(f"  Hosts scanned: {len(all_results)}")
        print(f"  Total open ports: {total_open}")
        print(f"{C.BOLD}{C.CYAN}{'═' * 72}{C.RESET}\n")

    if not all_results:
        print(f"\n  {C.YELLOW}No reachable hosts found.{C.RESET}\n")


if __name__ == "__main__":
    main()

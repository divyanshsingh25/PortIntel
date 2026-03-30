"""
scanner.py - Core scanning engine for PortIntel.

Implements:
  • TCP connect scan
  • Banner grabbing
  • Service / version detection
  • Multithreaded execution via ThreadPoolExecutor
  • Dynamic thread adjustment based on response times
  • Rate limiting to avoid detection
  • Retry logic for unreliable connections
"""

import re
import socket
import time
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Callable

from port_scanner.config import (
    DEFAULT_TIMEOUT,
    DEFAULT_THREADS,
    MAX_THREADS,
    MIN_THREADS,
    DEFAULT_RETRIES,
    RATE_LIMIT_DELAY,
    PORT_SERVICE_MAP,
    BANNER_SIGNATURES,
)
from port_scanner.logger import setup_logger

logger = setup_logger()


# ═══════════════════════════════════════════════════════════════════════
#  DATA CLASSES
# ═══════════════════════════════════════════════════════════════════════

@dataclass
class PortResult:
    """Holds the scan result for a single port."""
    port: int
    state: str              # "open", "closed", "filtered"
    service: str = ""       # e.g. "HTTP", "SSH"
    banner: str = ""        # raw banner text
    version: str = ""       # extracted version string
    response_time: float = 0.0  # seconds


@dataclass
class ScanResult:
    """Aggregate result for an entire host scan."""
    target: str
    ip: str
    os_guess: str = "Unknown"
    ttl: Optional[int] = None
    start_time: float = 0.0
    end_time: float = 0.0
    ports: List[PortResult] = field(default_factory=list)
    open_ports: int = 0
    closed_ports: int = 0
    filtered_ports: int = 0
    total_scanned: int = 0

    @property
    def duration(self) -> float:
        return self.end_time - self.start_time


# ═══════════════════════════════════════════════════════════════════════
#  PORT SCANNER CLASS
# ═══════════════════════════════════════════════════════════════════════

class PortScanner:
    """
    Autonomous multithreaded TCP port scanner.

    Parameters
    ----------
    target_ip : str
        IPv4 address to scan.
    ports : list[int]
        List of port numbers to probe.
    timeout : float
        Socket connect timeout in seconds.
    threads : int
        Initial number of concurrent workers.
    retries : int
        Number of retries for timed-out connections.
    rate_limit : float
        Minimum delay (seconds) between consecutive probes.
    autonomous : bool
        If True, dynamically adjust thread count and timeout
        based on network responsiveness.
    progress_callback : callable | None
        Called with (scanned_count, total_count) after each port.
    """

    def __init__(
        self,
        target_ip: str,
        ports: List[int],
        timeout: float = DEFAULT_TIMEOUT,
        threads: int = DEFAULT_THREADS,
        retries: int = DEFAULT_RETRIES,
        rate_limit: float = RATE_LIMIT_DELAY,
        autonomous: bool = True,
        progress_callback: Optional[Callable] = None,
    ):
        self.target_ip = target_ip
        self.ports = ports
        self.timeout = timeout
        self.threads = threads
        self.retries = retries
        self.rate_limit = rate_limit
        self.autonomous = autonomous
        self.progress_callback = progress_callback

        # Internal state
        self._lock = threading.Lock()
        self._scanned = 0
        self._response_times: List[float] = []
        self._results: List[PortResult] = []
        self._adjust_interval = 200        # re-evaluate threads every N ports
        self._stop_event = threading.Event()

    # ── Public API ───────────────────────────────────────────────────────

    def scan(self) -> ScanResult:
        """
        Execute the full port scan and return a ScanResult object.
        """
        total = len(self.ports)
        logger.info(
            f"Starting scan on {self.target_ip} | "
            f"{total} ports | {self.threads} threads | "
            f"timeout={self.timeout}s | retries={self.retries}"
        )

        result = ScanResult(
            target=self.target_ip,
            ip=self.target_ip,
            start_time=time.time(),
        )

        try:
            with ThreadPoolExecutor(max_workers=self.threads) as executor:
                futures = {
                    executor.submit(self._scan_port, port): port
                    for port in self.ports
                }
                for future in as_completed(futures):
                    if self._stop_event.is_set():
                        break
                    try:
                        port_result = future.result()
                        if port_result:
                            with self._lock:
                                self._results.append(port_result)
                    except Exception as exc:
                        port = futures[future]
                        logger.debug(f"Port {port} raised: {exc}")

        except KeyboardInterrupt:
            logger.warning("Scan interrupted by user.")
            self._stop_event.set()

        result.end_time = time.time()
        result.ports = sorted(self._results, key=lambda p: p.port)
        result.total_scanned = self._scanned
        result.open_ports = sum(1 for p in result.ports if p.state == "open")
        result.closed_ports = sum(1 for p in result.ports if p.state == "closed")
        result.filtered_ports = sum(1 for p in result.ports if p.state == "filtered")

        logger.info(
            f"Scan complete: {result.open_ports} open, "
            f"{result.closed_ports} closed, "
            f"{result.filtered_ports} filtered "
            f"({result.duration:.2f}s)"
        )
        return result

    def stop(self):
        """Signal all workers to stop."""
        self._stop_event.set()

    # ── Single-port probe ────────────────────────────────────────────────

    def _scan_port(self, port: int) -> Optional[PortResult]:
        """
        Probe a single port with retry logic.

        1. Attempt a TCP connect.
        2. If it succeeds, grab the banner.
        3. Identify the service and extract version info.
        4. Rate-limit if configured.
        5. Update progress.
        """
        if self._stop_event.is_set():
            return None

        # Rate limiting
        if self.rate_limit > 0:
            time.sleep(self.rate_limit)

        state = "filtered"
        banner = ""
        response_time = 0.0

        for attempt in range(1, self.retries + 1):
            try:
                start = time.time()
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.timeout)

                # TCP connect attempt
                result_code = sock.connect_ex((self.target_ip, port))
                elapsed = time.time() - start

                if result_code == 0:
                    state = "open"
                    response_time = elapsed
                    # Attempt banner grab
                    banner = self._grab_banner(sock, port)
                    sock.close()
                    break
                else:
                    # Connection refused → port is closed (not filtered)
                    state = "closed"
                    sock.close()
                    break

            except socket.timeout:
                state = "filtered"
                logger.debug(
                    f"Port {port} timeout (attempt {attempt}/{self.retries})"
                )
            except ConnectionRefusedError:
                state = "closed"
                break
            except OSError as exc:
                state = "filtered"
                logger.debug(f"Port {port} OS error: {exc}")
                break
            finally:
                try:
                    sock.close()
                except Exception:
                    pass

        # Record response time for autonomous adjustment
        if response_time > 0:
            with self._lock:
                self._response_times.append(response_time)

        # Identify service & version
        service = self._identify_service(port, banner)
        version = self._extract_version(service, banner)

        # Update progress
        with self._lock:
            self._scanned += 1
            scanned = self._scanned

        if self.progress_callback:
            self.progress_callback(scanned, len(self.ports))

        # Autonomous thread adjustment
        if self.autonomous and scanned % self._adjust_interval == 0:
            self._adjust_threads()

        # Only return detailed results for open / filtered ports
        # to keep the dataset manageable on full scans
        if state == "closed" and len(self.ports) > 1024:
            return PortResult(port=port, state=state)

        return PortResult(
            port=port,
            state=state,
            service=service,
            banner=banner.strip(),
            version=version,
            response_time=round(response_time, 4),
        )

    # ── Banner Grabbing ──────────────────────────────────────────────────

    def _grab_banner(self, sock: socket.socket, port: int) -> str:
        """
        Try to read a banner from an open socket.

        For HTTP services we send a minimal GET request;
        for everything else we just wait for the server to speak first.
        """
        try:
            # Some services send a banner immediately
            sock.settimeout(2.0)

            if port in (80, 8080, 8443, 443, 8888):
                # HTTP: send a HEAD request to get the Server header
                request = (
                    f"HEAD / HTTP/1.1\r\n"
                    f"Host: {self.target_ip}\r\n"
                    f"Connection: close\r\n\r\n"
                )
                sock.sendall(request.encode())

            banner = sock.recv(1024).decode("utf-8", errors="ignore")
            return banner
        except (socket.timeout, socket.error, UnicodeDecodeError):
            return ""

    # ── Service Identification ───────────────────────────────────────────

    def _identify_service(self, port: int, banner: str) -> str:
        """
        Identify the service running on a port.

        Order of precedence:
        1. Banner content (most reliable)
        2. Well-known port number (fallback)
        """
        banner_lower = banner.lower()

        # Check banner for known protocol keywords
        if "ssh" in banner_lower:
            return "SSH"
        if "ftp" in banner_lower:
            return "FTP"
        if "smtp" in banner_lower or "esmtp" in banner_lower:
            return "SMTP"
        if "http" in banner_lower:
            return "HTTP"
        if "imap" in banner_lower:
            return "IMAP"
        if "pop" in banner_lower:
            return "POP3"
        if "mysql" in banner_lower or "mariadb" in banner_lower:
            return "MySQL"
        if "postgresql" in banner_lower:
            return "PostgreSQL"
        if "redis" in banner_lower:
            return "Redis"
        if "mongodb" in banner_lower:
            return "MongoDB"
        if "vnc" in banner_lower or "rfb" in banner_lower:
            return "VNC"

        # Fallback: port-based lookup
        return PORT_SERVICE_MAP.get(port, "Unknown")

    def _extract_version(self, service: str, banner: str) -> str:
        """
        Extract a version string from a banner using regex signatures.
        """
        if not banner or service not in BANNER_SIGNATURES:
            return ""

        pattern = BANNER_SIGNATURES[service]
        match = re.search(pattern, banner, re.IGNORECASE)
        return match.group(1).strip() if match else ""

    # ── Autonomous Thread Adjustment ─────────────────────────────────────

    def _adjust_threads(self):
        """
        Dynamically adjust thread count based on average response time.

        Logic:
          • Fast responses (< 0.3s avg) → increase threads (network is healthy)
          • Slow responses (> 1.0s avg) → decrease threads (network is stressed)
          • Otherwise keep current count

        This prevents overwhelming slow links while maximizing throughput
        on fast networks.
        """
        with self._lock:
            if len(self._response_times) < 10:
                return
            avg_rt = sum(self._response_times[-50:]) / len(self._response_times[-50:])
            self._response_times.clear()

        if avg_rt < 0.3 and self.threads < MAX_THREADS:
            new_threads = min(self.threads + 50, MAX_THREADS)
            logger.debug(
                f"Autonomous: fast responses ({avg_rt:.3f}s avg) → "
                f"threads {self.threads} → {new_threads}"
            )
            self.threads = new_threads
        elif avg_rt > 1.0 and self.threads > MIN_THREADS:
            new_threads = max(self.threads - 50, MIN_THREADS)
            logger.debug(
                f"Autonomous: slow responses ({avg_rt:.3f}s avg) → "
                f"threads {self.threads} → {new_threads}"
            )
            self.threads = new_threads

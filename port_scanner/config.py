

# ─── Scan Defaults ───────────────────────────────────────────────────────────
DEFAULT_TIMEOUT = 1.5          # seconds to wait for a connection reply
DEFAULT_THREADS = 100          # initial number of concurrent workers
MAX_THREADS = 500              # hard ceiling on thread count
MIN_THREADS = 10               # floor for dynamic thread adjustment
DEFAULT_RETRIES = 2            # how many times to retry a timed-out port
RATE_LIMIT_DELAY = 0.0         # seconds between each connection attempt (0 = no limit)

# ─── Port Ranges ─────────────────────────────────────────────────────────────
COMMON_PORTS = [
    20, 21, 22, 23, 25, 53, 69, 80, 110, 111, 119, 123, 135, 137, 138, 139,
    143, 161, 162, 389, 443, 445, 465, 514, 515, 587, 631, 636, 993, 995,
    1080, 1433, 1434, 1521, 1723, 2049, 2082, 2083, 2086, 2087, 3306, 3389,
    5432, 5900, 5901, 6379, 8080, 8443, 8888, 9090, 9200, 27017
]

WELL_KNOWN_PORTS = list(range(1, 1024))
ALL_PORTS = list(range(1, 65536))

# ─── Service Signatures ─────────────────────────────────────────────────────
# Maps well-known ports to service names for quick identification.
PORT_SERVICE_MAP = {
    20: "FTP-Data", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 67: "DHCP", 68: "DHCP", 69: "TFTP", 80: "HTTP",
    110: "POP3", 111: "RPCbind", 119: "NNTP", 123: "NTP",
    135: "MS-RPC", 137: "NetBIOS-NS", 138: "NetBIOS-DGM",
    139: "NetBIOS-SSN", 143: "IMAP", 161: "SNMP", 162: "SNMP-Trap",
    389: "LDAP", 443: "HTTPS", 445: "SMB", 465: "SMTPS",
    514: "Syslog", 515: "LPD", 587: "SMTP-Submission",
    631: "IPP", 636: "LDAPS", 993: "IMAPS", 995: "POP3S",
    1080: "SOCKS", 1433: "MS-SQL", 1434: "MS-SQL-Monitor",
    1521: "Oracle-DB", 1723: "PPTP", 2049: "NFS",
    2082: "cPanel", 2083: "cPanel-SSL", 2086: "WHM", 2087: "WHM-SSL",
    3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
    5900: "VNC", 5901: "VNC-1", 6379: "Redis",
    8080: "HTTP-Proxy", 8443: "HTTPS-Alt", 8888: "HTTP-Alt",
    9090: "Web-Console", 9200: "Elasticsearch", 27017: "MongoDB",
}

# ─── Banner / Version Signatures ────────────────────────────────────────────
# Regex patterns used to extract service version strings from banners.
BANNER_SIGNATURES = {
    "SSH":        r"(SSH-[\d.]+-\S+)",
    "FTP":        r"([\w\s]+ FTP[\w\s]*[\d.]+)",
    "SMTP":       r"([\w\s]+ ESMTP[\w\s]*)",
    "HTTP":       r"(Server:\s*\S+)",
    "MySQL":      r"(\d+\.\d+\.\d+[\w.-]*MariaDB|\d+\.\d+\.\d+)",
    "POP3":       r"(\+OK\s+.*)",
    "IMAP":       r"(\* OK\s+.*)",
    "Redis":      r"(redis_version:[\d.]+)",
    "MongoDB":    r"(MongoDB\s+[\d.]+)",
    "PostgreSQL": r"(PostgreSQL\s+[\d.]+)",
}

# ─── OS Fingerprinting (TTL heuristic) ──────────────────────────────────────
TTL_OS_MAP = {
    64:  "Linux / Unix / macOS",
    128: "Windows",
    255: "Cisco / Network Device",
}

# ─── Logging ─────────────────────────────────────────────────────────────────
LOG_FILE = "portintel.log"
LOG_FORMAT = "%(asctime)s | %(levelname)-8s | %(message)s"
LOG_DATE_FORMAT = "%Y-%m-%d %H:%M:%S"

# ─── Output ──────────────────────────────────────────────────────────────────
JSON_OUTPUT_FILE = "scan_results.json"
TXT_OUTPUT_FILE = "scan_report.txt"

# ─── UI ──────────────────────────────────────────────────────────────────────
BANNER = r"""
╔══════════════════════════════════════════════════════════════════════╗
║                                                                      ║
║    ██████╗  ██████╗ ██████╗ ████████╗██╗███╗   ██╗████████╗███████╗██╗  ║
║    ██╔══██╗██╔═══██╗██╔══██╗╚══██╔══╝██║████╗  ██║╚══██╔══╝██╔════╝██║  ║
║    ██████╔╝██║   ██║██████╔╝   ██║   ██║██╔██╗ ██║   ██║   █████╗  ██║  ║
║    ██╔═══╝ ██║   ██║██╔══██╗   ██║   ██║██║╚██╗██║   ██║   ██╔══╝  ██║  ║
║    ██║     ╚██████╔╝██║  ██║   ██║   ██║██║ ╚████║   ██║   ███████╗███████╗║
║    ╚═╝      ╚═════╝ ╚═╝  ╚═╝   ╚═╝   ╚═╝╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚══════╝║
║                                                                      ║
║          Autonomous Port Scanner & Network Intelligence              ║
║                        v1.0.0                                        ║
╚══════════════════════════════════════════════════════════════════════╝
"""

WARNING_BANNER = """
┌──────────────────────────────────────────────────────────────────────┐
│  ⚠  WARNING: This tool is intended for AUTHORIZED USE ONLY.         │
│  Unauthorized scanning of networks you do not own or have explicit  │
│  permission to test is ILLEGAL and may violate computer crime laws. │
│  By proceeding, you confirm that you have proper authorization.     │
└──────────────────────────────────────────────────────────────────────┘
"""

"""
logger.py - Centralized logging for PortIntel.

Sets up both file and console logging so every scan action is
recorded for audit / troubleshooting while keeping the terminal
output clean and colour-coded.
"""

import logging
import sys
from port_scanner.config import LOG_FILE, LOG_FORMAT, LOG_DATE_FORMAT


def setup_logger(name: str = "portintel", verbose: bool = False) -> logging.Logger:
    """
    Create and return a logger that writes to both a file and stderr.

    Parameters
    ----------
    name : str
        Logger name (usually the application name).
    verbose : bool
        If True, set console log level to DEBUG; otherwise INFO.

    Returns
    -------
    logging.Logger
    """
    logger = logging.getLogger(name)
    logger.setLevel(logging.DEBUG)  # capture everything; handlers filter

    # Prevent duplicate handlers on repeated calls
    if logger.handlers:
        return logger

    # ── File handler (always DEBUG) ──────────────────────────────────────
    file_handler = logging.FileHandler(LOG_FILE, mode="a", encoding="utf-8")
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(logging.Formatter(LOG_FORMAT, datefmt=LOG_DATE_FORMAT))

    # ── Console handler ──────────────────────────────────────────────────
    console_handler = logging.StreamHandler(sys.stderr)
    console_handler.setLevel(logging.DEBUG if verbose else logging.INFO)
    console_handler.setFormatter(logging.Formatter(LOG_FORMAT, datefmt=LOG_DATE_FORMAT))

    logger.addHandler(file_handler)
    logger.addHandler(console_handler)

    return logger

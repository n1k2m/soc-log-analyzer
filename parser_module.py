"""
Log parser for Apache Combined Log Format.

Example line:
  192.168.1.10 - - [10/Oct/2025:13:55:36 +0000] "POST /login HTTP/1.1" 401 512
"""

import re
import logging
from datetime import datetime
from pathlib import Path

log = logging.getLogger(__name__)

# Matches standard Apache/Nginx access log lines.
# Groups: ip, time, method, url, status, bytes (bytes optional)
_LOG_PATTERN = re.compile(
    r'(?P<ip>\S+)'           # client IP
    r' \S+ \S+'              # ident, auth (usually "-")
    r' \[(?P<time>[^\]]+)\]' # timestamp in brackets
    r' "(?P<method>\S+)'     # HTTP method
    r' (?P<url>\S+)'         # request path
    r' \S+"'                 # HTTP version
    r' (?P<status>\d{3})'    # response status code
    r'(?:\s+(?P<bytes>\d+))?' # response size (optional)
)

_TIME_FORMAT = "%d/%b/%Y:%H:%M:%S %z"


def _parse_line(line: str) -> dict | None:
    """Parse a single log line. Returns None if the line doesn't match."""
    match = _LOG_PATTERN.match(line.strip())
    if not match:
        return None

    entry = match.groupdict()

    try:
        entry["time"] = datetime.strptime(entry["time"], _TIME_FORMAT)
    except ValueError:
        log.debug(f"Could not parse timestamp: {entry['time']!r}")
        return None

    entry["bytes"] = int(entry["bytes"]) if entry["bytes"] else 0
    return entry


def load_logs(path: str) -> list[dict]:
    """
    Read and parse a log file. Skips malformed lines silently.

    Returns a list of parsed log entries (dicts).
    """
    file_path = Path(path)
    if not file_path.exists():
        log.error(f"Log file not found: {path}")
        return []

    entries = []
    skipped = 0

    with file_path.open(encoding="utf-8", errors="replace") as f:
        for line in f:
            parsed = _parse_line(line)
            if parsed:
                entries.append(parsed)
            else:
                skipped += 1

    if skipped:
        log.warning(f"Skipped {skipped} malformed log lines")

    return entries

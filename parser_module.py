import re
import logging
from datetime import datetime
from pathlib import Path

log = logging.getLogger(__name__)

_LOG_PATTERN = re.compile(
    r'(?P<ip>\S+)'           # client IP
    r' \S+ \S+'              # ident, auth 
    r' \[(?P<time>[^\]]+)\]' # timestamp in brackets
    r' "(?P<method>\S+)'     # HTTP method
    r' (?P<url>\S+)'         # request path
    r' \S+"'                 # HTTP version
    r' (?P<status>\d{3})'    # response status code
    r'(?:\s+(?P<bytes>\d+))?' # response size (optional)
)

_TIME_FORMAT = "%d/%b/%Y:%H:%M:%S %z"


def _parse_line(line: str) -> dict | None:
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

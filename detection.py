"""
Detection rules for SOC log analysis.

Each detect_* function is independent and returns a list of alert dicts.
run_detections() orchestrates all rules and applies correlation.
"""

import logging
from collections import Counter, defaultdict
from datetime import datetime

from config import (
    FAILED_LOGIN_THRESHOLD,
    HIGH_REQUEST_THRESHOLD,
    SEVERITY,
    SPIKE_MULTIPLIER,
    TI_MIN_REQUESTS,
)

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Detection rules
# ---------------------------------------------------------------------------

def detect_bruteforce(logs: list[dict]) -> list[dict]:
    """
    Flag IPs with repeated 401 responses within the log window.

    Why it matters: repeated login failures from one source is the clearest
    signal of credential stuffing or brute-force attacks.
    """
    failed_by_ip: dict[str, list[datetime]] = defaultdict(list)

    for entry in logs:
        if entry["status"] == "401":
            failed_by_ip[entry["ip"]].append(entry["time"])

    alerts = []
    for ip, timestamps in failed_by_ip.items():
        if len(timestamps) >= FAILED_LOGIN_THRESHOLD:
            alerts.append({
                "type": "BRUTEFORCE",
                "ip": ip,
                "failed_attempts": len(timestamps),
                "first_seen": str(min(timestamps)),
                "last_seen": str(max(timestamps)),
                "severity": SEVERITY["BRUTEFORCE"],
            })
            log.debug(f"BRUTEFORCE: {ip} — {len(timestamps)} failed logins")

    return alerts


def detect_blacklist_hits(logs: list[dict], ti_data: dict) -> list[dict]:
    """
    Flag requests from IPs present in TI blacklist data.

    Uses TI_MIN_REQUESTS to avoid noise from single-hit scanner probes —
    a single request from a known bad IP is worth noting but shouldn't
    generate a HIGH alert on its own.
    """
    if not ti_data:
        return []

    ip_counts = Counter(entry["ip"] for entry in logs)
    alerts = []

    for ip, count in ip_counts.items():
        if ip in ti_data and count >= TI_MIN_REQUESTS:
            ti_info = ti_data[ip]
            alerts.append({
                "type": "BLACKLIST_HIT",
                "ip": ip,
                "requests": count,
                "abuse_confidence": ti_info.get("abuseConfidenceScore", "n/a"),
                "country": ti_info.get("countryCode", "n/a"),
                "severity": SEVERITY["BLACKLIST_HIT"],
            })
            log.debug(f"BLACKLIST_HIT: {ip} ({count} requests)")

    return alerts


def detect_high_traffic(logs: list[dict], ti_data: dict) -> list[dict]:
    """
    Flag IPs that send an unusually high number of requests.

    Excludes IPs already caught by blacklist detection to avoid duplicate alerts.
    """
    ip_counts = Counter(entry["ip"] for entry in logs)
    already_flagged = set(ti_data.keys())
    alerts = []

    for ip, count in ip_counts.items():
        if ip not in already_flagged and count > HIGH_REQUEST_THRESHOLD:
            alerts.append({
                "type": "HIGH_TRAFFIC",
                "ip": ip,
                "requests": count,
                "severity": SEVERITY["HIGH_TRAFFIC"],
            })

    return alerts


def detect_traffic_spikes(logs: list[dict]) -> tuple[list[dict], dict]:
    """
    Detect time windows with significantly higher-than-average traffic.

    Buckets requests by minute, then flags any bucket exceeding
    average * SPIKE_MULTIPLIER.

    Returns (alerts, buckets) — buckets are passed to the reporter for charting.
    """
    buckets: dict[datetime, int] = defaultdict(int)

    for entry in logs:
        # Truncate to the minute for bucketing
        minute = entry["time"].replace(second=0, microsecond=0)
        buckets[minute] += 1

    if not buckets:
        return [], {}

    avg = sum(buckets.values()) / len(buckets)
    alerts = []

    for timestamp, count in buckets.items():
        if count > avg * SPIKE_MULTIPLIER:
            alerts.append({
                "type": "TRAFFIC_SPIKE",
                "time": str(timestamp),
                "requests_in_window": count,
                "average_requests": round(avg, 2),
                "severity": SEVERITY["TRAFFIC_SPIKE"],
            })

    return alerts, dict(buckets)


# ---------------------------------------------------------------------------
# Correlation
# ---------------------------------------------------------------------------

def correlate(alerts: list[dict]) -> list[dict]:
    """
    Upgrade severity when multiple signals converge on the same IP.

    Rule: BRUTEFORCE + BLACKLIST_HIT from the same IP -> CRITICAL.
    This is a simple example of multi-rule correlation, similar to what
    SIEM platforms do with correlation searches.
    """
    bruteforce_ips = {a["ip"] for a in alerts if a["type"] == "BRUTEFORCE"}
    blacklist_ips  = {a["ip"] for a in alerts if a["type"] == "BLACKLIST_HIT"}
    overlap = bruteforce_ips & blacklist_ips

    if not overlap:
        return alerts

    upgraded = []
    for alert in alerts:
        if alert.get("ip") in overlap:
            alert = {**alert, "severity": "CRITICAL", "correlated": True}
        upgraded.append(alert)

    for ip in overlap:
        log.warning(f"CORRELATION: {ip} triggered both BRUTEFORCE and BLACKLIST_HIT -> CRITICAL")

    return upgraded


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------

def run_detections(logs: list[dict], ti_data: dict) -> tuple[list[dict], dict]:
    """
    Run all detection rules and return (alerts, metrics).

    metrics["time_buckets"] is passed to the reporter for visualization.
    """
    alerts: list[dict] = []

    alerts.extend(detect_bruteforce(logs))
    alerts.extend(detect_blacklist_hits(logs, ti_data))
    alerts.extend(detect_high_traffic(logs, ti_data))

    spike_alerts, buckets = detect_traffic_spikes(logs)
    alerts.extend(spike_alerts)

    alerts = correlate(alerts)

    return alerts, {"time_buckets": buckets}

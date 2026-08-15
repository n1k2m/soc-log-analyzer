import logging
from collections import Counter, defaultdict
from dataclasses import replace
from datetime import datetime, timedelta, timezone

from config import (
    FAILED_LOGIN_THRESHOLD,
    FAILED_LOGIN_WINDOW_MINUTES,
    HIGH_REQUEST_THRESHOLD,
    SEVERITY,
    SPIKE_MULTIPLIER,
    TI_MIN_REQUESTS,
)
from models import Alert, LogEntry

log = logging.getLogger(__name__)

CRITICAL_CORRELATION_RULES = (
    ("BRUTEFORCE", "BLACKLIST_HIT"),
)


def _to_utc(timestamp: datetime) -> datetime:
    if timestamp.tzinfo is None:
        return timestamp.replace(tzinfo=timezone.utc)
    return timestamp.astimezone(timezone.utc)


def detect_bruteforce(
    logs: list[LogEntry],
    threshold: int = FAILED_LOGIN_THRESHOLD,
    window_minutes: int = FAILED_LOGIN_WINDOW_MINUTES,
) -> list[Alert]:
    failed_by_ip: dict[str, list[datetime]] = defaultdict(list)

    for entry in logs:
        if entry.status == "401":
            failed_by_ip[entry.ip].append(entry.time)

    alerts = []
    window = timedelta(minutes=window_minutes)

    for ip, timestamps in failed_by_ip.items():
        timestamps = sorted(timestamps)
        left = 0

        for right, timestamp in enumerate(timestamps):
            while timestamp - timestamps[left] > window:
                left += 1

            attempts = right - left + 1
            if attempts >= threshold:
                first_seen = timestamps[left]
                last_seen = timestamp
                alerts.append(Alert(
                    type="BRUTEFORCE",
                    ip=ip,
                    failed_attempts=attempts,
                    first_seen=str(first_seen),
                    last_seen=str(last_seen),
                    severity=SEVERITY["BRUTEFORCE"],
                ))
                log.debug(f"BRUTEFORCE: {ip} - {attempts} failed logins in {window_minutes}m")
                break

    return alerts


def detect_blacklist_hits(logs: list[LogEntry], ti_data: dict) -> list[Alert]:
    if not ti_data:
        return []

    ip_counts = Counter(entry.ip for entry in logs)
    alerts = []

    for ip, count in ip_counts.items():
        if ip in ti_data and count >= TI_MIN_REQUESTS:
            ti_info = ti_data[ip]
            alerts.append(Alert(
                type="BLACKLIST_HIT",
                ip=ip,
                requests=count,
                abuse_confidence=ti_info.get("abuseConfidenceScore", "n/a"),
                country=ti_info.get("countryCode", "n/a"),
                severity=SEVERITY["BLACKLIST_HIT"],
            ))
            log.debug(f"BLACKLIST_HIT: {ip} ({count} requests)")

    return alerts


def detect_high_traffic(logs: list[LogEntry], ti_data: dict) -> list[Alert]:
    ip_counts = Counter(entry.ip for entry in logs)
    already_flagged = set(ti_data.keys())
    alerts = []

    for ip, count in ip_counts.items():
        if ip not in already_flagged and count > HIGH_REQUEST_THRESHOLD:
            alerts.append(Alert(
                type="HIGH_TRAFFIC",
                ip=ip,
                requests=count,
                severity=SEVERITY["HIGH_TRAFFIC"],
            ))

    return alerts


def detect_traffic_spikes(logs: list[LogEntry]) -> tuple[list[Alert], dict]:
    buckets: dict[datetime, int] = defaultdict(int)

    for entry in logs:
        minute = _to_utc(entry.time).replace(second=0, microsecond=0)
        buckets[minute] += 1

    if not buckets:
        return [], {}

    avg = sum(buckets.values()) / len(buckets)
    alerts = []

    for timestamp, count in buckets.items():
        if count > avg * SPIKE_MULTIPLIER:
            alerts.append(Alert(
                type="TRAFFIC_SPIKE",
                time=str(timestamp),
                requests_in_window=count,
                average_requests=round(avg, 2),
                severity=SEVERITY["TRAFFIC_SPIKE"],
            ))

    return alerts, dict(buckets)


def correlate(alerts: list[Alert]) -> list[Alert]:
    critical_ips: set[str] = set()

    for first_type, second_type in CRITICAL_CORRELATION_RULES:
        first_ips = {a.ip for a in alerts if a.type == first_type and a.ip}
        second_ips = {a.ip for a in alerts if a.type == second_type and a.ip}
        critical_ips.update(first_ips & second_ips)

    if not critical_ips:
        return alerts

    upgraded = []
    for alert in alerts:
        if alert.ip in critical_ips:
            alert = replace(alert, severity="CRITICAL", correlated=True)
        upgraded.append(alert)

    for ip in critical_ips:
        log.warning(f"CORRELATION: {ip} triggered both BRUTEFORCE and BLACKLIST_HIT -> CRITICAL")

    return upgraded


def run_detections(logs: list[LogEntry], ti_data: dict) -> tuple[list[Alert], dict]:
    alerts: list[Alert] = []

    alerts.extend(detect_bruteforce(logs))
    alerts.extend(detect_blacklist_hits(logs, ti_data))
    alerts.extend(detect_high_traffic(logs, ti_data))

    spike_alerts, buckets = detect_traffic_spikes(logs)
    alerts.extend(spike_alerts)

    alerts = correlate(alerts)

    return alerts, {"time_buckets": buckets}

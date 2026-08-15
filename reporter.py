import json
import logging
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

import matplotlib.dates as mdates
import matplotlib.pyplot as plt

from models import Alert

log = logging.getLogger(__name__)


def _alert_to_dict(alert: Alert | dict) -> dict:
    return alert.to_dict() if isinstance(alert, Alert) else alert


def generate_report(alerts: list[Alert | dict], path: str) -> None:
    alert_dicts = [_alert_to_dict(alert) for alert in alerts]
    severity_order = ("CRITICAL", "HIGH", "MEDIUM", "LOW")
    sorted_alerts = sorted(
        alert_dicts,
        key=lambda a: severity_order.index(a.get("severity", "LOW"))
        if a.get("severity") in severity_order else len(severity_order)
    )

    summary = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "total_alerts": len(alert_dicts),
        "by_severity": {
            s: sum(1 for a in alert_dicts if a.get("severity") == s)
            for s in severity_order
        },
    }

    output = {"summary": summary, "alerts": sorted_alerts}

    Path(path).parent.mkdir(exist_ok=True)
    with open(path, "w") as f:
        json.dump(output, f, indent=2, default=str)

    log.info(f"Report written: {path} ({len(alert_dicts)} alerts)")


def plot_activity(buckets: dict, path: str) -> None:
    if not buckets:
        log.warning("No time bucket data to plot.")
        return

    normalized_buckets = defaultdict(int)
    for timestamp, count in buckets.items():
        if timestamp.tzinfo is None:
            timestamp = timestamp.replace(tzinfo=timezone.utc)
        normalized_buckets[timestamp.astimezone(timezone.utc)] += count

    times = sorted(normalized_buckets.keys())
    counts = [normalized_buckets[t] for t in times]

    fig, ax = plt.subplots(figsize=(12, 4))
    ax.plot(times, counts, linewidth=1.5, color="#e05c2a")
    ax.fill_between(times, counts, alpha=0.15, color="#e05c2a")

    ax.xaxis.set_major_formatter(mdates.DateFormatter("%H:%M", tz=timezone.utc))
    ax.xaxis.set_major_locator(mdates.AutoDateLocator())
    fig.autofmt_xdate()

    ax.set_title("Request Activity Over Time", fontsize=13, fontweight="bold")
    ax.set_xlabel("Time (UTC)")
    ax.set_ylabel("Requests / minute")
    ax.grid(axis="y", linestyle="--", alpha=0.4)

    plt.tight_layout()
    Path(path).parent.mkdir(exist_ok=True)
    plt.savefig(path, dpi=150)
    plt.close()

    log.info(f"Activity chart saved: {path}")

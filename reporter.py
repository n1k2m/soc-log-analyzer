import json
import logging
from datetime import datetime, timezone
from pathlib import Path

import matplotlib.dates as mdates
import matplotlib.pyplot as plt

log = logging.getLogger(__name__)


def generate_report(alerts: list[dict], path: str) -> None:
    severity_order = ("CRITICAL", "HIGH", "MEDIUM", "LOW")
    sorted_alerts = sorted(
        alerts,
        key=lambda a: severity_order.index(a.get("severity", "LOW"))
        if a.get("severity") in severity_order else len(severity_order)
    )

    summary = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "total_alerts": len(alerts),
        "by_severity": {
            s: sum(1 for a in alerts if a.get("severity") == s)
            for s in severity_order
        },
    }

    output = {"summary": summary, "alerts": sorted_alerts}

    Path(path).parent.mkdir(exist_ok=True)
    with open(path, "w") as f:
        json.dump(output, f, indent=2, default=str)

    log.info(f"Report written: {path} ({len(alerts)} alerts)")


def plot_activity(buckets: dict, path: str) -> None:
    if not buckets:
        log.warning("No time bucket data to plot.")
        return

    times = sorted(buckets.keys())
    counts = [buckets[t] for t in times]

    fig, ax = plt.subplots(figsize=(12, 4))
    ax.plot(times, counts, linewidth=1.5, color="#e05c2a")
    ax.fill_between(times, counts, alpha=0.15, color="#e05c2a")

    ax.xaxis.set_major_formatter(mdates.DateFormatter("%H:%M"))
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

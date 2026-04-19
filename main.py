"""
SOC Log Analyzer - Entry Point
"""

import logging
import sys
from pathlib import Path

from parser_module import load_logs
from detection import run_detections
from reporter import generate_report, plot_activity
from ti import load_ti_data

Path("output").mkdir(exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler("output/analyzer.log"),
    ],
)
log = logging.getLogger(__name__)


def main():
    log_path = "data/access.log"
    log.info(f"Loading logs from {log_path}")
    logs = load_logs(log_path)

    if not logs:
        log.error("No logs parsed. Check the log file format.")
        sys.exit(1)

    log.info(f"Parsed {len(logs)} log entries")

    log.info("Loading Threat Intelligence data")
    ti_data = load_ti_data()
    log.info(f"TI data loaded: {len(ti_data)} known malicious IPs")

    log.info("Running detection rules")
    alerts, metrics = run_detections(logs, ti_data)

    log.info(f"Detection complete. Total alerts: {len(alerts)}")
    for severity in ("CRITICAL", "HIGH", "MEDIUM"):
        count = sum(1 for a in alerts if a.get("severity") == severity)
        if count:
            log.info(f"  {severity}: {count}")

    generate_report(alerts, "output/report.json")
    plot_activity(metrics["time_buckets"], "output/activity.png")

    log.info("Report saved to output/report.json")
    log.info("Activity chart saved to output/activity.png")


if __name__ == "__main__":
    main()

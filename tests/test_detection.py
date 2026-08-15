import unittest
from datetime import datetime, timedelta, timezone

from detection import (
    correlate,
    detect_blacklist_hits,
    detect_bruteforce,
    detect_traffic_spikes,
)
from models import Alert, LogEntry


def entry(
    ip: str = "192.0.2.10",
    status: str = "200",
    when: datetime | None = None,
) -> LogEntry:
    return LogEntry(
        ip=ip,
        time=when or datetime(2025, 10, 10, 13, 0, tzinfo=timezone.utc),
        method="GET",
        url="/",
        status=status,
        bytes=100,
    )


class BruteForceDetectionTests(unittest.TestCase):
    def test_threshold_attempts_inside_window_alert(self) -> None:
        start = datetime(2025, 10, 10, 13, 0, tzinfo=timezone.utc)
        logs = [
            entry(status="401", when=start + timedelta(seconds=i * 20))
            for i in range(10)
        ]

        alerts = detect_bruteforce(logs, threshold=10, window_minutes=5)

        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].type, "BRUTEFORCE")
        self.assertEqual(alerts[0].failed_attempts, 10)

    def test_threshold_attempts_outside_window_do_not_alert(self) -> None:
        start = datetime(2025, 10, 10, 13, 0, tzinfo=timezone.utc)
        logs = [
            entry(status="401", when=start + timedelta(minutes=i))
            for i in range(10)
        ]

        alerts = detect_bruteforce(logs, threshold=10, window_minutes=5)

        self.assertEqual(alerts, [])

    def test_exact_threshold_alerts(self) -> None:
        start = datetime(2025, 10, 10, 13, 0, tzinfo=timezone.utc)
        logs = [
            entry(status="401", when=start + timedelta(seconds=i))
            for i in range(10)
        ]

        alerts = detect_bruteforce(logs, threshold=10, window_minutes=5)

        self.assertEqual(len(alerts), 1)

    def test_multiple_ips_are_tracked_independently(self) -> None:
        start = datetime(2025, 10, 10, 13, 0, tzinfo=timezone.utc)
        logs = [
            entry(ip="192.0.2.10", status="401", when=start + timedelta(seconds=i))
            for i in range(10)
        ]
        logs.extend(
            entry(ip="198.51.100.20", status="401", when=start + timedelta(seconds=i))
            for i in range(9)
        )

        alerts = detect_bruteforce(logs, threshold=10, window_minutes=5)

        self.assertEqual([alert.ip for alert in alerts], ["192.0.2.10"])


class BlacklistDetectionTests(unittest.TestCase):
    def test_blacklisted_ip_with_enough_requests_alerts(self) -> None:
        logs = [entry(ip="203.0.113.5") for _ in range(3)]
        ti_data = {"203.0.113.5": {"abuseConfidenceScore": 95, "countryCode": "US"}}

        alerts = detect_blacklist_hits(logs, ti_data)

        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].type, "BLACKLIST_HIT")

    def test_ip_absent_from_ti_does_not_alert(self) -> None:
        logs = [entry(ip="203.0.113.5") for _ in range(3)]
        ti_data = {"198.51.100.1": {"abuseConfidenceScore": 95}}

        alerts = detect_blacklist_hits(logs, ti_data)

        self.assertEqual(alerts, [])

    def test_blacklisted_ip_below_request_threshold_does_not_alert(self) -> None:
        logs = [entry(ip="203.0.113.5") for _ in range(2)]
        ti_data = {"203.0.113.5": {"abuseConfidenceScore": 95}}

        alerts = detect_blacklist_hits(logs, ti_data)

        self.assertEqual(alerts, [])


class TrafficSpikeDetectionTests(unittest.TestCase):
    def test_normal_traffic_does_not_alert(self) -> None:
        start = datetime(2025, 10, 10, 13, 0, tzinfo=timezone.utc)
        logs = [entry(when=start + timedelta(minutes=i)) for i in range(10)]

        alerts, _ = detect_traffic_spikes(logs)

        self.assertEqual(alerts, [])

    def test_obvious_spike_alerts(self) -> None:
        start = datetime(2025, 10, 10, 13, 0, tzinfo=timezone.utc)
        logs = [entry(when=start + timedelta(minutes=i)) for i in range(10)]
        logs.extend(entry(when=start + timedelta(minutes=20, seconds=i)) for i in range(50))

        alerts, _ = detect_traffic_spikes(logs)

        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].type, "TRAFFIC_SPIKE")

    def test_empty_input_is_safe(self) -> None:
        alerts, buckets = detect_traffic_spikes([])

        self.assertEqual(alerts, [])
        self.assertEqual(buckets, {})

    def test_time_buckets_are_normalized_to_utc(self) -> None:
        logs = [
            entry(
                when=datetime(
                    2025,
                    10,
                    10,
                    13,
                    55,
                    tzinfo=timezone(timedelta(hours=3)),
                )
            )
        ]

        _, buckets = detect_traffic_spikes(logs)
        bucket_time = next(iter(buckets))

        self.assertEqual(bucket_time.tzinfo, timezone.utc)
        self.assertEqual(bucket_time.hour, 10)
        self.assertEqual(bucket_time.minute, 55)


class CorrelationTests(unittest.TestCase):
    def test_bruteforce_and_blacklist_become_critical(self) -> None:
        alerts = [
            Alert(type="BRUTEFORCE", ip="192.0.2.10", severity="HIGH"),
            Alert(type="BLACKLIST_HIT", ip="192.0.2.10", severity="HIGH"),
        ]

        correlated = correlate(alerts)

        self.assertTrue(all(alert.severity == "CRITICAL" for alert in correlated))
        self.assertTrue(all(alert.correlated for alert in correlated))

    def test_only_bruteforce_severity_does_not_change(self) -> None:
        alerts = [Alert(type="BRUTEFORCE", ip="192.0.2.10", severity="HIGH")]

        correlated = correlate(alerts)

        self.assertEqual(correlated[0].severity, "HIGH")
        self.assertFalse(correlated[0].correlated)


if __name__ == "__main__":
    unittest.main()

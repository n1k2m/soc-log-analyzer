from dataclasses import asdict, dataclass
from datetime import datetime
from typing import Any


@dataclass(frozen=True)
class LogEntry:
    ip: str
    time: datetime
    method: str
    url: str
    status: str
    bytes: int = 0


@dataclass(frozen=True)
class Alert:
    type: str
    ip: str | None = None
    severity: str = "LOW"
    time: str | None = None
    failed_attempts: int | None = None
    first_seen: str | None = None
    last_seen: str | None = None
    requests: int | None = None
    requests_in_window: int | None = None
    average_requests: float | None = None
    abuse_confidence: Any = None
    country: str | None = None
    correlated: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            key: value
            for key, value in asdict(self).items()
            if value is not None and value is not False
        }

    def get(self, key: str, default: Any = None) -> Any:
        return self.to_dict().get(key, default)

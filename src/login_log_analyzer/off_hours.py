from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime, time, timezone
from ipaddress import IPv4Address, IPv6Address

from login_log_analyzer.authentication import (
    AuthenticationEvent,
    AuthenticationOutcome,
    AuthenticationPlatform,
)


@dataclass(frozen=True, slots=True)
class OffHoursLoginFinding:
    username: str
    timestamp: datetime
    source_ip: IPv4Address | IPv6Address | None
    platform: AuthenticationPlatform


class OffHoursLoginDetector:
    def __init__(
        self,
        allowed_weekdays: Iterable[int],
        start_time: time,
        end_time: time,
    ) -> None:
        try:
            weekdays = frozenset(allowed_weekdays)
        except TypeError as error:
            raise ValueError("allowed_weekdays must be an iterable of integers") from error

        if not weekdays:
            raise ValueError("allowed_weekdays must not be empty")
        if any(
            not isinstance(weekday, int)
            or isinstance(weekday, bool)
            or not 0 <= weekday <= 6
            for weekday in weekdays
        ):
            raise ValueError("allowed_weekdays must contain integers from 0 to 6")
        if not isinstance(start_time, time) or not isinstance(end_time, time):
            raise ValueError("start_time and end_time must be time instances")
        if start_time.tzinfo is not None or end_time.tzinfo is not None:
            raise ValueError("start_time and end_time must not include timezone information")
        if start_time == end_time:
            raise ValueError("start_time and end_time must be different")

        self._allowed_weekdays = weekdays
        self._start_time = start_time
        self._end_time = end_time

    def detect(self, events: Iterable[AuthenticationEvent]) -> list[OffHoursLoginFinding]:
        successful_events = [
            event
            for event in events
            if event.outcome is AuthenticationOutcome.SUCCESS
        ]
        successful_events.sort(key=self._event_sort_key)

        return [
            OffHoursLoginFinding(
                username=event.username,
                timestamp=event.timestamp,
                source_ip=event.source_ip,
                platform=event.platform,
            )
            for event in successful_events
            if not self._is_allowed(event.timestamp)
        ]

    def _is_allowed(self, timestamp: datetime) -> bool:
        weekday = timestamp.weekday()
        wall_time = timestamp.time()

        if self._start_time < self._end_time:
            return (
                weekday in self._allowed_weekdays
                and self._start_time <= wall_time < self._end_time
            )

        if wall_time >= self._start_time:
            return weekday in self._allowed_weekdays
        if wall_time < self._end_time:
            previous_weekday = (weekday - 1) % 7
            return previous_weekday in self._allowed_weekdays
        return False

    @staticmethod
    def _event_sort_key(
        event: AuthenticationEvent,
    ) -> tuple[datetime, str, str, int, int]:
        if event.source_ip is None:
            source_ip_version = 0
            source_ip_number = 0
        else:
            source_ip_version = event.source_ip.version
            source_ip_number = int(event.source_ip)

        return (
            event.timestamp.astimezone(timezone.utc),
            event.username,
            event.platform.value,
            source_ip_version,
            source_ip_number,
        )


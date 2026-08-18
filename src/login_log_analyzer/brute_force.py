from collections import deque
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from ipaddress import IPv4Address, IPv6Address

from login_log_analyzer.authentication import (
    AuthenticationEvent,
    AuthenticationOutcome,
)


@dataclass(frozen=True, slots=True)
class BruteForceFinding:
    username: str
    source_ip: IPv4Address | IPv6Address
    first_observed: datetime
    last_observed: datetime
    failure_count: int


class BruteForceDetector:
    def __init__(self, failure_threshold: int, window: timedelta) -> None:
        if (
            not isinstance(failure_threshold, int)
            or isinstance(failure_threshold, bool)
            or failure_threshold < 1
        ):
            raise ValueError("failure_threshold must be a positive integer")
        if not isinstance(window, timedelta) or window <= timedelta(0):
            raise ValueError("window must be a positive timedelta")

        self._failure_threshold = failure_threshold
        self._window = window

    def detect(self, events: Iterable[AuthenticationEvent]) -> list[BruteForceFinding]:
        failures = [
            event
            for event in events
            if event.outcome is AuthenticationOutcome.FAILURE
            and event.source_ip is not None
        ]
        failures.sort(
            key=lambda event: (
                self._absolute_timestamp(event.timestamp),
                event.username,
                event.source_ip.version,
                int(event.source_ip),
            )
        )

        active_windows: dict[
            tuple[str, IPv4Address | IPv6Address],
            deque[AuthenticationEvent],
        ] = {}
        reported_episodes: set[tuple[str, IPv4Address | IPv6Address]] = set()
        findings: list[BruteForceFinding] = []

        for event in failures:
            correlation_key = (event.username, event.source_ip)
            active_window = active_windows.setdefault(correlation_key, deque())
            event_timestamp = self._absolute_timestamp(event.timestamp)

            while active_window and (
                event_timestamp
                - self._absolute_timestamp(active_window[0].timestamp)
                > self._window
            ):
                active_window.popleft()

            if not active_window:
                reported_episodes.discard(correlation_key)

            active_window.append(event)

            if (
                len(active_window) >= self._failure_threshold
                and correlation_key not in reported_episodes
            ):
                findings.append(
                    BruteForceFinding(
                        username=event.username,
                        source_ip=event.source_ip,
                        first_observed=active_window[0].timestamp,
                        last_observed=event.timestamp,
                        failure_count=len(active_window),
                    )
                )
                reported_episodes.add(correlation_key)

        return findings

    @staticmethod
    def _absolute_timestamp(timestamp: datetime) -> datetime:
        return timestamp.astimezone(timezone.utc)


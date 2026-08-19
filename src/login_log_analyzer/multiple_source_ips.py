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
class MultipleSourceIPsFinding:
    username: str
    first_observed: datetime
    last_observed: datetime
    distinct_source_ip_count: int
    source_ips: tuple[IPv4Address | IPv6Address, ...]


class MultipleSourceIPsDetector:
    def __init__(self, source_ip_threshold: int, window: timedelta) -> None:
        if (
            not isinstance(source_ip_threshold, int)
            or isinstance(source_ip_threshold, bool)
            or source_ip_threshold < 2
        ):
            raise ValueError("source_ip_threshold must be an integer of at least 2")
        if not isinstance(window, timedelta) or window <= timedelta(0):
            raise ValueError("window must be a positive timedelta")

        self._source_ip_threshold = source_ip_threshold
        self._window = window

    def detect(
        self,
        events: Iterable[AuthenticationEvent],
    ) -> list[MultipleSourceIPsFinding]:
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
                event.platform.value,
            )
        )

        active_windows: dict[str, deque[AuthenticationEvent]] = {}
        source_ip_counts: dict[
            str,
            dict[IPv4Address | IPv6Address, int],
        ] = {}
        last_failures: dict[str, datetime] = {}
        reported_episodes: set[str] = set()
        findings: list[MultipleSourceIPsFinding] = []

        for event in failures:
            event_timestamp = self._absolute_timestamp(event.timestamp)
            previous_timestamp = last_failures.get(event.username)
            active_window = active_windows.setdefault(event.username, deque())
            active_source_ip_counts = source_ip_counts.setdefault(event.username, {})

            if (
                previous_timestamp is not None
                and event_timestamp - previous_timestamp > self._window
            ):
                active_window.clear()
                active_source_ip_counts.clear()
                reported_episodes.discard(event.username)

            last_failures[event.username] = event_timestamp

            while active_window and (
                event_timestamp
                - self._absolute_timestamp(active_window[0].timestamp)
                > self._window
            ):
                removed_event = active_window.popleft()
                removed_source_ip = removed_event.source_ip
                remaining_count = active_source_ip_counts[removed_source_ip] - 1
                if remaining_count == 0:
                    del active_source_ip_counts[removed_source_ip]
                else:
                    active_source_ip_counts[removed_source_ip] = remaining_count

            active_window.append(event)
            active_source_ip_counts[event.source_ip] = (
                active_source_ip_counts.get(event.source_ip, 0) + 1
            )

            if (
                len(active_source_ip_counts) >= self._source_ip_threshold
                and event.username not in reported_episodes
            ):
                source_ips = tuple(
                    sorted(
                        active_source_ip_counts,
                        key=lambda source_ip: (source_ip.version, int(source_ip)),
                    )
                )
                findings.append(
                    MultipleSourceIPsFinding(
                        username=event.username,
                        first_observed=active_window[0].timestamp,
                        last_observed=event.timestamp,
                        distinct_source_ip_count=len(source_ips),
                        source_ips=source_ips,
                    )
                )
                reported_episodes.add(event.username)

        return findings

    @staticmethod
    def _absolute_timestamp(timestamp: datetime) -> datetime:
        return timestamp.astimezone(timezone.utc)

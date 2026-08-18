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
class PasswordSprayFinding:
    source_ip: IPv4Address | IPv6Address
    first_observed: datetime
    last_observed: datetime
    distinct_username_count: int
    usernames: tuple[str, ...]


class PasswordSprayDetector:
    def __init__(self, username_threshold: int, window: timedelta) -> None:
        if (
            not isinstance(username_threshold, int)
            or isinstance(username_threshold, bool)
            or username_threshold < 2
        ):
            raise ValueError("username_threshold must be an integer of at least 2")
        if not isinstance(window, timedelta) or window <= timedelta(0):
            raise ValueError("window must be a positive timedelta")

        self._username_threshold = username_threshold
        self._window = window

    def detect(self, events: Iterable[AuthenticationEvent]) -> list[PasswordSprayFinding]:
        failures = [
            event
            for event in events
            if event.outcome is AuthenticationOutcome.FAILURE
            and event.source_ip is not None
        ]
        failures.sort(
            key=lambda event: (
                self._absolute_timestamp(event.timestamp),
                event.source_ip.version,
                int(event.source_ip),
                event.username,
            )
        )

        active_windows: dict[
            IPv4Address | IPv6Address,
            deque[AuthenticationEvent],
        ] = {}
        username_counts: dict[
            IPv4Address | IPv6Address,
            dict[str, int],
        ] = {}
        reported_episodes: set[IPv4Address | IPv6Address] = set()
        findings: list[PasswordSprayFinding] = []

        for event in failures:
            source_ip = event.source_ip
            active_window = active_windows.setdefault(source_ip, deque())
            active_username_counts = username_counts.setdefault(source_ip, {})
            event_timestamp = self._absolute_timestamp(event.timestamp)

            while active_window and (
                event_timestamp
                - self._absolute_timestamp(active_window[0].timestamp)
                > self._window
            ):
                removed_event = active_window.popleft()
                remaining_count = active_username_counts[removed_event.username] - 1
                if remaining_count == 0:
                    del active_username_counts[removed_event.username]
                else:
                    active_username_counts[removed_event.username] = remaining_count

            if not active_window:
                reported_episodes.discard(source_ip)

            active_window.append(event)
            active_username_counts[event.username] = (
                active_username_counts.get(event.username, 0) + 1
            )

            if (
                len(active_username_counts) >= self._username_threshold
                and source_ip not in reported_episodes
            ):
                usernames = tuple(sorted(active_username_counts))
                findings.append(
                    PasswordSprayFinding(
                        source_ip=source_ip,
                        first_observed=active_window[0].timestamp,
                        last_observed=event.timestamp,
                        distinct_username_count=len(usernames),
                        usernames=usernames,
                    )
                )
                reported_episodes.add(source_ip)

        return findings

    @staticmethod
    def _absolute_timestamp(timestamp: datetime) -> datetime:
        return timestamp.astimezone(timezone.utc)

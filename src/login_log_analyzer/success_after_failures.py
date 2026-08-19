from collections import deque
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from ipaddress import IPv4Address, IPv6Address

from login_log_analyzer.authentication import (
    AuthenticationEvent,
    AuthenticationOutcome,
    AuthenticationPlatform,
)


@dataclass(frozen=True, slots=True)
class SuccessfulLoginAfterFailuresFinding:
    username: str
    source_ip: IPv4Address | IPv6Address
    first_failure: datetime
    last_failure: datetime
    successful_login: datetime
    failure_count: int
    platform: AuthenticationPlatform


class SuccessfulLoginAfterFailuresDetector:
    def __init__(self, failure_threshold: int, window: timedelta) -> None:
        if (
            not isinstance(failure_threshold, int)
            or isinstance(failure_threshold, bool)
            or failure_threshold < 2
        ):
            raise ValueError("failure_threshold must be an integer of at least 2")
        if not isinstance(window, timedelta) or window <= timedelta(0):
            raise ValueError("window must be a positive timedelta")

        self._failure_threshold = failure_threshold
        self._window = window

    def detect(
        self,
        events: Iterable[AuthenticationEvent],
    ) -> list[SuccessfulLoginAfterFailuresFinding]:
        eligible_events = [event for event in events if event.source_ip is not None]
        eligible_events.sort(key=self._event_sort_key)

        active_failures: dict[
            tuple[str, IPv4Address | IPv6Address],
            deque[AuthenticationEvent],
        ] = {}
        findings: list[SuccessfulLoginAfterFailuresFinding] = []

        for event in eligible_events:
            correlation_key = (event.username, event.source_ip)
            event_timestamp = self._absolute_timestamp(event.timestamp)
            failures = active_failures.setdefault(correlation_key, deque())

            while failures and (
                event_timestamp - self._absolute_timestamp(failures[0].timestamp)
                > self._window
            ):
                failures.popleft()

            if event.outcome is AuthenticationOutcome.FAILURE:
                failures.append(event)
                continue

            if len(failures) >= self._failure_threshold:
                findings.append(
                    SuccessfulLoginAfterFailuresFinding(
                        username=event.username,
                        source_ip=event.source_ip,
                        first_failure=failures[0].timestamp,
                        last_failure=failures[-1].timestamp,
                        successful_login=event.timestamp,
                        failure_count=len(failures),
                        platform=event.platform,
                    )
                )
            active_failures.pop(correlation_key, None)

        return findings

    @classmethod
    def _event_sort_key(
        cls,
        event: AuthenticationEvent,
    ) -> tuple[datetime, str, int, int, int, str]:
        if event.source_ip is None:
            source_ip_version = 0
            source_ip_number = 0
        else:
            source_ip_version = event.source_ip.version
            source_ip_number = int(event.source_ip)
        outcome_order = 0 if event.outcome is AuthenticationOutcome.SUCCESS else 1
        return (
            cls._absolute_timestamp(event.timestamp),
            event.username,
            source_ip_version,
            source_ip_number,
            outcome_order,
            event.platform.value,
        )

    @staticmethod
    def _absolute_timestamp(timestamp: datetime) -> datetime:
        return timestamp.astimezone(timezone.utc)

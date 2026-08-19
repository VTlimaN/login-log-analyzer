from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from ipaddress import IPv4Address, IPv6Address

from login_log_analyzer.account_lockout import AccountLockoutEvent
from login_log_analyzer.brute_force import BruteForceFinding


@dataclass(frozen=True, slots=True)
class BruteForceAccountLockoutFinding:
    username: str
    source_ip: IPv4Address | IPv6Address
    brute_force_first_failure: datetime
    brute_force_last_failure: datetime
    brute_force_failure_count: int
    lockout_timestamp: datetime
    correlation_delay: timedelta

    def __post_init__(self) -> None:
        if not isinstance(self.username, str):
            raise TypeError("username must be a string")
        if not self.username.strip():
            raise ValueError("username must not be empty")
        if not isinstance(self.source_ip, (IPv4Address, IPv6Address)):
            raise TypeError("source_ip must be an IPv4Address or IPv6Address")
        for field_name in (
            "brute_force_first_failure",
            "brute_force_last_failure",
            "lockout_timestamp",
        ):
            value = getattr(self, field_name)
            if not isinstance(value, datetime):
                raise TypeError(f"{field_name} must be a datetime")
            if value.tzinfo is None or value.utcoffset() is None:
                raise ValueError(f"{field_name} must include timezone information")
        if (
            not isinstance(self.brute_force_failure_count, int)
            or isinstance(self.brute_force_failure_count, bool)
        ):
            raise TypeError("brute_force_failure_count must be an integer")
        if self.brute_force_failure_count < 1:
            raise ValueError("brute_force_failure_count must be positive")
        if not isinstance(self.correlation_delay, timedelta):
            raise TypeError("correlation_delay must be a timedelta")
        if self.correlation_delay < timedelta(0):
            raise ValueError("correlation_delay must not be negative")
        first = self.brute_force_first_failure.astimezone(timezone.utc)
        last = self.brute_force_last_failure.astimezone(timezone.utc)
        locked = self.lockout_timestamp.astimezone(timezone.utc)
        if first > last:
            raise ValueError("brute_force_first_failure must not follow the last failure")
        if last > locked:
            raise ValueError("brute_force_last_failure must not follow the lockout")
        if self.correlation_delay != locked - last:
            raise ValueError("correlation_delay must match the timestamp difference")


class BruteForceAccountLockoutCorrelator:
    def __init__(self, window: timedelta = timedelta(minutes=15)) -> None:
        if not isinstance(window, timedelta) or window <= timedelta(0):
            raise ValueError("window must be a positive timedelta")
        self._window = window

    def correlate(
        self,
        brute_force_findings: Iterable[BruteForceFinding],
        account_lockout_events: Iterable[AccountLockoutEvent],
    ) -> tuple[BruteForceAccountLockoutFinding, ...]:
        findings = tuple(brute_force_findings)
        lockouts = tuple(account_lockout_events)
        if any(not isinstance(finding, BruteForceFinding) for finding in findings):
            raise TypeError("brute_force_findings must contain BruteForceFinding values")
        if any(not isinstance(event, AccountLockoutEvent) for event in lockouts):
            raise TypeError("account_lockout_events must contain AccountLockoutEvent values")

        ordered_findings = sorted(findings, key=self._finding_order)
        ordered_lockouts = sorted(lockouts, key=self._lockout_order)
        correlated: list[BruteForceAccountLockoutFinding] = []

        for lockout in ordered_lockouts:
            lockout_time = self._absolute_timestamp(lockout.timestamp)
            eligible = [
                finding
                for finding in ordered_findings
                if finding.username == lockout.username
                and self._absolute_timestamp(finding.last_observed) <= lockout_time
                and lockout_time
                - self._absolute_timestamp(finding.last_observed)
                <= self._window
            ]
            if not eligible:
                continue
            finding = eligible[-1]
            delay = lockout_time - self._absolute_timestamp(finding.last_observed)
            correlated.append(
                BruteForceAccountLockoutFinding(
                    username=finding.username,
                    source_ip=finding.source_ip,
                    brute_force_first_failure=finding.first_observed,
                    brute_force_last_failure=finding.last_observed,
                    brute_force_failure_count=finding.failure_count,
                    lockout_timestamp=lockout.timestamp,
                    correlation_delay=delay,
                )
            )
        return tuple(correlated)

    @classmethod
    def _finding_order(cls, finding: BruteForceFinding) -> tuple[object, ...]:
        return (
            cls._absolute_timestamp(finding.last_observed),
            cls._absolute_timestamp(finding.first_observed),
            finding.username,
            finding.source_ip.version,
            int(finding.source_ip),
            finding.failure_count,
        )

    @classmethod
    def _lockout_order(cls, event: AccountLockoutEvent) -> tuple[object, ...]:
        return (
            cls._absolute_timestamp(event.timestamp),
            event.username,
            event.target_domain or "",
            event.caller_computer or "",
            event.recording_computer or "",
        )

    @staticmethod
    def _absolute_timestamp(timestamp: datetime) -> datetime:
        if not isinstance(timestamp, datetime):
            raise TypeError("finding timestamps must be datetimes")
        if timestamp.tzinfo is None or timestamp.utcoffset() is None:
            raise ValueError("finding timestamps must include timezone information")
        return timestamp.astimezone(timezone.utc)

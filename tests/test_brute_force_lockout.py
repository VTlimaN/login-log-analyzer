from dataclasses import FrozenInstanceError
from datetime import datetime, timedelta, timezone
from ipaddress import ip_address

import pytest

from login_log_analyzer.account_lockout import AccountLockoutEvent
from login_log_analyzer.authentication import AuthenticationPlatform
from login_log_analyzer.brute_force import BruteForceFinding
from login_log_analyzer.brute_force_lockout import (
    BruteForceAccountLockoutCorrelator,
    BruteForceAccountLockoutFinding,
)


def timestamp(minute: int, *, offset: int = 0) -> datetime:
    return datetime(2026, 8, 19, 12, minute, tzinfo=timezone(timedelta(hours=offset)))


def brute_force(
    *,
    username: str = "alice",
    source_ip: str = "192.0.2.10",
    first: datetime | None = None,
    last: datetime | None = None,
    count: int = 5,
) -> BruteForceFinding:
    return BruteForceFinding(
        username=username,
        source_ip=ip_address(source_ip),
        first_observed=first or timestamp(0),
        last_observed=last or timestamp(4),
        failure_count=count,
    )


def lockout(
    *,
    username: str = "alice",
    observed: datetime | None = None,
) -> AccountLockoutEvent:
    return AccountLockoutEvent(
        timestamp=observed or timestamp(10),
        username=username,
        platform=AuthenticationPlatform.WINDOWS,
    )


def correlate(
    findings: tuple[BruteForceFinding, ...],
    lockouts: tuple[AccountLockoutEvent, ...],
    *,
    window: timedelta | None = None,
) -> tuple[BruteForceAccountLockoutFinding, ...]:
    correlator = (
        BruteForceAccountLockoutCorrelator()
        if window is None
        else BruteForceAccountLockoutCorrelator(window=window)
    )
    return correlator.correlate(findings, lockouts)


def test_default_window_correlates_within_fifteen_minutes() -> None:
    assert len(correlate((brute_force(last=timestamp(0)),), (lockout(observed=timestamp(15)),))) == 1


def test_custom_positive_window_is_used() -> None:
    assert correlate(
        (brute_force(last=timestamp(0)),),
        (lockout(observed=timestamp(6)),),
        window=timedelta(minutes=5),
    ) == ()


@pytest.mark.parametrize("window", [timedelta(0), timedelta(seconds=-1), 15, None])
def test_rejects_invalid_window(window: object) -> None:
    with pytest.raises(ValueError, match="positive timedelta"):
        BruteForceAccountLockoutCorrelator(window=window)  # type: ignore[arg-type]


def test_correlates_exact_username_inside_inclusive_window() -> None:
    result = correlate(
        (brute_force(first=timestamp(0), last=timestamp(5), count=7),),
        (lockout(observed=timestamp(20)),),
    )

    assert result == (
        BruteForceAccountLockoutFinding(
            username="alice",
            source_ip=ip_address("192.0.2.10"),
            brute_force_first_failure=timestamp(0),
            brute_force_last_failure=timestamp(5),
            brute_force_failure_count=7,
            lockout_timestamp=timestamp(20),
            correlation_delay=timedelta(minutes=15),
        ),
    )


def test_outside_window_does_not_correlate() -> None:
    assert correlate(
        (brute_force(last=timestamp(0)),),
        (lockout(observed=timestamp(16)),),
    ) == ()


def test_lockout_before_brute_force_does_not_correlate() -> None:
    assert correlate(
        (brute_force(last=timestamp(10)),),
        (lockout(observed=timestamp(9)),),
    ) == ()


def test_same_absolute_instant_correlates_across_offsets() -> None:
    finding_time = datetime(2026, 8, 19, 9, 0, tzinfo=timezone(timedelta(hours=-3)))
    lockout_time = datetime(2026, 8, 19, 14, 0, tzinfo=timezone(timedelta(hours=2)))

    result = correlate(
        (brute_force(first=finding_time, last=finding_time),),
        (lockout(observed=lockout_time),),
    )

    assert result[0].correlation_delay == timedelta(0)
    assert result[0].brute_force_last_failure is finding_time
    assert result[0].lockout_timestamp is lockout_time


@pytest.mark.parametrize("lockout_username", ["Alice", "alice ", "bob"])
def test_username_matching_is_exact(lockout_username: str) -> None:
    assert correlate((brute_force(username="alice"),), (lockout(username=lockout_username),)) == ()


@pytest.mark.parametrize("source_ip", ["192.0.2.80", "2001:db8::80"])
def test_source_ip_is_preserved_from_brute_force(source_ip: str) -> None:
    result = correlate((brute_force(source_ip=source_ip),), (lockout(),))

    assert result[0].source_ip == ip_address(source_ip)


def test_selects_most_recent_eligible_finding_for_one_lockout() -> None:
    older = brute_force(source_ip="192.0.2.1", last=timestamp(2))
    newer = brute_force(source_ip="192.0.2.2", last=timestamp(8))

    result = correlate((newer, older), (lockout(observed=timestamp(10)),))

    assert len(result) == 1
    assert result[0].source_ip == ip_address("192.0.2.2")


def test_multiple_lockouts_correlate_independently() -> None:
    result = correlate(
        (brute_force(last=timestamp(4)),),
        (lockout(observed=timestamp(12)), lockout(observed=timestamp(10))),
    )

    assert [finding.lockout_timestamp for finding in result] == [
        timestamp(10),
        timestamp(12),
    ]


def test_duplicate_lockout_inputs_produce_one_result_per_observation() -> None:
    event = lockout()

    assert len(correlate((brute_force(),), (event, event))) == 2


def test_input_order_does_not_change_result() -> None:
    findings = (
        brute_force(username="bob", source_ip="192.0.2.2"),
        brute_force(username="alice", source_ip="192.0.2.1"),
    )
    lockouts = (lockout(username="bob"), lockout(username="alice"))

    assert correlate(findings, lockouts) == correlate(
        tuple(reversed(findings)),
        tuple(reversed(lockouts)),
    )


def test_finding_is_immutable() -> None:
    finding = correlate((brute_force(),), (lockout(),))[0]

    with pytest.raises(FrozenInstanceError):
        finding.username = "changed"  # type: ignore[misc]


@pytest.mark.parametrize(
    ("changes", "error"),
    [
        ({"username": " "}, ValueError),
        ({"source_ip": "192.0.2.1"}, TypeError),
        ({"brute_force_failure_count": True}, TypeError),
        ({"brute_force_failure_count": 0}, ValueError),
        ({"brute_force_first_failure": datetime(2026, 8, 19)}, ValueError),
        ({"correlation_delay": "six minutes"}, TypeError),
        ({"correlation_delay": timedelta(minutes=5)}, ValueError),
        ({"brute_force_first_failure": timestamp(6)}, ValueError),
        ({"lockout_timestamp": timestamp(3)}, ValueError),
    ],
)
def test_finding_rejects_invalid_fields(
    changes: dict[str, object],
    error: type[Exception],
) -> None:
    values: dict[str, object] = {
        "username": "alice",
        "source_ip": ip_address("192.0.2.10"),
        "brute_force_first_failure": timestamp(0),
        "brute_force_last_failure": timestamp(4),
        "brute_force_failure_count": 5,
        "lockout_timestamp": timestamp(10),
        "correlation_delay": timedelta(minutes=6),
    }
    values.update(changes)

    with pytest.raises(error):
        BruteForceAccountLockoutFinding(**values)  # type: ignore[arg-type]


def test_rejects_invalid_input_contents() -> None:
    correlator = BruteForceAccountLockoutCorrelator()

    with pytest.raises(TypeError, match="BruteForceFinding"):
        correlator.correlate((object(),), ())  # type: ignore[arg-type]
    with pytest.raises(TypeError, match="AccountLockoutEvent"):
        correlator.correlate((), (object(),))  # type: ignore[arg-type]


def test_rejects_naive_brute_force_timestamp() -> None:
    finding = brute_force(last=datetime(2026, 8, 19, 12, 4))

    with pytest.raises(ValueError, match="timezone"):
        correlate((finding,), (lockout(),))

from dataclasses import FrozenInstanceError
from datetime import datetime, timedelta, timezone
from ipaddress import IPv4Address, IPv6Address

import pytest

from login_log_analyzer.authentication import (
    AuthenticationEvent,
    AuthenticationOutcome,
    AuthenticationPlatform,
)
from login_log_analyzer.brute_force import BruteForceDetector, BruteForceFinding


BASE_TIMESTAMP = datetime(2026, 8, 18, 10, 0, tzinfo=timezone.utc)


def create_event(
    minute: int,
    *,
    username: str = "admin",
    source_ip: IPv4Address | IPv6Address | None = IPv4Address("192.0.2.25"),
    outcome: AuthenticationOutcome = AuthenticationOutcome.FAILURE,
    platform: AuthenticationPlatform = AuthenticationPlatform.LINUX,
    timestamp: datetime | None = None,
) -> AuthenticationEvent:
    return AuthenticationEvent(
        timestamp=timestamp or BASE_TIMESTAMP + timedelta(minutes=minute),
        username=username,
        outcome=outcome,
        platform=platform,
        source_ip=source_ip,
    )


def test_detects_threshold_for_same_username_and_source_ip() -> None:
    detector = BruteForceDetector(failure_threshold=3, window=timedelta(minutes=5))
    events = [create_event(0), create_event(2), create_event(5)]

    findings = detector.detect(events)

    assert findings == [
        BruteForceFinding(
            username="admin",
            source_ip=IPv4Address("192.0.2.25"),
            first_observed=BASE_TIMESTAMP,
            last_observed=BASE_TIMESTAMP + timedelta(minutes=5),
            failure_count=3,
        )
    ]


def test_does_not_detect_below_threshold() -> None:
    detector = BruteForceDetector(failure_threshold=3, window=timedelta(minutes=5))

    assert detector.detect([create_event(0), create_event(1)]) == []


def test_does_not_detect_failures_outside_window() -> None:
    detector = BruteForceDetector(failure_threshold=3, window=timedelta(minutes=5))
    events = [create_event(0), create_event(6), create_event(12)]

    assert detector.detect(events) == []


def test_time_window_boundary_is_inclusive() -> None:
    detector = BruteForceDetector(failure_threshold=2, window=timedelta(minutes=5))

    findings = detector.detect([create_event(0), create_event(5)])

    assert len(findings) == 1


def test_event_outside_time_window_boundary_is_excluded() -> None:
    detector = BruteForceDetector(failure_threshold=2, window=timedelta(minutes=5))
    timestamp = BASE_TIMESTAMP + timedelta(minutes=5, microseconds=1)

    findings = detector.detect([create_event(0), create_event(0, timestamp=timestamp)])

    assert findings == []


def test_detection_is_independent_of_input_order() -> None:
    detector = BruteForceDetector(failure_threshold=3, window=timedelta(minutes=5))
    chronological_events = [create_event(0), create_event(1), create_event(2)]

    chronological_findings = detector.detect(chronological_events)
    reversed_findings = detector.detect(reversed(chronological_events))

    assert reversed_findings == chronological_findings


def test_success_does_not_count_or_reset_failures() -> None:
    detector = BruteForceDetector(failure_threshold=3, window=timedelta(minutes=5))
    events = [
        create_event(0),
        create_event(1, outcome=AuthenticationOutcome.SUCCESS),
        create_event(2),
        create_event(4),
    ]

    findings = detector.detect(events)

    assert len(findings) == 1
    assert findings[0].failure_count == 3


def test_ignores_events_without_source_ip() -> None:
    detector = BruteForceDetector(failure_threshold=2, window=timedelta(minutes=5))

    findings = detector.detect(
        [create_event(0, source_ip=None), create_event(1, source_ip=None)]
    )

    assert findings == []


def test_correlates_usernames_exactly() -> None:
    detector = BruteForceDetector(failure_threshold=2, window=timedelta(minutes=5))
    events = [
        create_event(0, username="Admin"),
        create_event(1, username="admin"),
    ]

    assert detector.detect(events) == []


def test_keeps_source_ips_separate() -> None:
    detector = BruteForceDetector(failure_threshold=2, window=timedelta(minutes=5))
    events = [
        create_event(0, source_ip=IPv4Address("192.0.2.25")),
        create_event(1, source_ip=IPv4Address("192.0.2.26")),
    ]

    assert detector.detect(events) == []


def test_correlates_ipv6_source_address() -> None:
    detector = BruteForceDetector(failure_threshold=2, window=timedelta(minutes=5))
    source_ip = IPv6Address("2001:db8::25")

    findings = detector.detect(
        [create_event(0, source_ip=source_ip), create_event(1, source_ip=source_ip)]
    )

    assert len(findings) == 1
    assert findings[0].source_ip == source_ip


@pytest.mark.parametrize(
    "platform",
    [AuthenticationPlatform.LINUX, AuthenticationPlatform.WINDOWS],
)
def test_detects_normalized_events_from_each_platform(
    platform: AuthenticationPlatform,
) -> None:
    detector = BruteForceDetector(failure_threshold=2, window=timedelta(minutes=5))

    findings = detector.detect(
        [create_event(0, platform=platform), create_event(1, platform=platform)]
    )

    assert len(findings) == 1


def test_correlates_mixed_platform_events() -> None:
    detector = BruteForceDetector(failure_threshold=2, window=timedelta(minutes=5))
    events = [
        create_event(0, platform=AuthenticationPlatform.LINUX),
        create_event(1, platform=AuthenticationPlatform.WINDOWS),
    ]

    assert len(detector.detect(events)) == 1


def test_compares_different_timezone_offsets_by_absolute_time() -> None:
    detector = BruteForceDetector(failure_threshold=2, window=timedelta(minutes=5))
    first_timestamp = datetime(2026, 8, 18, 10, 0, tzinfo=timezone.utc)
    second_timestamp = datetime(
        2026,
        8,
        18,
        7,
        4,
        tzinfo=timezone(timedelta(hours=-3)),
    )

    findings = detector.detect(
        [
            create_event(0, timestamp=second_timestamp),
            create_event(0, timestamp=first_timestamp),
        ]
    )

    assert len(findings) == 1
    assert findings[0].first_observed is first_timestamp
    assert findings[0].last_observed is second_timestamp


@pytest.mark.parametrize("failure_threshold", [0, -1, True, 1.5])
def test_rejects_invalid_failure_threshold(failure_threshold: object) -> None:
    with pytest.raises(ValueError, match="failure_threshold"):
        BruteForceDetector(
            failure_threshold=failure_threshold,
            window=timedelta(minutes=5),
        )


@pytest.mark.parametrize(
    "window",
    [timedelta(0), timedelta(seconds=-1), 300],
)
def test_rejects_invalid_window(window: object) -> None:
    with pytest.raises(ValueError, match="window"):
        BruteForceDetector(failure_threshold=3, window=window)


def test_emits_once_per_continuous_episode() -> None:
    detector = BruteForceDetector(failure_threshold=3, window=timedelta(minutes=5))
    events = [create_event(minute) for minute in range(6)]

    findings = detector.detect(events)

    assert len(findings) == 1
    assert findings[0].failure_count == 3


def test_emits_again_after_gap_larger_than_window() -> None:
    detector = BruteForceDetector(failure_threshold=3, window=timedelta(minutes=5))
    events = [
        create_event(0),
        create_event(1),
        create_event(2),
        create_event(8),
        create_event(9),
        create_event(10),
    ]

    findings = detector.detect(events)

    assert len(findings) == 2


def test_finding_is_immutable_and_has_value_semantics() -> None:
    finding = BruteForceFinding(
        username="admin",
        source_ip=IPv4Address("192.0.2.25"),
        first_observed=BASE_TIMESTAMP,
        last_observed=BASE_TIMESTAMP + timedelta(minutes=2),
        failure_count=3,
    )
    equivalent_finding = BruteForceFinding(
        username="admin",
        source_ip=IPv4Address("192.0.2.25"),
        first_observed=BASE_TIMESTAMP,
        last_observed=BASE_TIMESTAMP + timedelta(minutes=2),
        failure_count=3,
    )

    assert finding == equivalent_finding
    with pytest.raises(FrozenInstanceError):
        finding.failure_count = 4


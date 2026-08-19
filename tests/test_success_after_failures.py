from dataclasses import FrozenInstanceError
from datetime import datetime, timedelta, timezone
from ipaddress import IPv4Address, IPv6Address

import pytest

from login_log_analyzer.authentication import (
    AuthenticationEvent,
    AuthenticationOutcome,
    AuthenticationPlatform,
)
from login_log_analyzer.success_after_failures import (
    SuccessfulLoginAfterFailuresDetector,
    SuccessfulLoginAfterFailuresFinding,
)


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


def create_detector(
    *,
    threshold: int = 5,
    window: timedelta = timedelta(minutes=5),
) -> SuccessfulLoginAfterFailuresDetector:
    return SuccessfulLoginAfterFailuresDetector(
        failure_threshold=threshold,
        window=window,
    )


@pytest.mark.parametrize("threshold", [0, 1, -1, True, 2.0, "2", None])
def test_rejects_invalid_failure_threshold(threshold: object) -> None:
    with pytest.raises(ValueError):
        SuccessfulLoginAfterFailuresDetector(
            failure_threshold=threshold,
            window=timedelta(minutes=5),
        )


@pytest.mark.parametrize("window", [timedelta(0), timedelta(seconds=-1), 5, None])
def test_rejects_invalid_window(window: object) -> None:
    with pytest.raises(ValueError):
        SuccessfulLoginAfterFailuresDetector(
            failure_threshold=2,
            window=window,
        )


def test_detects_exact_threshold_followed_by_success() -> None:
    events = [create_event(minute) for minute in range(5)]
    events.append(create_event(5, outcome=AuthenticationOutcome.SUCCESS))

    findings = create_detector().detect(events)

    assert findings == [
        SuccessfulLoginAfterFailuresFinding(
            username="admin",
            source_ip=IPv4Address("192.0.2.25"),
            first_failure=BASE_TIMESTAMP,
            last_failure=BASE_TIMESTAMP + timedelta(minutes=4),
            successful_login=BASE_TIMESTAMP + timedelta(minutes=5),
            failure_count=5,
            platform=AuthenticationPlatform.LINUX,
        )
    ]


def test_does_not_detect_below_threshold_followed_by_success() -> None:
    events = [create_event(minute) for minute in range(4)]
    events.append(create_event(4, outcome=AuthenticationOutcome.SUCCESS))

    assert create_detector().detect(events) == []


def test_does_not_detect_failures_without_success() -> None:
    assert create_detector().detect([create_event(minute) for minute in range(5)]) == []


def test_does_not_detect_success_before_failures() -> None:
    events = [create_event(0, outcome=AuthenticationOutcome.SUCCESS)]
    events.extend(create_event(minute) for minute in range(1, 6))

    assert create_detector().detect(events) == []


def test_window_boundary_is_inclusive() -> None:
    events = [
        create_event(0),
        create_event(4),
        create_event(5, outcome=AuthenticationOutcome.SUCCESS),
    ]

    findings = create_detector(threshold=2).detect(events)

    assert len(findings) == 1
    assert findings[0].first_failure == BASE_TIMESTAMP


def test_failure_outside_window_does_not_count() -> None:
    outside = BASE_TIMESTAMP + timedelta(minutes=5, microseconds=1)
    events = [
        create_event(0),
        create_event(4),
        create_event(0, outcome=AuthenticationOutcome.SUCCESS, timestamp=outside),
    ]

    assert create_detector(threshold=2).detect(events) == []


def test_failures_without_source_ip_are_ignored() -> None:
    events = [create_event(minute, source_ip=None) for minute in range(5)]
    events.append(
        create_event(5, source_ip=None, outcome=AuthenticationOutcome.SUCCESS)
    )

    assert create_detector().detect(events) == []


def test_success_from_different_ip_does_not_correlate() -> None:
    events = [create_event(minute) for minute in range(5)]
    events.append(
        create_event(
            5,
            source_ip=IPv4Address("192.0.2.26"),
            outcome=AuthenticationOutcome.SUCCESS,
        )
    )

    assert create_detector().detect(events) == []


def test_success_for_different_username_does_not_correlate() -> None:
    events = [create_event(minute) for minute in range(5)]
    events.append(
        create_event(5, username="Admin", outcome=AuthenticationOutcome.SUCCESS)
    )

    assert create_detector().detect(events) == []


def test_detection_is_independent_of_input_order() -> None:
    events = [create_event(minute) for minute in range(5)]
    events.append(create_event(5, outcome=AuthenticationOutcome.SUCCESS))

    assert create_detector().detect(reversed(events)) == create_detector().detect(events)


def test_failures_at_same_instant_as_success_do_not_count() -> None:
    events = [
        create_event(0, outcome=AuthenticationOutcome.SUCCESS),
        create_event(0),
        create_event(0),
    ]

    assert create_detector(threshold=2).detect(events) == []


def test_mixed_platform_failures_correlate_and_success_platform_is_preserved() -> None:
    events = [
        create_event(0, platform=AuthenticationPlatform.LINUX),
        create_event(1, platform=AuthenticationPlatform.WINDOWS),
        create_event(
            2,
            outcome=AuthenticationOutcome.SUCCESS,
            platform=AuthenticationPlatform.WINDOWS,
        ),
    ]

    finding = create_detector(threshold=2).detect(events)[0]

    assert finding.platform is AuthenticationPlatform.WINDOWS


def test_absolute_time_ordering_across_offsets() -> None:
    first = datetime.fromisoformat("2026-08-18T07:00:00-03:00")
    second = datetime.fromisoformat("2026-08-18T12:01:00+02:00")
    success = datetime.fromisoformat("2026-08-18T10:02:00+00:00")
    events = [
        create_event(0, timestamp=success, outcome=AuthenticationOutcome.SUCCESS),
        create_event(0, timestamp=second),
        create_event(0, timestamp=first),
    ]

    finding = create_detector(threshold=2).detect(events)[0]

    assert finding.first_failure is first
    assert finding.last_failure is second
    assert finding.successful_login is success


def test_qualifying_success_resets_sequence() -> None:
    events = [create_event(minute) for minute in range(5)]
    events.extend(
        [
            create_event(5, outcome=AuthenticationOutcome.SUCCESS),
            create_event(5, outcome=AuthenticationOutcome.SUCCESS),
        ]
    )

    assert len(create_detector().detect(events)) == 1


def test_non_qualifying_success_resets_sequence() -> None:
    events = [create_event(minute) for minute in range(3)]
    events.append(create_event(3, outcome=AuthenticationOutcome.SUCCESS))
    events.extend(create_event(minute) for minute in range(4, 9))
    events.append(create_event(9, outcome=AuthenticationOutcome.SUCCESS))

    findings = create_detector(window=timedelta(minutes=10)).detect(events)

    assert len(findings) == 1
    assert findings[0].first_failure == BASE_TIMESTAMP + timedelta(minutes=4)


def test_two_independent_episodes_produce_two_findings() -> None:
    events = [create_event(minute) for minute in range(5)]
    events.append(create_event(5, outcome=AuthenticationOutcome.SUCCESS))
    events.extend(create_event(minute) for minute in range(6, 11))
    events.append(create_event(11, outcome=AuthenticationOutcome.SUCCESS))

    assert len(create_detector().detect(events)) == 2


def test_finding_reports_all_qualifying_failures_above_threshold() -> None:
    events = [create_event(minute) for minute in range(6)]
    events.append(create_event(6, outcome=AuthenticationOutcome.SUCCESS))

    finding = create_detector(window=timedelta(minutes=10)).detect(events)[0]

    assert finding.failure_count == 6
    assert finding.last_failure == BASE_TIMESTAMP + timedelta(minutes=5)


def test_supports_ipv6() -> None:
    source_ip = IPv6Address("2001:db8::25")
    events = [create_event(0, source_ip=source_ip), create_event(1, source_ip=source_ip)]
    events.append(
        create_event(
            2,
            source_ip=source_ip,
            outcome=AuthenticationOutcome.SUCCESS,
        )
    )

    assert create_detector(threshold=2).detect(events)[0].source_ip == source_ip


def test_finding_is_immutable() -> None:
    finding = SuccessfulLoginAfterFailuresFinding(
        username="admin",
        source_ip=IPv4Address("192.0.2.25"),
        first_failure=BASE_TIMESTAMP,
        last_failure=BASE_TIMESTAMP,
        successful_login=BASE_TIMESTAMP,
        failure_count=2,
        platform=AuthenticationPlatform.LINUX,
    )

    with pytest.raises(FrozenInstanceError):
        finding.failure_count = 3

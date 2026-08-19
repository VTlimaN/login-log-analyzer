from dataclasses import FrozenInstanceError
from datetime import datetime, timedelta, timezone
from ipaddress import IPv4Address, IPv6Address

import pytest

from login_log_analyzer.authentication import (
    AuthenticationEvent,
    AuthenticationOutcome,
    AuthenticationPlatform,
)
from login_log_analyzer.multiple_source_ips import (
    MultipleSourceIPsDetector,
    MultipleSourceIPsFinding,
)


BASE_TIMESTAMP = datetime(2026, 8, 18, 10, 0, tzinfo=timezone.utc)


def create_event(
    minute: int,
    source_ip: IPv4Address | IPv6Address | None,
    *,
    username: str = "admin",
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
    threshold: int = 5,
    window: timedelta = timedelta(minutes=10),
) -> MultipleSourceIPsDetector:
    return MultipleSourceIPsDetector(
        source_ip_threshold=threshold,
        window=window,
    )


def ip(number: int) -> IPv4Address:
    return IPv4Address(f"192.0.2.{number}")


@pytest.mark.parametrize("threshold", [0, 1, -1, True, 2.0, "2", None])
def test_rejects_invalid_source_ip_threshold(threshold: object) -> None:
    with pytest.raises(ValueError, match="source_ip_threshold"):
        MultipleSourceIPsDetector(
            source_ip_threshold=threshold,
            window=timedelta(minutes=10),
        )


@pytest.mark.parametrize("window", [timedelta(0), timedelta(seconds=-1), 10, None])
def test_rejects_invalid_window(window: object) -> None:
    with pytest.raises(ValueError, match="window"):
        MultipleSourceIPsDetector(source_ip_threshold=2, window=window)


def test_detects_exact_distinct_source_ip_threshold() -> None:
    events = [create_event(minute, ip(minute + 1)) for minute in range(5)]

    findings = create_detector().detect(events)

    assert findings == [
        MultipleSourceIPsFinding(
            username="admin",
            first_observed=BASE_TIMESTAMP,
            last_observed=BASE_TIMESTAMP + timedelta(minutes=4),
            distinct_source_ip_count=5,
            source_ips=tuple(ip(number) for number in range(1, 6)),
        )
    ]


def test_does_not_detect_below_threshold() -> None:
    events = [create_event(minute, ip(minute + 1)) for minute in range(4)]

    assert create_detector().detect(events) == []


def test_duplicate_ip_does_not_increase_cardinality() -> None:
    events = [
        create_event(0, ip(1)),
        create_event(1, ip(1)),
        create_event(2, ip(2)),
    ]

    finding = create_detector(threshold=2).detect(events)[0]

    assert finding.distinct_source_ip_count == 2
    assert finding.source_ips == (ip(1), ip(2))


def test_repeated_same_ip_never_qualifies() -> None:
    events = [create_event(minute, ip(1)) for minute in range(20)]

    assert create_detector(threshold=2, window=timedelta(minutes=30)).detect(events) == []


def test_ipv4_and_ipv6_are_distinct_and_sorted_deterministically() -> None:
    ipv6_high = IPv6Address("2001:db8::20")
    ipv6_low = IPv6Address("2001:db8::10")
    events = [
        create_event(0, ipv6_high),
        create_event(1, ip(20)),
        create_event(2, ipv6_low),
        create_event(3, ip(10)),
    ]

    finding = create_detector(threshold=4).detect(reversed(events))[0]

    assert finding.source_ips == (ip(10), ip(20), ipv6_low, ipv6_high)


def test_ignores_missing_source_ip() -> None:
    events = [create_event(0, None), create_event(1, ip(1))]

    assert create_detector(threshold=2).detect(events) == []


def test_successes_do_not_count_or_reset_episode() -> None:
    events = [
        create_event(0, ip(1)),
        create_event(1, ip(2), outcome=AuthenticationOutcome.SUCCESS),
        create_event(2, ip(2)),
    ]

    findings = create_detector(threshold=2).detect(events)

    assert len(findings) == 1
    assert findings[0].source_ips == (ip(1), ip(2))


def test_different_usernames_are_independent() -> None:
    events = [
        create_event(0, ip(1), username="admin"),
        create_event(1, ip(2), username="Admin"),
        create_event(2, ip(3), username="admin"),
        create_event(3, ip(4), username="Admin"),
    ]

    findings = create_detector(threshold=2).detect(events)

    assert [finding.username for finding in findings] == ["admin", "Admin"]


def test_detection_is_independent_of_input_order() -> None:
    events = [create_event(minute, ip(minute + 1)) for minute in range(5)]

    assert create_detector().detect(reversed(events)) == create_detector().detect(events)


def test_window_boundary_is_inclusive() -> None:
    events = [create_event(0, ip(1)), create_event(10, ip(2))]

    assert len(create_detector(threshold=2).detect(events)) == 1


def test_events_outside_window_do_not_qualify() -> None:
    outside = BASE_TIMESTAMP + timedelta(minutes=10, microseconds=1)
    events = [
        create_event(0, ip(1)),
        create_event(0, ip(2), timestamp=outside),
    ]

    assert create_detector(threshold=2).detect(events) == []


def test_mixed_platform_events_correlate() -> None:
    events = [
        create_event(0, ip(1), platform=AuthenticationPlatform.LINUX),
        create_event(1, ip(2), platform=AuthenticationPlatform.WINDOWS),
    ]

    assert len(create_detector(threshold=2).detect(events)) == 1


def test_absolute_time_comparison_preserves_original_timestamps() -> None:
    first = datetime.fromisoformat("2026-08-18T07:00:00-03:00")
    second = datetime.fromisoformat("2026-08-18T12:05:00+02:00")
    events = [
        create_event(0, ip(2), timestamp=second),
        create_event(0, ip(1), timestamp=first),
    ]

    finding = create_detector(threshold=2).detect(events)[0]

    assert finding.first_observed is first
    assert finding.last_observed is second


def test_emits_once_per_continuous_episode() -> None:
    events = [create_event(minute, ip(minute + 1)) for minute in range(8)]

    findings = create_detector(threshold=5).detect(events)

    assert len(findings) == 1
    assert findings[0].distinct_source_ip_count == 5


def test_episode_remains_suppressed_while_consecutive_failures_stay_close() -> None:
    events = [
        create_event(0, ip(1)),
        create_event(1, ip(2)),
        create_event(10, ip(3)),
        create_event(11, ip(4)),
    ]

    assert len(create_detector(threshold=2).detect(events)) == 1


def test_emits_again_after_gap_larger_than_window() -> None:
    events = [
        create_event(0, ip(1)),
        create_event(1, ip(2)),
        create_event(12, ip(3)),
        create_event(13, ip(4)),
    ]

    findings = create_detector(threshold=2).detect(events)

    assert len(findings) == 2
    assert findings[1].source_ips == (ip(3), ip(4))


def test_finding_count_represents_distinct_ips_not_failure_count() -> None:
    events = [
        create_event(0, ip(1)),
        create_event(1, ip(1)),
        create_event(2, ip(2)),
        create_event(3, ip(2)),
        create_event(4, ip(3)),
    ]

    finding = create_detector(threshold=3).detect(events)[0]

    assert finding.distinct_source_ip_count == 3
    assert finding.source_ips == (ip(1), ip(2), ip(3))


def test_finding_is_immutable_and_has_value_semantics() -> None:
    finding = MultipleSourceIPsFinding(
        username="admin",
        first_observed=BASE_TIMESTAMP,
        last_observed=BASE_TIMESTAMP + timedelta(minutes=1),
        distinct_source_ip_count=2,
        source_ips=(ip(1), ip(2)),
    )
    equivalent = MultipleSourceIPsFinding(
        username="admin",
        first_observed=BASE_TIMESTAMP,
        last_observed=BASE_TIMESTAMP + timedelta(minutes=1),
        distinct_source_ip_count=2,
        source_ips=(ip(1), ip(2)),
    )

    assert finding == equivalent
    with pytest.raises(FrozenInstanceError):
        finding.distinct_source_ip_count = 3

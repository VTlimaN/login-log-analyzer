from dataclasses import FrozenInstanceError
from datetime import datetime, time, timedelta, timezone
from ipaddress import IPv4Address

import pytest

from login_log_analyzer.authentication import (
    AuthenticationEvent,
    AuthenticationOutcome,
    AuthenticationPlatform,
)
from login_log_analyzer.off_hours import (
    OffHoursLoginDetector,
    OffHoursLoginFinding,
)


MONDAY = datetime(2026, 8, 17, tzinfo=timezone.utc)


def create_event(
    timestamp: datetime,
    *,
    username: str = "analyst",
    source_ip: IPv4Address | None = IPv4Address("192.0.2.25"),
    outcome: AuthenticationOutcome = AuthenticationOutcome.SUCCESS,
    platform: AuthenticationPlatform = AuthenticationPlatform.LINUX,
) -> AuthenticationEvent:
    return AuthenticationEvent(
        timestamp=timestamp,
        username=username,
        outcome=outcome,
        platform=platform,
        source_ip=source_ip,
    )


def create_weekday_detector() -> OffHoursLoginDetector:
    return OffHoursLoginDetector(
        allowed_weekdays={0, 1, 2, 3, 4},
        start_time=time(8),
        end_time=time(18),
    )


def test_successful_login_inside_allowed_hours_has_no_finding() -> None:
    detector = create_weekday_detector()

    findings = detector.detect([create_event(MONDAY.replace(hour=10))])

    assert findings == []


def test_successful_login_before_allowed_start_produces_finding() -> None:
    detector = create_weekday_detector()

    findings = detector.detect([create_event(MONDAY.replace(hour=7, minute=59))])

    assert len(findings) == 1


def test_successful_login_after_allowed_end_produces_finding() -> None:
    detector = create_weekday_detector()

    findings = detector.detect([create_event(MONDAY.replace(hour=19))])

    assert len(findings) == 1


def test_start_boundary_is_inclusive() -> None:
    detector = create_weekday_detector()

    findings = detector.detect([create_event(MONDAY.replace(hour=8))])

    assert findings == []


def test_end_boundary_is_exclusive() -> None:
    detector = create_weekday_detector()

    findings = detector.detect([create_event(MONDAY.replace(hour=18))])

    assert len(findings) == 1


def test_failed_authentication_is_ignored() -> None:
    detector = create_weekday_detector()
    event = create_event(
        MONDAY.replace(hour=2),
        outcome=AuthenticationOutcome.FAILURE,
    )

    assert detector.detect([event]) == []


def test_allowed_weekday_uses_python_weekday_convention() -> None:
    detector = OffHoursLoginDetector(
        allowed_weekdays={0},
        start_time=time(8),
        end_time=time(18),
    )

    assert detector.detect([create_event(MONDAY.replace(hour=10))]) == []


def test_disallowed_weekday_produces_finding() -> None:
    detector = OffHoursLoginDetector(
        allowed_weekdays={0},
        start_time=time(8),
        end_time=time(18),
    )
    tuesday = MONDAY + timedelta(days=1, hours=10)

    assert len(detector.detect([create_event(tuesday)])) == 1


@pytest.mark.parametrize("days_after_monday", [5, 6])
def test_weekend_login_produces_finding(days_after_monday: int) -> None:
    detector = create_weekday_detector()
    weekend_timestamp = MONDAY + timedelta(days=days_after_monday, hours=10)

    assert len(detector.detect([create_event(weekend_timestamp)])) == 1


@pytest.mark.parametrize(
    "allowed_weekdays",
    [set(), {-1}, {7}, {True}, {"0"}, 0],
)
def test_rejects_invalid_weekday_configuration(allowed_weekdays: object) -> None:
    with pytest.raises(ValueError, match="allowed_weekdays"):
        OffHoursLoginDetector(
            allowed_weekdays=allowed_weekdays,
            start_time=time(8),
            end_time=time(18),
        )


def test_overnight_window_allows_time_before_midnight() -> None:
    detector = OffHoursLoginDetector(
        allowed_weekdays={0},
        start_time=time(22),
        end_time=time(6),
    )

    assert detector.detect([create_event(MONDAY.replace(hour=23))]) == []


def test_overnight_window_allows_time_after_midnight_from_previous_weekday() -> None:
    detector = OffHoursLoginDetector(
        allowed_weekdays={0},
        start_time=time(22),
        end_time=time(6),
    )
    tuesday_at_two = MONDAY + timedelta(days=1, hours=2)

    assert detector.detect([create_event(tuesday_at_two)]) == []


@pytest.mark.parametrize(
    "timestamp",
    [
        MONDAY.replace(hour=2),
        MONDAY + timedelta(days=1, hours=22),
        MONDAY + timedelta(days=1, hours=6),
    ],
)
def test_overnight_window_rejects_time_outside_start_weekday(
    timestamp: datetime,
) -> None:
    detector = OffHoursLoginDetector(
        allowed_weekdays={0},
        start_time=time(22),
        end_time=time(6),
    )

    assert len(detector.detect([create_event(timestamp)])) == 1


def test_rejects_equal_start_and_end_times() -> None:
    with pytest.raises(ValueError, match="different"):
        OffHoursLoginDetector(
            allowed_weekdays={0},
            start_time=time(8),
            end_time=time(8),
        )


@pytest.mark.parametrize(
    "platform",
    [AuthenticationPlatform.LINUX, AuthenticationPlatform.WINDOWS],
)
def test_detects_off_hours_login_from_each_platform(
    platform: AuthenticationPlatform,
) -> None:
    detector = create_weekday_detector()

    findings = detector.detect(
        [create_event(MONDAY.replace(hour=2), platform=platform)]
    )

    assert len(findings) == 1
    assert findings[0].platform is platform


@pytest.mark.parametrize(
    "source_ip",
    [IPv4Address("192.0.2.25"), None],
)
def test_finding_preserves_optional_source_ip(
    source_ip: IPv4Address | None,
) -> None:
    detector = create_weekday_detector()

    findings = detector.detect(
        [create_event(MONDAY.replace(hour=2), source_ip=source_ip)]
    )

    assert findings[0].source_ip == source_ip


def test_finding_preserves_username() -> None:
    detector = create_weekday_detector()

    findings = detector.detect(
        [create_event(MONDAY.replace(hour=2), username="DOMAIN\\ServiceAccount$")]
    )

    assert findings[0].username == "DOMAIN\\ServiceAccount$"


def test_evaluates_wall_clock_time_in_event_timezone() -> None:
    detector = OffHoursLoginDetector(
        allowed_weekdays={0},
        start_time=time(8),
        end_time=time(10),
    )
    local_timestamp = datetime(
        2026,
        8,
        17,
        9,
        tzinfo=timezone(timedelta(hours=-3)),
    )

    assert detector.detect([create_event(local_timestamp)]) == []


def test_evaluates_different_timezone_offsets_by_their_wall_clock_times() -> None:
    detector = OffHoursLoginDetector(
        allowed_weekdays={0},
        start_time=time(8),
        end_time=time(18),
    )
    inside_timestamp = datetime(
        2026,
        8,
        17,
        9,
        tzinfo=timezone(timedelta(hours=-3)),
    )
    outside_timestamp = datetime(
        2026,
        8,
        17,
        19,
        tzinfo=timezone(timedelta(hours=2)),
    )

    findings = detector.detect(
        [create_event(inside_timestamp), create_event(outside_timestamp)]
    )

    assert len(findings) == 1
    assert findings[0].timestamp is outside_timestamp


def test_findings_are_sorted_by_absolute_timestamp() -> None:
    detector = create_weekday_detector()
    earlier = MONDAY.replace(hour=2)
    later = MONDAY.replace(hour=20)

    findings = detector.detect([create_event(later), create_event(earlier)])

    assert [finding.timestamp for finding in findings] == [earlier, later]


def test_each_qualifying_event_produces_a_finding() -> None:
    detector = create_weekday_detector()
    events = [
        create_event(MONDAY.replace(hour=2)),
        create_event(MONDAY.replace(hour=3)),
    ]

    assert len(detector.detect(events)) == 2


def test_finding_is_immutable_and_has_value_semantics() -> None:
    finding = OffHoursLoginFinding(
        username="analyst",
        timestamp=MONDAY.replace(hour=2),
        source_ip=IPv4Address("192.0.2.25"),
        platform=AuthenticationPlatform.LINUX,
    )
    equivalent_finding = OffHoursLoginFinding(
        username="analyst",
        timestamp=MONDAY.replace(hour=2),
        source_ip=IPv4Address("192.0.2.25"),
        platform=AuthenticationPlatform.LINUX,
    )

    assert finding == equivalent_finding
    with pytest.raises(FrozenInstanceError):
        finding.username = "admin"


@pytest.mark.parametrize(
    ("start_time", "end_time"),
    [
        (8, time(18)),
        (time(8), 18),
        (time(8, tzinfo=timezone.utc), time(18)),
        (time(8), time(18, tzinfo=timezone.utc)),
    ],
)
def test_rejects_invalid_time_configuration(
    start_time: object,
    end_time: object,
) -> None:
    with pytest.raises(ValueError, match="time"):
        OffHoursLoginDetector(
            allowed_weekdays={0},
            start_time=start_time,
            end_time=end_time,
        )


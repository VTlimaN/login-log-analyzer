from datetime import datetime, timedelta, timezone

import pytest

from login_log_analyzer.account_lockout import AccountLockoutEvent
from login_log_analyzer.authentication import AuthenticationPlatform
from login_log_analyzer.windows_account_lockout import (
    WindowsAccountLockoutParseError,
    WindowsAccountLockoutParser,
)


TIMESTAMP = datetime(2026, 8, 19, 13, 30, tzinfo=timezone.utc)


def create_event_data(**changes: object) -> dict[str, object]:
    event_data: dict[str, object] = {
        "event_id": 4740,
        "timestamp": TIMESTAMP,
        "username": "DemoUser",
        "target_domain": "DEMO",
        "caller_computer": "WS-042",
        "recording_computer": "DC01.demo.invalid",
    }
    event_data.update(changes)
    return event_data


def test_parses_valid_4740() -> None:
    event = WindowsAccountLockoutParser().parse_event(create_event_data())

    assert event == AccountLockoutEvent(
        timestamp=TIMESTAMP,
        username="DemoUser",
        platform=AuthenticationPlatform.WINDOWS,
        target_domain="DEMO",
        caller_computer="WS-042",
        recording_computer="DC01.demo.invalid",
    )


def test_unsupported_integer_event_id_returns_none() -> None:
    assert WindowsAccountLockoutParser().parse_event({"event_id": 4625}) is None


@pytest.mark.parametrize("event_id", [None, "4740", True, 4740.0])
def test_rejects_malformed_event_id(event_id: object) -> None:
    with pytest.raises(WindowsAccountLockoutParseError, match="event_id"):
        WindowsAccountLockoutParser().parse_event(
            create_event_data(event_id=event_id)
        )


def test_rejects_non_mapping_input() -> None:
    with pytest.raises(WindowsAccountLockoutParseError, match="mapping"):
        WindowsAccountLockoutParser().parse_event(4740)


def test_rejects_missing_timestamp() -> None:
    event_data = create_event_data()
    del event_data["timestamp"]

    with pytest.raises(WindowsAccountLockoutParseError, match="timestamp"):
        WindowsAccountLockoutParser().parse_event(event_data)


def test_rejects_naive_timestamp() -> None:
    with pytest.raises(WindowsAccountLockoutParseError, match="timezone"):
        WindowsAccountLockoutParser().parse_event(
            create_event_data(timestamp=datetime(2026, 8, 19, 13, 30))
        )


def test_preserves_timestamp_offset() -> None:
    timestamp = datetime(
        2026,
        8,
        19,
        10,
        30,
        tzinfo=timezone(timedelta(hours=-3)),
    )

    event = WindowsAccountLockoutParser().parse_event(
        create_event_data(timestamp=timestamp)
    )

    assert event is not None
    assert event.timestamp is timestamp


def test_rejects_missing_username() -> None:
    event_data = create_event_data()
    del event_data["username"]

    with pytest.raises(WindowsAccountLockoutParseError, match="username"):
        WindowsAccountLockoutParser().parse_event(event_data)


def test_optional_fields_may_be_missing() -> None:
    event = WindowsAccountLockoutParser().parse_event(
        {"event_id": 4740, "timestamp": TIMESTAMP, "username": "DemoUser"}
    )

    assert event is not None
    assert event.target_domain is None
    assert event.caller_computer is None
    assert event.recording_computer is None


@pytest.mark.parametrize(
    "field_name",
    ["target_domain", "caller_computer", "recording_computer"],
)
def test_empty_optional_fields_become_none(field_name: str) -> None:
    event = WindowsAccountLockoutParser().parse_event(
        create_event_data(**{field_name: "   "})
    )

    assert event is not None
    assert getattr(event, field_name) is None


@pytest.mark.parametrize(
    "field_name",
    ["target_domain", "caller_computer", "recording_computer"],
)
def test_rejects_invalid_optional_field_type(field_name: str) -> None:
    with pytest.raises(WindowsAccountLockoutParseError, match=field_name):
        WindowsAccountLockoutParser().parse_event(
            create_event_data(**{field_name: 42})
        )


def test_preserves_nonempty_optional_fields_exactly() -> None:
    event = WindowsAccountLockoutParser().parse_event(
        create_event_data(
            target_domain=" Demo ",
            caller_computer="ws-042 ",
            recording_computer=" DC01.demo.invalid",
        )
    )

    assert event is not None
    assert event.target_domain == " Demo "
    assert event.caller_computer == "ws-042 "
    assert event.recording_computer == " DC01.demo.invalid"

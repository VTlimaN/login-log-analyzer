from dataclasses import FrozenInstanceError
from datetime import datetime, timezone

import pytest

from login_log_analyzer.account_lockout import AccountLockoutEvent
from login_log_analyzer.authentication import AuthenticationPlatform


TIMESTAMP = datetime(2026, 8, 19, 13, 30, tzinfo=timezone.utc)


def create_event(**changes: object) -> AccountLockoutEvent:
    values: dict[str, object] = {
        "timestamp": TIMESTAMP,
        "username": "DemoUser",
        "platform": AuthenticationPlatform.WINDOWS,
        "target_domain": "DEMO",
        "caller_computer": "WS-042",
        "recording_computer": "DC01.demo.invalid",
    }
    values.update(changes)
    return AccountLockoutEvent(**values)


def test_creates_immutable_account_lockout_event() -> None:
    event = create_event()

    assert event.username == "DemoUser"
    with pytest.raises(FrozenInstanceError):
        event.username = "Changed"


def test_requires_timezone_aware_timestamp() -> None:
    with pytest.raises(ValueError, match="timezone"):
        create_event(timestamp=datetime(2026, 8, 19, 13, 30))


def test_requires_datetime_timestamp() -> None:
    with pytest.raises(TypeError, match="datetime"):
        create_event(timestamp="2026-08-19T13:30:00+00:00")


def test_preserves_exact_username() -> None:
    event = create_event(username="DOMAIN\\ServiceAccount$")

    assert event.username == "DOMAIN\\ServiceAccount$"


@pytest.mark.parametrize("username", ["", "   "])
def test_rejects_empty_username(username: str) -> None:
    with pytest.raises(ValueError, match="username"):
        create_event(username=username)


def test_rejects_non_string_username() -> None:
    with pytest.raises(TypeError, match="username"):
        create_event(username=4740)


def test_requires_windows_platform() -> None:
    with pytest.raises(ValueError, match="Windows"):
        create_event(platform=AuthenticationPlatform.LINUX)


def test_rejects_invalid_platform_type() -> None:
    with pytest.raises(TypeError, match="AuthenticationPlatform"):
        create_event(platform="windows")


@pytest.mark.parametrize(
    "field_name",
    ["target_domain", "caller_computer", "recording_computer"],
)
def test_allows_missing_optional_context(field_name: str) -> None:
    event = create_event(**{field_name: None})

    assert getattr(event, field_name) is None


@pytest.mark.parametrize(
    "field_name",
    ["target_domain", "caller_computer", "recording_computer"],
)
def test_rejects_invalid_optional_context_type(field_name: str) -> None:
    with pytest.raises(TypeError, match=field_name):
        create_event(**{field_name: 42})


@pytest.mark.parametrize(
    "field_name",
    ["target_domain", "caller_computer", "recording_computer"],
)
def test_rejects_empty_optional_context(field_name: str) -> None:
    with pytest.raises(ValueError, match=field_name):
        create_event(**{field_name: "   "})

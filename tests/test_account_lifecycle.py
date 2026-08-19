from dataclasses import FrozenInstanceError
from datetime import datetime

import pytest

from login_log_analyzer.account_lifecycle import (
    AccountLifecycleAction,
    AccountLifecycleEvent,
)
from login_log_analyzer.authentication import AuthenticationPlatform


TIMESTAMP = datetime.fromisoformat("2026-08-19T14:00:00-03:00")


def create_event(**changes: object) -> AccountLifecycleEvent:
    values: dict[str, object] = {
        "timestamp": TIMESTAMP,
        "username": "LifecycleUser",
        "action": AccountLifecycleAction.CREATED,
        "platform": AuthenticationPlatform.WINDOWS,
    }
    values.update(changes)
    return AccountLifecycleEvent(**values)


def test_action_values_are_stable() -> None:
    assert [action.value for action in AccountLifecycleAction] == [
        "created",
        "enabled",
        "disabled",
        "deleted",
        "unlocked",
    ]


def test_event_is_immutable() -> None:
    event = create_event()

    with pytest.raises(FrozenInstanceError):
        event.username = "Changed"


def test_preserves_exact_values_and_optional_context() -> None:
    event = create_event(
        username="  ExactUser  ",
        target_domain="LAB",
        subject_username="Administrator",
        subject_domain="LAB",
        recording_computer="DC01.lab.invalid",
    )

    assert event.username == "  ExactUser  "
    assert event.target_domain == "LAB"
    assert event.subject_username == "Administrator"
    assert event.subject_domain == "LAB"
    assert event.recording_computer == "DC01.lab.invalid"


@pytest.mark.parametrize("timestamp", ["2026-08-19", None, 1])
def test_requires_datetime(timestamp: object) -> None:
    with pytest.raises(TypeError, match="datetime"):
        create_event(timestamp=timestamp)


def test_rejects_naive_timestamp() -> None:
    with pytest.raises(ValueError, match="timezone"):
        create_event(timestamp=datetime(2026, 8, 19, 14, 0))


@pytest.mark.parametrize("username", [None, 1])
def test_requires_string_username(username: object) -> None:
    with pytest.raises(TypeError, match="username"):
        create_event(username=username)


@pytest.mark.parametrize("username", ["", "   "])
def test_rejects_empty_username(username: str) -> None:
    with pytest.raises(ValueError, match="username"):
        create_event(username=username)


@pytest.mark.parametrize("action", ["created", None, 4720])
def test_requires_action_enum(action: object) -> None:
    with pytest.raises(TypeError, match="AccountLifecycleAction"):
        create_event(action=action)


def test_requires_platform_enum() -> None:
    with pytest.raises(TypeError, match="AuthenticationPlatform"):
        create_event(platform="windows")


def test_requires_windows_platform() -> None:
    with pytest.raises(ValueError, match="Windows"):
        create_event(platform=AuthenticationPlatform.LINUX)


@pytest.mark.parametrize(
    "field_name",
    ["target_domain", "subject_username", "subject_domain", "recording_computer"],
)
def test_optional_context_accepts_none(field_name: str) -> None:
    assert getattr(create_event(**{field_name: None}), field_name) is None


@pytest.mark.parametrize(
    "field_name",
    ["target_domain", "subject_username", "subject_domain", "recording_computer"],
)
def test_optional_context_rejects_invalid_type(field_name: str) -> None:
    with pytest.raises(TypeError, match=field_name):
        create_event(**{field_name: 1})


@pytest.mark.parametrize(
    "field_name",
    ["target_domain", "subject_username", "subject_domain", "recording_computer"],
)
def test_optional_context_rejects_whitespace(field_name: str) -> None:
    with pytest.raises(ValueError, match=field_name):
        create_event(**{field_name: "  "})

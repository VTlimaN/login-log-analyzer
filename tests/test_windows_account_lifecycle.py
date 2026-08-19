from datetime import datetime

import pytest

from login_log_analyzer.account_lifecycle import AccountLifecycleAction
from login_log_analyzer.authentication import AuthenticationPlatform
from login_log_analyzer.windows_account_lifecycle import (
    WindowsAccountLifecycleParseError,
    WindowsAccountLifecycleParser,
)


TIMESTAMP = datetime.fromisoformat("2026-08-19T14:00:00-03:00")


def create_record(**changes: object) -> dict[str, object]:
    record: dict[str, object] = {
        "event_id": 4720,
        "timestamp": TIMESTAMP,
        "username": "LifecycleUser",
    }
    record.update(changes)
    return record


@pytest.mark.parametrize(
    ("event_id", "action"),
    [
        (4720, AccountLifecycleAction.CREATED),
        (4722, AccountLifecycleAction.ENABLED),
        (4725, AccountLifecycleAction.DISABLED),
        (4726, AccountLifecycleAction.DELETED),
        (4767, AccountLifecycleAction.UNLOCKED),
    ],
)
def test_maps_supported_event_ids(
    event_id: int,
    action: AccountLifecycleAction,
) -> None:
    event = WindowsAccountLifecycleParser().parse_event(
        create_record(event_id=event_id)
    )

    assert event is not None
    assert event.action is action
    assert event.platform is AuthenticationPlatform.WINDOWS


@pytest.mark.parametrize("event_id", [4624, 4625, 4723, 4724, 4738, 4740, 9999])
def test_unsupported_integer_returns_none(event_id: int) -> None:
    assert (
        WindowsAccountLifecycleParser().parse_event(
            create_record(event_id=event_id)
        )
        is None
    )


@pytest.mark.parametrize("event_id", [True, False, "4720", 4720.0, None])
def test_rejects_invalid_event_id(event_id: object) -> None:
    with pytest.raises(WindowsAccountLifecycleParseError, match="integer"):
        WindowsAccountLifecycleParser().parse_event(
            create_record(event_id=event_id)
        )


def test_rejects_non_mapping() -> None:
    with pytest.raises(WindowsAccountLifecycleParseError, match="mapping"):
        WindowsAccountLifecycleParser().parse_event([])


@pytest.mark.parametrize(
    ("changes", "message"),
    [
        ({"timestamp": None}, "datetime"),
        ({"username": None}, "username"),
        ({"username": "   "}, "username"),
        ({"subject_username": 1}, "subject_username"),
    ],
)
def test_malformed_supported_event_raises_dedicated_error(
    changes: dict[str, object],
    message: str,
) -> None:
    with pytest.raises(WindowsAccountLifecycleParseError, match=message):
        WindowsAccountLifecycleParser().parse_event(create_record(**changes))


def test_preserves_optional_context() -> None:
    event = WindowsAccountLifecycleParser().parse_event(
        create_record(
            target_domain="LAB",
            subject_username="Administrator",
            subject_domain="LAB",
            recording_computer="DC01.lab.invalid",
        )
    )

    assert event is not None
    assert event.username == "LifecycleUser"
    assert event.target_domain == "LAB"
    assert event.subject_username == "Administrator"
    assert event.subject_domain == "LAB"
    assert event.recording_computer == "DC01.lab.invalid"


def test_missing_and_blank_optional_context_becomes_none() -> None:
    event = WindowsAccountLifecycleParser().parse_event(
        create_record(target_domain="", subject_username="   ")
    )

    assert event is not None
    assert event.target_domain is None
    assert event.subject_username is None
    assert event.subject_domain is None
    assert event.recording_computer is None

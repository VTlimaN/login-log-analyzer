from dataclasses import FrozenInstanceError
from datetime import datetime, timedelta, timezone
from ipaddress import IPv4Address, IPv6Address

import pytest

from login_log_analyzer.authentication import (
    AuthenticationEvent,
    AuthenticationOutcome,
    AuthenticationPlatform,
)


TIMESTAMP = datetime(2026, 8, 18, 3, 21, 44, tzinfo=timezone.utc)


def create_event(**changes: object) -> AuthenticationEvent:
    values = {
        "timestamp": TIMESTAMP,
        "username": "admin",
        "outcome": AuthenticationOutcome.FAILURE,
        "platform": AuthenticationPlatform.LINUX,
        "source_ip": IPv4Address("192.168.1.50"),
    }
    values.update(changes)
    return AuthenticationEvent(**values)


def test_authentication_event_stores_normalized_values() -> None:
    event = create_event()

    assert event.timestamp == TIMESTAMP
    assert event.username == "admin"
    assert event.outcome is AuthenticationOutcome.FAILURE
    assert event.platform is AuthenticationPlatform.LINUX
    assert event.source_ip == IPv4Address("192.168.1.50")


def test_authentication_event_accepts_missing_source_ip() -> None:
    event = create_event(source_ip=None)

    assert event.source_ip is None


@pytest.mark.parametrize(
    "source_ip",
    [IPv4Address("192.168.1.50"), IPv6Address("2001:db8::50")],
)
def test_authentication_event_accepts_ip_address_types(
    source_ip: IPv4Address | IPv6Address,
) -> None:
    event = create_event(source_ip=source_ip)

    assert event.source_ip == source_ip


def test_authentication_outcomes_are_closed_to_supported_values() -> None:
    assert set(AuthenticationOutcome) == {
        AuthenticationOutcome.SUCCESS,
        AuthenticationOutcome.FAILURE,
    }


def test_authentication_platforms_are_closed_to_supported_values() -> None:
    assert set(AuthenticationPlatform) == {
        AuthenticationPlatform.LINUX,
        AuthenticationPlatform.WINDOWS,
    }


def test_authentication_event_accepts_timezone_offset() -> None:
    timestamp = datetime(
        2026,
        8,
        18,
        3,
        21,
        44,
        tzinfo=timezone(timedelta(hours=-3)),
    )

    event = create_event(timestamp=timestamp)

    assert event.timestamp == timestamp


def test_authentication_event_rejects_naive_timestamp() -> None:
    timestamp = datetime(2026, 8, 18, 3, 21, 44)

    with pytest.raises(ValueError, match="timezone"):
        create_event(timestamp=timestamp)


def test_authentication_event_rejects_non_datetime_timestamp() -> None:
    with pytest.raises(TypeError, match="datetime"):
        create_event(timestamp="2026-08-18T03:21:44Z")


@pytest.mark.parametrize("username", ["", "   "])
def test_authentication_event_rejects_empty_username(username: str) -> None:
    with pytest.raises(ValueError, match="must not be empty"):
        create_event(username=username)


def test_authentication_event_rejects_non_string_username() -> None:
    with pytest.raises(TypeError, match="string"):
        create_event(username=42)


def test_authentication_event_rejects_untyped_outcome() -> None:
    with pytest.raises(TypeError, match="AuthenticationOutcome"):
        create_event(outcome="failure")


def test_authentication_event_rejects_untyped_platform() -> None:
    with pytest.raises(TypeError, match="AuthenticationPlatform"):
        create_event(platform="linux")


def test_authentication_event_rejects_string_source_ip() -> None:
    with pytest.raises(TypeError, match="IPv4Address"):
        create_event(source_ip="192.168.1.50")


def test_authentication_event_is_immutable() -> None:
    event = create_event()

    with pytest.raises(FrozenInstanceError):
        event.username = "root"


def test_authentication_event_has_value_equality() -> None:
    first_event = create_event()
    equivalent_event = create_event()
    successful_event = create_event(outcome=AuthenticationOutcome.SUCCESS)

    assert first_event == equivalent_event
    assert first_event != successful_event


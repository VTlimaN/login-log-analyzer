from datetime import datetime, timedelta, timezone
from ipaddress import IPv4Address, IPv6Address

import pytest

from login_log_analyzer.authentication import (
    AuthenticationEvent,
    AuthenticationOutcome,
    AuthenticationPlatform,
)
from login_log_analyzer.windows_authentication import (
    WindowsAuthenticationParseError,
    WindowsAuthenticationParser,
)


TIMESTAMP = datetime(2026, 8, 18, 12, 15, 30, tzinfo=timezone.utc)


def create_event_data(**changes: object) -> dict[str, object]:
    event_data: dict[str, object] = {
        "event_id": 4624,
        "timestamp": TIMESTAMP,
        "username": "analyst",
        "source_ip": "192.0.2.25",
    }
    event_data.update(changes)
    return event_data


def test_parse_4624_successful_logon() -> None:
    parser = WindowsAuthenticationParser()

    event = parser.parse_event(create_event_data())

    assert event is not None
    assert event.timestamp == TIMESTAMP
    assert event.username == "analyst"
    assert event.outcome is AuthenticationOutcome.SUCCESS
    assert event.platform is AuthenticationPlatform.WINDOWS
    assert event.source_ip == IPv4Address("192.0.2.25")


def test_parse_4625_failed_logon() -> None:
    parser = WindowsAuthenticationParser()

    event = parser.parse_event(create_event_data(event_id=4625))

    assert event is not None
    assert event.outcome is AuthenticationOutcome.FAILURE
    assert event.platform is AuthenticationPlatform.WINDOWS


def test_parse_preserves_timezone_aware_timestamp() -> None:
    parser = WindowsAuthenticationParser()
    timestamp = datetime(
        2026,
        8,
        18,
        9,
        15,
        30,
        tzinfo=timezone(timedelta(hours=-3)),
    )

    event = parser.parse_event(create_event_data(timestamp=timestamp))

    assert event is not None
    assert event.timestamp is timestamp
    assert event.timestamp.utcoffset() == timedelta(hours=-3)


def test_parse_rejects_naive_timestamp() -> None:
    parser = WindowsAuthenticationParser()

    with pytest.raises(WindowsAuthenticationParseError, match="timezone"):
        parser.parse_event(
            create_event_data(timestamp=datetime(2026, 8, 18, 12, 15, 30))
        )


def test_parse_preserves_username() -> None:
    parser = WindowsAuthenticationParser()

    event = parser.parse_event(create_event_data(username="DOMAIN\\ServiceAccount$"))

    assert event is not None
    assert event.username == "DOMAIN\\ServiceAccount$"


@pytest.mark.parametrize(
    ("source_ip", "expected_ip"),
    [
        ("198.51.100.25", IPv4Address("198.51.100.25")),
        ("2001:db8::25", IPv6Address("2001:db8::25")),
    ],
)
def test_parse_source_ip(
    source_ip: str,
    expected_ip: IPv4Address | IPv6Address,
) -> None:
    parser = WindowsAuthenticationParser()

    event = parser.parse_event(create_event_data(source_ip=source_ip))

    assert event is not None
    assert event.source_ip == expected_ip


@pytest.mark.parametrize("source_ip", [None, "", "-"])
def test_parse_event_without_meaningful_source_ip(source_ip: object) -> None:
    parser = WindowsAuthenticationParser()

    event = parser.parse_event(create_event_data(source_ip=source_ip))

    assert event is not None
    assert event.source_ip is None


def test_parse_event_with_missing_source_ip() -> None:
    parser = WindowsAuthenticationParser()
    event_data = create_event_data()
    del event_data["source_ip"]

    event = parser.parse_event(event_data)

    assert event is not None
    assert event.source_ip is None


def test_parse_unsupported_event_id_returns_none() -> None:
    parser = WindowsAuthenticationParser()

    event = parser.parse_event({"event_id": 4634})

    assert event is None


def test_parse_rejects_missing_username() -> None:
    parser = WindowsAuthenticationParser()
    event_data = create_event_data()
    del event_data["username"]

    with pytest.raises(WindowsAuthenticationParseError, match="username"):
        parser.parse_event(event_data)


def test_parse_rejects_invalid_source_ip() -> None:
    parser = WindowsAuthenticationParser()

    with pytest.raises(WindowsAuthenticationParseError, match="source IP"):
        parser.parse_event(create_event_data(source_ip="999.999.999.999"))


def test_parse_rejects_missing_timestamp() -> None:
    parser = WindowsAuthenticationParser()
    event_data = create_event_data()
    del event_data["timestamp"]

    with pytest.raises(WindowsAuthenticationParseError, match="timestamp"):
        parser.parse_event(event_data)


@pytest.mark.parametrize("event_id", ["4624", None, True])
def test_parse_rejects_malformed_event_id(event_id: object) -> None:
    parser = WindowsAuthenticationParser()

    with pytest.raises(WindowsAuthenticationParseError, match="event_id"):
        parser.parse_event(create_event_data(event_id=event_id))


def test_parse_rejects_non_mapping_input() -> None:
    parser = WindowsAuthenticationParser()

    with pytest.raises(WindowsAuthenticationParseError, match="mapping"):
        parser.parse_event(4624)


def test_parse_produces_equivalent_normalized_values() -> None:
    parser = WindowsAuthenticationParser()
    expected_event = AuthenticationEvent(
        timestamp=TIMESTAMP,
        username="analyst",
        outcome=AuthenticationOutcome.SUCCESS,
        platform=AuthenticationPlatform.WINDOWS,
        source_ip=IPv4Address("192.0.2.25"),
    )

    event = parser.parse_event(create_event_data())

    assert event == expected_event


from datetime import datetime, timedelta, timezone, tzinfo
from ipaddress import IPv4Address, IPv6Address

import pytest

from login_log_analyzer.authentication import (
    AuthenticationOutcome,
    AuthenticationPlatform,
)
from login_log_analyzer.linux_authentication import (
    LinuxAuthenticationParseError,
    LinuxAuthenticationParser,
)


TIMEZONE = timezone(timedelta(hours=-3))


def test_parse_accepted_password_authentication() -> None:
    parser = LinuxAuthenticationParser(year=2026, timezone_info=TIMEZONE)

    event = parser.parse_line(
        "Aug 18 09:12:10 server sshd[872]: "
        "Accepted password for sasser from 10.0.0.25 port 49820 ssh2"
    )

    assert event is not None
    assert event.timestamp == datetime(2026, 8, 18, 9, 12, 10, tzinfo=TIMEZONE)
    assert event.username == "sasser"
    assert event.outcome is AuthenticationOutcome.SUCCESS
    assert event.platform is AuthenticationPlatform.LINUX
    assert event.source_ip == IPv4Address("10.0.0.25")


def test_parse_failed_password_authentication() -> None:
    parser = LinuxAuthenticationParser(year=2026, timezone_info=TIMEZONE)

    event = parser.parse_line(
        "Aug 18 03:21:44 server sshd[1922]: "
        "Failed password for admin from 192.168.1.50 port 55231 ssh2"
    )

    assert event is not None
    assert event.username == "admin"
    assert event.outcome is AuthenticationOutcome.FAILURE
    assert event.source_ip == IPv4Address("192.168.1.50")


def test_parse_failed_password_for_invalid_user() -> None:
    parser = LinuxAuthenticationParser(year=2026, timezone_info=TIMEZONE)

    event = parser.parse_line(
        "Aug 18 03:22:01 server sshd[1922]: "
        "Failed password for invalid user attacker "
        "from 192.168.1.50 port 55240 ssh2"
    )

    assert event is not None
    assert event.username == "attacker"
    assert event.outcome is AuthenticationOutcome.FAILURE


def test_parse_ipv6_source_address() -> None:
    parser = LinuxAuthenticationParser(year=2026, timezone_info=TIMEZONE)

    event = parser.parse_line(
        "Aug 18 09:12:10 server sshd[872]: "
        "Accepted password for analyst from 2001:db8::25 port 49820 ssh2"
    )

    assert event is not None
    assert event.source_ip == IPv6Address("2001:db8::25")


def test_parse_preserves_supplied_timezone() -> None:
    parser = LinuxAuthenticationParser(year=2026, timezone_info=TIMEZONE)

    event = parser.parse_line(
        "Aug 18 09:12:10 server sshd[872]: "
        "Accepted password for analyst from 192.0.2.25 port 49820 ssh2"
    )

    assert event is not None
    assert event.timestamp.tzinfo is TIMEZONE
    assert event.timestamp.utcoffset() == timedelta(hours=-3)


def test_parse_uses_explicit_year() -> None:
    parser = LinuxAuthenticationParser(year=2040, timezone_info=timezone.utc)

    event = parser.parse_line(
        "Jan  1 00:00:01 host sshd[1]: "
        "Failed password for root from 192.0.2.10 port 10000 ssh2"
    )

    assert event is not None
    assert event.timestamp.year == 2040


@pytest.mark.parametrize(
    ("timestamp_text", "expected_timestamp"),
    [
        ("Jan  1 00:00:01", datetime(2026, 1, 1, 0, 0, 1, tzinfo=TIMEZONE)),
        ("Feb 28 12:30:45", datetime(2026, 2, 28, 12, 30, 45, tzinfo=TIMEZONE)),
        ("Dec 31 23:59:59", datetime(2026, 12, 31, 23, 59, 59, tzinfo=TIMEZONE)),
    ],
)
def test_parse_valid_syslog_timestamps(
    timestamp_text: str,
    expected_timestamp: datetime,
) -> None:
    parser = LinuxAuthenticationParser(year=2026, timezone_info=TIMEZONE)

    event = parser.parse_line(
        f"{timestamp_text} host sshd[42]: "
        "Failed password for root from 192.0.2.10 port 10000 ssh2"
    )

    assert event is not None
    assert event.timestamp == expected_timestamp


def test_parse_preserves_username_case() -> None:
    parser = LinuxAuthenticationParser(year=2026, timezone_info=TIMEZONE)

    event = parser.parse_line(
        "Aug 18 09:12:10 server sshd[872]: "
        "Accepted password for SecurityAdmin from 192.0.2.25 port 49820 ssh2"
    )

    assert event is not None
    assert event.username == "SecurityAdmin"


def test_parse_unsupported_non_ssh_line_returns_none() -> None:
    parser = LinuxAuthenticationParser(year=2026, timezone_info=TIMEZONE)

    event = parser.parse_line(
        "Aug 18 09:15:00 server sudo: analyst : TTY=pts/0 ; COMMAND=/usr/bin/id"
    )

    assert event is None


def test_parse_unsupported_ssh_line_returns_none() -> None:
    parser = LinuxAuthenticationParser(year=2026, timezone_info=TIMEZONE)

    event = parser.parse_line(
        "Aug 18 09:15:00 server sshd[872]: "
        "Disconnected from user analyst 192.0.2.25 port 49820"
    )

    assert event is None


def test_parse_unsupported_public_key_authentication_returns_none() -> None:
    parser = LinuxAuthenticationParser(year=2026, timezone_info=TIMEZONE)

    event = parser.parse_line(
        "Aug 18 09:12:10 server sshd[872]: "
        "Accepted publickey for analyst from 192.0.2.25 port 49820 ssh2"
    )

    assert event is None


def test_parse_malformed_timestamp_raises_parse_error() -> None:
    parser = LinuxAuthenticationParser(year=2026, timezone_info=TIMEZONE)

    with pytest.raises(LinuxAuthenticationParseError, match="timestamp"):
        parser.parse_line(
            "Feb 30 09:12:10 server sshd[872]: "
            "Accepted password for analyst from 192.0.2.25 port 49820 ssh2"
        )


def test_parse_invalid_source_ip_raises_parse_error() -> None:
    parser = LinuxAuthenticationParser(year=2026, timezone_info=TIMEZONE)

    with pytest.raises(LinuxAuthenticationParseError, match="source IP"):
        parser.parse_line(
            "Aug 18 09:12:10 server sshd[872]: "
            "Accepted password for analyst from 999.999.999.999 port 49820 ssh2"
        )


def test_parse_malformed_supported_message_raises_parse_error() -> None:
    parser = LinuxAuthenticationParser(year=2026, timezone_info=TIMEZONE)

    with pytest.raises(LinuxAuthenticationParseError, match="message"):
        parser.parse_line(
            "Aug 18 09:12:10 server sshd[872]: "
            "Failed password for analyst 192.0.2.25 port 49820 ssh2"
        )


def test_parser_rejects_timezone_without_utc_offset() -> None:
    class MissingOffsetTimezone(tzinfo):
        def utcoffset(self, value: datetime) -> None:
            return None

    with pytest.raises(ValueError, match="UTC offset"):
        LinuxAuthenticationParser(
            year=2026,
            timezone_info=MissingOffsetTimezone(),
        )

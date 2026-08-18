import re
from datetime import datetime, tzinfo
from ipaddress import ip_address

from login_log_analyzer.authentication import (
    AuthenticationEvent,
    AuthenticationOutcome,
    AuthenticationPlatform,
)


SYSLOG_SSH_PATTERN = re.compile(
    r"^(?P<month>[A-Z][a-z]{2})\s+"
    r"(?P<day>\d{1,2}) "
    r"(?P<time>\d{2}:\d{2}:\d{2}) "
    r"(?P<hostname>\S+) "
    r"sshd\[\d+\]: "
    r"(?P<message>.+)$"
)
ACCEPTED_PASSWORD_PATTERN = re.compile(
    r"^Accepted password for (?P<username>\S+) "
    r"from (?P<source_ip>\S+) port \d+ ssh2$"
)
FAILED_PASSWORD_PATTERN = re.compile(
    r"^Failed password for (?P<username>\S+) "
    r"from (?P<source_ip>\S+) port \d+ ssh2$"
)
FAILED_INVALID_USER_PATTERN = re.compile(
    r"^Failed password for invalid user (?P<username>\S+) "
    r"from (?P<source_ip>\S+) port \d+ ssh2$"
)
SUPPORTED_AUTHENTICATION_MARKER = re.compile(
    r"sshd(?:\[[^]]*\])?:\s+(?:Accepted|Failed) password\b"
)
MONTH_NUMBERS = {
    "Jan": 1,
    "Feb": 2,
    "Mar": 3,
    "Apr": 4,
    "May": 5,
    "Jun": 6,
    "Jul": 7,
    "Aug": 8,
    "Sep": 9,
    "Oct": 10,
    "Nov": 11,
    "Dec": 12,
}


class LinuxAuthenticationParseError(ValueError):
    pass


class LinuxAuthenticationParser:
    def __init__(self, year: int, timezone_info: tzinfo) -> None:
        if not isinstance(year, int) or isinstance(year, bool) or not 1 <= year <= 9999:
            raise ValueError("year must be an integer between 1 and 9999")
        if not isinstance(timezone_info, tzinfo):
            raise TypeError("timezone_info must be a tzinfo instance")
        reference_timestamp = datetime(year, 1, 1, tzinfo=timezone_info)
        if reference_timestamp.utcoffset() is None:
            raise ValueError("timezone_info must provide a UTC offset")

        self._year = year
        self._timezone = timezone_info

    def parse_line(self, line: str) -> AuthenticationEvent | None:
        if not isinstance(line, str):
            raise TypeError("line must be a string")

        line_match = SYSLOG_SSH_PATTERN.fullmatch(line)
        if line_match is None:
            if SUPPORTED_AUTHENTICATION_MARKER.search(line):
                raise LinuxAuthenticationParseError(
                    "malformed Linux SSH authentication log line"
                )
            return None

        message = line_match.group("message")
        accepted_message_match = ACCEPTED_PASSWORD_PATTERN.fullmatch(message)
        if accepted_message_match is not None:
            message_match = accepted_message_match
            outcome = AuthenticationOutcome.SUCCESS
        else:
            message_match = FAILED_INVALID_USER_PATTERN.fullmatch(message)
            if message_match is None:
                message_match = FAILED_PASSWORD_PATTERN.fullmatch(message)
            outcome = AuthenticationOutcome.FAILURE

        if message_match is None:
            if message.startswith(("Accepted password", "Failed password")):
                raise LinuxAuthenticationParseError(
                    "malformed Linux SSH password authentication message"
                )
            return None

        timestamp = self._parse_timestamp(
            line_match.group("month"),
            line_match.group("day"),
            line_match.group("time"),
        )

        try:
            source_ip = ip_address(message_match.group("source_ip"))
        except ValueError as error:
            raise LinuxAuthenticationParseError(
                "invalid source IP in Linux SSH authentication message"
            ) from error

        return AuthenticationEvent(
            timestamp=timestamp,
            username=message_match.group("username"),
            outcome=outcome,
            platform=AuthenticationPlatform.LINUX,
            source_ip=source_ip,
        )

    def _parse_timestamp(self, month: str, day: str, time: str) -> datetime:
        try:
            hour, minute, second = (int(part) for part in time.split(":"))
            return datetime(
                self._year,
                MONTH_NUMBERS[month],
                int(day),
                hour,
                minute,
                second,
                tzinfo=self._timezone,
            )
        except (KeyError, ValueError) as error:
            raise LinuxAuthenticationParseError(
                "invalid timestamp in Linux SSH authentication log line"
            ) from error

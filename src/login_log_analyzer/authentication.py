from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from ipaddress import IPv4Address, IPv6Address


class AuthenticationPlatform(Enum):
    LINUX = "linux"
    WINDOWS = "windows"


class AuthenticationOutcome(Enum):
    SUCCESS = "success"
    FAILURE = "failure"


@dataclass(frozen=True, slots=True)
class AuthenticationEvent:
    timestamp: datetime
    username: str
    outcome: AuthenticationOutcome
    platform: AuthenticationPlatform
    source_ip: IPv4Address | IPv6Address | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.timestamp, datetime):
            raise TypeError("timestamp must be a datetime")
        if self.timestamp.tzinfo is None or self.timestamp.utcoffset() is None:
            raise ValueError("timestamp must include timezone information")
        if not isinstance(self.username, str):
            raise TypeError("username must be a string")
        if not self.username.strip():
            raise ValueError("username must not be empty")
        if not isinstance(self.outcome, AuthenticationOutcome):
            raise TypeError("outcome must be an AuthenticationOutcome")
        if not isinstance(self.platform, AuthenticationPlatform):
            raise TypeError("platform must be an AuthenticationPlatform")
        if self.source_ip is not None and not isinstance(
            self.source_ip, (IPv4Address, IPv6Address)
        ):
            raise TypeError("source_ip must be an IPv4Address, IPv6Address, or None")


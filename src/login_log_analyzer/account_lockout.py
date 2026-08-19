from dataclasses import dataclass
from datetime import datetime

from login_log_analyzer.authentication import AuthenticationPlatform


@dataclass(frozen=True, slots=True)
class AccountLockoutEvent:
    timestamp: datetime
    username: str
    platform: AuthenticationPlatform
    target_domain: str | None = None
    caller_computer: str | None = None
    recording_computer: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.timestamp, datetime):
            raise TypeError("timestamp must be a datetime")
        if self.timestamp.tzinfo is None or self.timestamp.utcoffset() is None:
            raise ValueError("timestamp must include timezone information")
        if not isinstance(self.username, str):
            raise TypeError("username must be a string")
        if not self.username.strip():
            raise ValueError("username must not be empty")
        if not isinstance(self.platform, AuthenticationPlatform):
            raise TypeError("platform must be an AuthenticationPlatform")
        if self.platform is not AuthenticationPlatform.WINDOWS:
            raise ValueError("platform must be Windows")

        for field_name in (
            "target_domain",
            "caller_computer",
            "recording_computer",
        ):
            value = getattr(self, field_name)
            if value is not None and not isinstance(value, str):
                raise TypeError(f"{field_name} must be a string or None")
            if isinstance(value, str) and not value.strip():
                raise ValueError(f"{field_name} must not be empty")

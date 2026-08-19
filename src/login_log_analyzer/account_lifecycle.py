from dataclasses import dataclass
from datetime import datetime
from enum import Enum

from login_log_analyzer.authentication import AuthenticationPlatform


class AccountLifecycleAction(Enum):
    CREATED = "created"
    ENABLED = "enabled"
    DISABLED = "disabled"
    DELETED = "deleted"
    UNLOCKED = "unlocked"


@dataclass(frozen=True, slots=True)
class AccountLifecycleEvent:
    timestamp: datetime
    username: str
    action: AccountLifecycleAction
    platform: AuthenticationPlatform
    target_domain: str | None = None
    subject_username: str | None = None
    subject_domain: str | None = None
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
        if not isinstance(self.action, AccountLifecycleAction):
            raise TypeError("action must be an AccountLifecycleAction")
        if not isinstance(self.platform, AuthenticationPlatform):
            raise TypeError("platform must be an AuthenticationPlatform")
        if self.platform is not AuthenticationPlatform.WINDOWS:
            raise ValueError("platform must be Windows")

        for field_name in (
            "target_domain",
            "subject_username",
            "subject_domain",
            "recording_computer",
        ):
            value = getattr(self, field_name)
            if value is not None and not isinstance(value, str):
                raise TypeError(f"{field_name} must be a string or None")
            if isinstance(value, str) and not value.strip():
                raise ValueError(f"{field_name} must not be empty")

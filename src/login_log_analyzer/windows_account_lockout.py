from collections.abc import Mapping

from login_log_analyzer.account_lockout import AccountLockoutEvent
from login_log_analyzer.authentication import AuthenticationPlatform


WINDOWS_ACCOUNT_LOCKOUT_EVENT_ID = 4740


class WindowsAccountLockoutParseError(ValueError):
    pass


class WindowsAccountLockoutParser:
    def parse_event(
        self,
        event_data: Mapping[str, object],
    ) -> AccountLockoutEvent | None:
        if not isinstance(event_data, Mapping):
            raise WindowsAccountLockoutParseError("event_data must be a mapping")

        event_id = event_data.get("event_id")
        if not isinstance(event_id, int) or isinstance(event_id, bool):
            raise WindowsAccountLockoutParseError("event_id must be an integer")
        if event_id != WINDOWS_ACCOUNT_LOCKOUT_EVENT_ID:
            return None

        try:
            return AccountLockoutEvent(
                timestamp=event_data.get("timestamp"),
                username=event_data.get("username"),
                platform=AuthenticationPlatform.WINDOWS,
                target_domain=self._optional_string(
                    event_data.get("target_domain"),
                    "target_domain",
                ),
                caller_computer=self._optional_string(
                    event_data.get("caller_computer"),
                    "caller_computer",
                ),
                recording_computer=self._optional_string(
                    event_data.get("recording_computer"),
                    "recording_computer",
                ),
            )
        except (TypeError, ValueError) as error:
            raise WindowsAccountLockoutParseError(str(error)) from error

    @staticmethod
    def _optional_string(value: object, field_name: str) -> str | None:
        if value is None:
            return None
        if not isinstance(value, str):
            raise WindowsAccountLockoutParseError(
                f"{field_name} must be a string or None"
            )
        if not value.strip():
            return None
        return value

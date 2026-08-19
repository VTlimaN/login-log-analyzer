from collections.abc import Mapping

from login_log_analyzer.account_lifecycle import (
    AccountLifecycleAction,
    AccountLifecycleEvent,
)
from login_log_analyzer.authentication import AuthenticationPlatform


WINDOWS_ACCOUNT_LIFECYCLE_ACTIONS = {
    4720: AccountLifecycleAction.CREATED,
    4722: AccountLifecycleAction.ENABLED,
    4725: AccountLifecycleAction.DISABLED,
    4726: AccountLifecycleAction.DELETED,
    4767: AccountLifecycleAction.UNLOCKED,
}


class WindowsAccountLifecycleParseError(ValueError):
    pass


class WindowsAccountLifecycleParser:
    def parse_event(
        self,
        event_data: Mapping[str, object],
    ) -> AccountLifecycleEvent | None:
        if not isinstance(event_data, Mapping):
            raise WindowsAccountLifecycleParseError("event_data must be a mapping")

        event_id = event_data.get("event_id")
        if not isinstance(event_id, int) or isinstance(event_id, bool):
            raise WindowsAccountLifecycleParseError("event_id must be an integer")

        action = WINDOWS_ACCOUNT_LIFECYCLE_ACTIONS.get(event_id)
        if action is None:
            return None

        try:
            return AccountLifecycleEvent(
                timestamp=event_data.get("timestamp"),
                username=event_data.get("username"),
                action=action,
                platform=AuthenticationPlatform.WINDOWS,
                target_domain=self._optional_string(
                    event_data.get("target_domain"),
                    "target_domain",
                ),
                subject_username=self._optional_string(
                    event_data.get("subject_username"),
                    "subject_username",
                ),
                subject_domain=self._optional_string(
                    event_data.get("subject_domain"),
                    "subject_domain",
                ),
                recording_computer=self._optional_string(
                    event_data.get("recording_computer"),
                    "recording_computer",
                ),
            )
        except (TypeError, ValueError) as error:
            raise WindowsAccountLifecycleParseError(str(error)) from error

    @staticmethod
    def _optional_string(value: object, field_name: str) -> str | None:
        if value is None:
            return None
        if not isinstance(value, str):
            raise WindowsAccountLifecycleParseError(
                f"{field_name} must be a string or None"
            )
        if not value.strip():
            return None
        return value

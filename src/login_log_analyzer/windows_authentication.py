from collections.abc import Mapping
from ipaddress import IPv4Address, IPv6Address, ip_address

from login_log_analyzer.authentication import (
    AuthenticationEvent,
    AuthenticationOutcome,
    AuthenticationPlatform,
)


SUPPORTED_EVENT_OUTCOMES = {
    4624: AuthenticationOutcome.SUCCESS,
    4625: AuthenticationOutcome.FAILURE,
}


class WindowsAuthenticationParseError(ValueError):
    pass


class WindowsAuthenticationParser:
    def parse_event(self, event_data: Mapping[str, object]) -> AuthenticationEvent | None:
        if not isinstance(event_data, Mapping):
            raise WindowsAuthenticationParseError("event_data must be a mapping")

        event_id = event_data.get("event_id")
        if not isinstance(event_id, int) or isinstance(event_id, bool):
            raise WindowsAuthenticationParseError("event_id must be an integer")

        outcome = SUPPORTED_EVENT_OUTCOMES.get(event_id)
        if outcome is None:
            return None

        source_ip = self._parse_source_ip(event_data.get("source_ip"))

        try:
            return AuthenticationEvent(
                timestamp=event_data.get("timestamp"),
                username=event_data.get("username"),
                outcome=outcome,
                platform=AuthenticationPlatform.WINDOWS,
                source_ip=source_ip,
            )
        except (TypeError, ValueError) as error:
            raise WindowsAuthenticationParseError(str(error)) from error

    def _parse_source_ip(
        self,
        source_ip_value: object,
    ) -> IPv4Address | IPv6Address | None:
        if source_ip_value is None or source_ip_value in ("", "-"):
            return None
        if not isinstance(source_ip_value, str):
            raise WindowsAuthenticationParseError(
                "source_ip must be a string, None, empty, or '-'"
            )

        try:
            return ip_address(source_ip_value)
        except ValueError as error:
            raise WindowsAuthenticationParseError(
                "invalid source IP in Windows authentication event"
            ) from error


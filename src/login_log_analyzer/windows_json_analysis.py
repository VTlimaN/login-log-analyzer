import json
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from login_log_analyzer.authentication import AuthenticationEvent
from login_log_analyzer.brute_force import (
    BruteForceDetector,
    BruteForceFinding,
)
from login_log_analyzer.off_hours import (
    OffHoursLoginDetector,
    OffHoursLoginFinding,
)
from login_log_analyzer.password_spray import (
    PasswordSprayDetector,
    PasswordSprayFinding,
)
from login_log_analyzer.success_after_failures import (
    SuccessfulLoginAfterFailuresDetector,
    SuccessfulLoginAfterFailuresFinding,
)
from login_log_analyzer.windows_authentication import (
    SUPPORTED_EVENT_OUTCOMES,
    WindowsAuthenticationParseError,
    WindowsAuthenticationParser,
)


class WindowsJsonFormatError(ValueError):
    pass


class WindowsJsonRecordConversionError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class WindowsJsonRecordError:
    record_number: int
    message: str


@dataclass(frozen=True, slots=True)
class WindowsJsonAnalysisResult:
    total_records: int
    parsed_event_count: int
    unsupported_record_count: int
    record_errors: tuple[WindowsJsonRecordError, ...]
    brute_force_findings: tuple[BruteForceFinding, ...]
    off_hours_findings: tuple[OffHoursLoginFinding, ...]
    password_spray_findings: tuple[PasswordSprayFinding, ...]
    successful_login_after_failures_findings: tuple[
        SuccessfulLoginAfterFailuresFinding,
        ...,
    ]

    @property
    def record_error_count(self) -> int:
        return len(self.record_errors)


class WindowsJsonFileAnalyzer:
    def __init__(
        self,
        windows_parser: WindowsAuthenticationParser,
        brute_force_detector: BruteForceDetector,
        off_hours_detector: OffHoursLoginDetector,
        password_spray_detector: PasswordSprayDetector,
        successful_login_after_failures_detector: SuccessfulLoginAfterFailuresDetector,
    ) -> None:
        self._windows_parser = windows_parser
        self._brute_force_detector = brute_force_detector
        self._off_hours_detector = off_hours_detector
        self._password_spray_detector = password_spray_detector
        self._successful_login_after_failures_detector = (
            successful_login_after_failures_detector
        )

    def analyze(self, path: Path) -> WindowsJsonAnalysisResult:
        with path.open("r", encoding="utf-8") as event_file:
            document = json.load(event_file)

        if not isinstance(document, list):
            raise WindowsJsonFormatError("top-level JSON value must be an array")

        events: list[AuthenticationEvent] = []
        record_errors: list[WindowsJsonRecordError] = []
        unsupported_record_count = 0

        for record_number, record in enumerate(document, start=1):
            try:
                event_data = self._convert_record(record)
                event = self._windows_parser.parse_event(event_data)
            except (
                WindowsJsonRecordConversionError,
                WindowsAuthenticationParseError,
            ) as error:
                record_errors.append(
                    WindowsJsonRecordError(
                        record_number=record_number,
                        message=str(error),
                    )
                )
                continue

            if event is None:
                unsupported_record_count += 1
            else:
                events.append(event)

        normalized_events = tuple(events)

        return WindowsJsonAnalysisResult(
            total_records=len(document),
            parsed_event_count=len(normalized_events),
            unsupported_record_count=unsupported_record_count,
            record_errors=tuple(record_errors),
            brute_force_findings=tuple(
                self._brute_force_detector.detect(normalized_events)
            ),
            off_hours_findings=tuple(
                self._off_hours_detector.detect(normalized_events)
            ),
            password_spray_findings=tuple(
                self._password_spray_detector.detect(normalized_events)
            ),
            successful_login_after_failures_findings=tuple(
                self._successful_login_after_failures_detector.detect(
                    normalized_events
                )
            ),
        )

    def _convert_record(self, record: object) -> Mapping[str, object]:
        if not isinstance(record, Mapping):
            raise WindowsJsonRecordConversionError("record must be a JSON object")

        event_data = dict(record)
        event_id = event_data.get("event_id")
        if (
            not isinstance(event_id, int)
            or isinstance(event_id, bool)
            or event_id not in SUPPORTED_EVENT_OUTCOMES
        ):
            return event_data

        timestamp_value = event_data.get("timestamp")
        if not isinstance(timestamp_value, str):
            raise WindowsJsonRecordConversionError(
                "timestamp must be an ISO 8601 string with timezone information"
            )

        try:
            timestamp = datetime.fromisoformat(timestamp_value)
        except ValueError as error:
            raise WindowsJsonRecordConversionError(
                "timestamp must be a valid ISO 8601 string"
            ) from error

        if timestamp.tzinfo is None or timestamp.utcoffset() is None:
            raise WindowsJsonRecordConversionError(
                "timestamp must include timezone information"
            )

        event_data["timestamp"] = timestamp
        return event_data

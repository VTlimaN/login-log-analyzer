import json
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from login_log_analyzer.account_lifecycle import AccountLifecycleEvent
from login_log_analyzer.account_lockout import AccountLockoutEvent
from login_log_analyzer.authentication import AuthenticationEvent
from login_log_analyzer.brute_force import (
    BruteForceDetector,
    BruteForceFinding,
)
from login_log_analyzer.brute_force_lockout import (
    BruteForceAccountLockoutCorrelator,
    BruteForceAccountLockoutFinding,
)
from login_log_analyzer.multiple_source_ips import (
    MultipleSourceIPsDetector,
    MultipleSourceIPsFinding,
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
from login_log_analyzer.windows_account_lockout import (
    WINDOWS_ACCOUNT_LOCKOUT_EVENT_ID,
    WindowsAccountLockoutParseError,
    WindowsAccountLockoutParser,
)
from login_log_analyzer.windows_account_lifecycle import (
    WINDOWS_ACCOUNT_LIFECYCLE_ACTIONS,
    WindowsAccountLifecycleParseError,
    WindowsAccountLifecycleParser,
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
    multiple_source_ips_findings: tuple[MultipleSourceIPsFinding, ...]
    account_lockout_events: tuple[AccountLockoutEvent, ...]
    account_lifecycle_events: tuple[AccountLifecycleEvent, ...] = ()
    brute_force_account_lockout_findings: tuple[
        BruteForceAccountLockoutFinding,
        ...,
    ] = ()

    @property
    def record_error_count(self) -> int:
        return len(self.record_errors)

    @property
    def account_lockout_count(self) -> int:
        return len(self.account_lockout_events)

    @property
    def account_lifecycle_count(self) -> int:
        return len(self.account_lifecycle_events)

    @property
    def brute_force_account_lockout_finding_count(self) -> int:
        return len(self.brute_force_account_lockout_findings)


class WindowsJsonFileAnalyzer:
    def __init__(
        self,
        windows_parser: WindowsAuthenticationParser,
        account_lockout_parser: WindowsAccountLockoutParser,
        account_lifecycle_parser: WindowsAccountLifecycleParser,
        brute_force_detector: BruteForceDetector,
        off_hours_detector: OffHoursLoginDetector,
        password_spray_detector: PasswordSprayDetector,
        successful_login_after_failures_detector: SuccessfulLoginAfterFailuresDetector,
        multiple_source_ips_detector: MultipleSourceIPsDetector,
        brute_force_account_lockout_correlator: BruteForceAccountLockoutCorrelator,
    ) -> None:
        self._windows_parser = windows_parser
        self._account_lockout_parser = account_lockout_parser
        self._account_lifecycle_parser = account_lifecycle_parser
        self._brute_force_detector = brute_force_detector
        self._off_hours_detector = off_hours_detector
        self._password_spray_detector = password_spray_detector
        self._successful_login_after_failures_detector = (
            successful_login_after_failures_detector
        )
        self._multiple_source_ips_detector = multiple_source_ips_detector
        self._brute_force_account_lockout_correlator = (
            brute_force_account_lockout_correlator
        )

    def analyze(self, path: Path) -> WindowsJsonAnalysisResult:
        with path.open("r", encoding="utf-8") as event_file:
            document = json.load(event_file)

        if not isinstance(document, list):
            raise WindowsJsonFormatError("top-level JSON value must be an array")

        events: list[AuthenticationEvent] = []
        account_lockout_events: list[AccountLockoutEvent] = []
        account_lifecycle_events: list[AccountLifecycleEvent] = []
        record_errors: list[WindowsJsonRecordError] = []
        unsupported_record_count = 0

        for record_number, record in enumerate(document, start=1):
            try:
                event_data = self._convert_record(record)
                event_id = event_data["event_id"]
                if event_id in SUPPORTED_EVENT_OUTCOMES:
                    event = self._windows_parser.parse_event(event_data)
                    if event is not None:
                        events.append(event)
                elif event_id == WINDOWS_ACCOUNT_LOCKOUT_EVENT_ID:
                    lockout_event = self._account_lockout_parser.parse_event(
                        event_data
                    )
                    if lockout_event is not None:
                        account_lockout_events.append(lockout_event)
                elif event_id in WINDOWS_ACCOUNT_LIFECYCLE_ACTIONS:
                    lifecycle_event = self._account_lifecycle_parser.parse_event(
                        event_data
                    )
                    if lifecycle_event is not None:
                        account_lifecycle_events.append(lifecycle_event)
                else:
                    unsupported_record_count += 1
            except (
                WindowsJsonRecordConversionError,
                WindowsAuthenticationParseError,
                WindowsAccountLockoutParseError,
                WindowsAccountLifecycleParseError,
            ) as error:
                record_errors.append(
                    WindowsJsonRecordError(
                        record_number=record_number,
                        message=str(error),
                    )
                )
                continue

        normalized_events = tuple(events)
        brute_force_findings = tuple(
            self._brute_force_detector.detect(normalized_events)
        )
        normalized_lockouts = tuple(account_lockout_events)

        return WindowsJsonAnalysisResult(
            total_records=len(document),
            parsed_event_count=len(normalized_events),
            unsupported_record_count=unsupported_record_count,
            record_errors=tuple(record_errors),
            brute_force_findings=brute_force_findings,
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
            multiple_source_ips_findings=tuple(
                self._multiple_source_ips_detector.detect(normalized_events)
            ),
            account_lockout_events=normalized_lockouts,
            account_lifecycle_events=tuple(account_lifecycle_events),
            brute_force_account_lockout_findings=(
                self._brute_force_account_lockout_correlator.correlate(
                    brute_force_findings,
                    normalized_lockouts,
                )
            ),
        )

    def _convert_record(self, record: object) -> Mapping[str, object]:
        if not isinstance(record, Mapping):
            raise WindowsJsonRecordConversionError("record must be a JSON object")

        event_data = dict(record)
        event_id = event_data.get("event_id")
        if not isinstance(event_id, int) or isinstance(event_id, bool):
            raise WindowsJsonRecordConversionError("event_id must be an integer")
        if event_id not in (
            *SUPPORTED_EVENT_OUTCOMES,
            WINDOWS_ACCOUNT_LOCKOUT_EVENT_ID,
            *WINDOWS_ACCOUNT_LIFECYCLE_ACTIONS,
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

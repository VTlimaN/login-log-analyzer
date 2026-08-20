from dataclasses import dataclass
from pathlib import Path

from login_log_analyzer.authentication import AuthenticationEvent
from login_log_analyzer.brute_force import (
    BruteForceDetector,
    BruteForceFinding,
)
from login_log_analyzer.linux_authentication import (
    LinuxAuthenticationParseError,
    LinuxAuthenticationParser,
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


MAX_LINUX_LOG_FILE_BYTES = 100 * 1024 * 1024
MAX_LINUX_LOG_LINES = 1_000_000
MAX_LINUX_AUTHENTICATION_EVENTS = 100_000
MAX_LINUX_PARSE_ERRORS = 100_000
MAX_LINUX_LOG_LINE_CHARACTERS = 65_536


class LinuxLogInputLimitError(OSError):
    pass


@dataclass(frozen=True, slots=True)
class LinuxLogParseError:
    line_number: int
    message: str


@dataclass(frozen=True, slots=True)
class LinuxLogAnalysisResult:
    total_lines: int
    parsed_event_count: int
    unsupported_line_count: int
    parse_errors: tuple[LinuxLogParseError, ...]
    brute_force_findings: tuple[BruteForceFinding, ...]
    off_hours_findings: tuple[OffHoursLoginFinding, ...]
    password_spray_findings: tuple[PasswordSprayFinding, ...]
    successful_login_after_failures_findings: tuple[
        SuccessfulLoginAfterFailuresFinding,
        ...,
    ]
    multiple_source_ips_findings: tuple[MultipleSourceIPsFinding, ...]

    @property
    def parse_error_count(self) -> int:
        return len(self.parse_errors)


class LinuxLogFileAnalyzer:
    def __init__(
        self,
        parser: LinuxAuthenticationParser,
        brute_force_detector: BruteForceDetector,
        off_hours_detector: OffHoursLoginDetector,
        password_spray_detector: PasswordSprayDetector,
        successful_login_after_failures_detector: SuccessfulLoginAfterFailuresDetector,
        multiple_source_ips_detector: MultipleSourceIPsDetector,
    ) -> None:
        self._parser = parser
        self._brute_force_detector = brute_force_detector
        self._off_hours_detector = off_hours_detector
        self._password_spray_detector = password_spray_detector
        self._successful_login_after_failures_detector = (
            successful_login_after_failures_detector
        )
        self._multiple_source_ips_detector = multiple_source_ips_detector

    def analyze(self, path: Path) -> LinuxLogAnalysisResult:
        if path.stat().st_size > MAX_LINUX_LOG_FILE_BYTES:
            raise LinuxLogInputLimitError(
                f"Linux log exceeds the {MAX_LINUX_LOG_FILE_BYTES}-byte limit"
            )

        events: list[AuthenticationEvent] = []
        parse_errors: list[LinuxLogParseError] = []
        total_lines = 0
        total_characters = 0
        unsupported_line_count = 0

        with path.open("r", encoding="utf-8", newline="") as log_file:
            while True:
                raw_line = log_file.readline(MAX_LINUX_LOG_LINE_CHARACTERS + 1)
                if not raw_line:
                    break
                total_lines += 1
                total_characters += len(raw_line)
                if len(raw_line) > MAX_LINUX_LOG_LINE_CHARACTERS:
                    raise LinuxLogInputLimitError(
                        "Linux log line exceeds the "
                        f"{MAX_LINUX_LOG_LINE_CHARACTERS}-character limit"
                    )
                if total_characters > MAX_LINUX_LOG_FILE_BYTES:
                    raise LinuxLogInputLimitError(
                        f"Linux log exceeds the {MAX_LINUX_LOG_FILE_BYTES}-character limit"
                    )
                if total_lines > MAX_LINUX_LOG_LINES:
                    raise LinuxLogInputLimitError(
                        f"Linux log exceeds the {MAX_LINUX_LOG_LINES}-line limit"
                    )
                line = self._remove_line_ending(raw_line)

                try:
                    event = self._parser.parse_line(line)
                except LinuxAuthenticationParseError as error:
                    parse_errors.append(
                        LinuxLogParseError(
                            line_number=total_lines,
                            message=str(error),
                        )
                    )
                    if len(parse_errors) > MAX_LINUX_PARSE_ERRORS:
                        raise LinuxLogInputLimitError(
                            "Linux log exceeds the "
                            f"{MAX_LINUX_PARSE_ERRORS}-parse-error limit"
                        )
                    continue

                if event is None:
                    unsupported_line_count += 1
                else:
                    events.append(event)
                    if len(events) > MAX_LINUX_AUTHENTICATION_EVENTS:
                        raise LinuxLogInputLimitError(
                            "Linux log exceeds the "
                            f"{MAX_LINUX_AUTHENTICATION_EVENTS}"
                            "-authentication-event limit"
                        )

        normalized_events = tuple(events)

        return LinuxLogAnalysisResult(
            total_lines=total_lines,
            parsed_event_count=len(normalized_events),
            unsupported_line_count=unsupported_line_count,
            parse_errors=tuple(parse_errors),
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
            multiple_source_ips_findings=tuple(
                self._multiple_source_ips_detector.detect(normalized_events)
            ),
        )

    @staticmethod
    def _remove_line_ending(line: str) -> str:
        if line.endswith("\n"):
            line = line[:-1]
        if line.endswith("\r"):
            line = line[:-1]
        return line

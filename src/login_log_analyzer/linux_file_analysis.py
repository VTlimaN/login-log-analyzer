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
        events: list[AuthenticationEvent] = []
        parse_errors: list[LinuxLogParseError] = []
        total_lines = 0
        unsupported_line_count = 0

        with path.open("r", encoding="utf-8", newline="") as log_file:
            for line_number, raw_line in enumerate(log_file, start=1):
                total_lines = line_number
                line = self._remove_line_ending(raw_line)

                try:
                    event = self._parser.parse_line(line)
                except LinuxAuthenticationParseError as error:
                    parse_errors.append(
                        LinuxLogParseError(
                            line_number=line_number,
                            message=str(error),
                        )
                    )
                    continue

                if event is None:
                    unsupported_line_count += 1
                else:
                    events.append(event)

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

import re
import subprocess
import sys
import xml.etree.ElementTree as ElementTree
from dataclasses import dataclass
from datetime import datetime

from login_log_analyzer.authentication import AuthenticationEvent
from login_log_analyzer.brute_force import BruteForceDetector, BruteForceFinding
from login_log_analyzer.off_hours import OffHoursLoginDetector, OffHoursLoginFinding
from login_log_analyzer.password_spray import (
    PasswordSprayDetector,
    PasswordSprayFinding,
)
from login_log_analyzer.windows_authentication import (
    SUPPORTED_EVENT_OUTCOMES,
    WindowsAuthenticationParseError,
    WindowsAuthenticationParser,
)


DEFAULT_WINDOWS_NATIVE_EVENT_LIMIT = 100
WINDOWS_SECURITY_QUERY = "*[System[(EventID=4624 or EventID=4625)]]"
XML_DECLARATION_PATTERN = re.compile(r"<\?xml[^>]*\?>")


class WindowsNativeCollectionError(RuntimeError):
    pass


class WindowsNativeUnsupportedPlatformError(WindowsNativeCollectionError):
    pass


class WindowsNativeCollectorUnavailableError(WindowsNativeCollectionError):
    pass


class WindowsNativeQueryError(WindowsNativeCollectionError):
    pass


class WindowsNativeOutputError(WindowsNativeCollectionError):
    pass


class WindowsNativeRecordConversionError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class WindowsNativeRecordError:
    record_number: int
    message: str


@dataclass(frozen=True, slots=True)
class WindowsNativeAnalysisResult:
    collected_record_count: int
    parsed_event_count: int
    unsupported_record_count: int
    record_errors: tuple[WindowsNativeRecordError, ...]
    brute_force_findings: tuple[BruteForceFinding, ...]
    off_hours_findings: tuple[OffHoursLoginFinding, ...]
    password_spray_findings: tuple[PasswordSprayFinding, ...]

    @property
    def record_error_count(self) -> int:
        return len(self.record_errors)


class WindowsEventLogCollector:
    def collect(
        self,
        max_events: int = DEFAULT_WINDOWS_NATIVE_EVENT_LIMIT,
    ) -> tuple[ElementTree.Element, ...]:
        self._validate_event_limit(max_events)
        if sys.platform != "win32":
            raise WindowsNativeUnsupportedPlatformError(
                "native Windows Event Log collection is supported only on Windows"
            )

        command = [
            "wevtutil",
            "qe",
            "Security",
            f"/q:{WINDOWS_SECURITY_QUERY}",
            f"/c:{max_events}",
            "/rd:true",
            "/f:xml",
        ]

        try:
            completed_process = subprocess.run(
                command,
                capture_output=True,
                text=True,
                encoding="utf-8",
                check=False,
                shell=False,
            )
        except OSError as error:
            raise WindowsNativeCollectorUnavailableError(
                "wevtutil could not be found or launched"
            ) from error
        except UnicodeError as error:
            raise WindowsNativeOutputError(
                "wevtutil output could not be decoded as UTF-8"
            ) from error

        if completed_process.returncode != 0:
            detail = completed_process.stderr.strip()
            message = "Windows Security log query failed"
            if detail:
                message = f"{message}: {detail}"
            raise WindowsNativeQueryError(message)

        return self._parse_output(completed_process.stdout)

    @staticmethod
    def _validate_event_limit(max_events: int) -> None:
        if (
            not isinstance(max_events, int)
            or isinstance(max_events, bool)
            or max_events < 1
        ):
            raise ValueError("max_events must be a positive integer")

    @classmethod
    def _parse_output(cls, output: str) -> tuple[ElementTree.Element, ...]:
        normalized_output = XML_DECLARATION_PATTERN.sub(
            "", output.lstrip("\ufeff")
        ).strip()
        if not normalized_output:
            return ()

        try:
            root = ElementTree.fromstring(normalized_output)
        except ElementTree.ParseError:
            try:
                root = ElementTree.fromstring(f"<Events>{normalized_output}</Events>")
            except ElementTree.ParseError as error:
                raise WindowsNativeOutputError(
                    "wevtutil returned malformed XML output"
                ) from error

        root_name = cls._local_name(root.tag)
        if root_name == "Event":
            return (root,)
        if root_name != "Events":
            raise WindowsNativeOutputError(
                "wevtutil returned an unexpected XML root element"
            )

        records = tuple(root)
        if any(cls._local_name(record.tag) != "Event" for record in records):
            raise WindowsNativeOutputError(
                "wevtutil returned an unexpected XML event element"
            )
        return records

    @staticmethod
    def _local_name(tag: str) -> str:
        return tag.rsplit("}", 1)[-1]


class WindowsNativeEventAnalyzer:
    def __init__(
        self,
        collector: WindowsEventLogCollector,
        windows_parser: WindowsAuthenticationParser,
        brute_force_detector: BruteForceDetector,
        off_hours_detector: OffHoursLoginDetector,
        password_spray_detector: PasswordSprayDetector,
    ) -> None:
        self._collector = collector
        self._windows_parser = windows_parser
        self._brute_force_detector = brute_force_detector
        self._off_hours_detector = off_hours_detector
        self._password_spray_detector = password_spray_detector

    def analyze(
        self,
        max_events: int = DEFAULT_WINDOWS_NATIVE_EVENT_LIMIT,
    ) -> WindowsNativeAnalysisResult:
        records = self._collector.collect(max_events)
        events: list[AuthenticationEvent] = []
        record_errors: list[WindowsNativeRecordError] = []
        unsupported_record_count = 0

        for record_number, record in enumerate(records, start=1):
            try:
                event_data = self._convert_record(record)
                event = self._windows_parser.parse_event(event_data)
            except (
                WindowsNativeRecordConversionError,
                WindowsAuthenticationParseError,
            ) as error:
                record_errors.append(
                    WindowsNativeRecordError(
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
        return WindowsNativeAnalysisResult(
            collected_record_count=len(records),
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
        )

    def _convert_record(self, record: ElementTree.Element) -> dict[str, object]:
        if self._local_name(record.tag) != "Event":
            raise WindowsNativeRecordConversionError(
                "record must be a Windows Event XML element"
            )

        system = self._find_child(record, "System")
        if system is None:
            raise WindowsNativeRecordConversionError("event is missing System data")

        event_id_element = self._find_child(system, "EventID")
        event_id_text = (
            event_id_element.text.strip()
            if event_id_element is not None and event_id_element.text
            else ""
        )
        try:
            event_id = int(event_id_text)
        except ValueError as error:
            raise WindowsNativeRecordConversionError(
                "event contains an invalid EventID"
            ) from error

        if event_id not in SUPPORTED_EVENT_OUTCOMES:
            return {"event_id": event_id}

        time_created = self._find_child(system, "TimeCreated")
        timestamp_value = (
            time_created.get("SystemTime") if time_created is not None else None
        )
        timestamp = self._parse_timestamp(timestamp_value)
        event_data = self._event_data_values(record)

        if "TargetUserName" not in event_data:
            raise WindowsNativeRecordConversionError(
                "event is missing TargetUserName"
            )

        return {
            "event_id": event_id,
            "timestamp": timestamp,
            "username": event_data["TargetUserName"],
            "source_ip": event_data.get("IpAddress"),
        }

    @staticmethod
    def _parse_timestamp(timestamp_value: str | None) -> datetime:
        if not timestamp_value:
            raise WindowsNativeRecordConversionError(
                "event is missing TimeCreated SystemTime"
            )

        normalized_timestamp = (
            f"{timestamp_value[:-1]}+00:00"
            if timestamp_value.endswith("Z")
            else timestamp_value
        )
        try:
            timestamp = datetime.fromisoformat(normalized_timestamp)
        except ValueError as error:
            raise WindowsNativeRecordConversionError(
                "event contains an invalid TimeCreated SystemTime"
            ) from error

        if timestamp.tzinfo is None or timestamp.utcoffset() is None:
            raise WindowsNativeRecordConversionError(
                "TimeCreated SystemTime must include timezone information"
            )
        return timestamp

    @classmethod
    def _event_data_values(cls, record: ElementTree.Element) -> dict[str, str]:
        event_data_element = cls._find_child(record, "EventData")
        if event_data_element is None:
            return {}

        values: dict[str, str] = {}
        for data_element in event_data_element:
            if cls._local_name(data_element.tag) != "Data":
                continue
            name = data_element.get("Name")
            if name:
                values[name] = data_element.text or ""
        return values

    @classmethod
    def _find_child(
        cls,
        parent: ElementTree.Element,
        child_name: str,
    ) -> ElementTree.Element | None:
        return next(
            (
                child
                for child in parent
                if cls._local_name(child.tag) == child_name
            ),
            None,
        )

    @staticmethod
    def _local_name(tag: str) -> str:
        return tag.rsplit("}", 1)[-1]

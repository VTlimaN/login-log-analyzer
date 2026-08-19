import subprocess
import xml.etree.ElementTree as ElementTree
from dataclasses import FrozenInstanceError
from datetime import time, timedelta, timezone
from ipaddress import ip_address

import pytest

from login_log_analyzer.authentication import (
    AuthenticationOutcome,
    AuthenticationPlatform,
)
from login_log_analyzer.brute_force import BruteForceDetector
from login_log_analyzer.off_hours import OffHoursLoginDetector
from login_log_analyzer.password_spray import PasswordSprayDetector
from login_log_analyzer.success_after_failures import (
    SuccessfulLoginAfterFailuresDetector,
)
from login_log_analyzer.windows_authentication import WindowsAuthenticationParser
from login_log_analyzer.windows_native_analysis import (
    WINDOWS_SECURITY_QUERY,
    WindowsEventLogCollector,
    WindowsNativeAnalysisResult,
    WindowsNativeCollectorUnavailableError,
    WindowsNativeEventAnalyzer,
    WindowsNativeOutputError,
    WindowsNativeQueryError,
    WindowsNativeRecordError,
    WindowsNativeUnsupportedPlatformError,
)


EVENT_NAMESPACE = "http://schemas.microsoft.com/win/2004/08/events/event"


def create_event_xml(
    *,
    event_id: int = 4624,
    timestamp: str = "2026-08-18T12:15:00.1234567Z",
    username: str | None = "TargetAccount",
    source_ip: str | None = "192.0.2.25",
    subject_username: str = "SYSTEM",
) -> str:
    target_data = (
        f'<Data Name="TargetUserName">{username}</Data>'
        if username is not None
        else ""
    )
    source_data = (
        f'<Data Name="IpAddress">{source_ip}</Data>'
        if source_ip is not None
        else ""
    )
    return (
        f'<Event xmlns="{EVENT_NAMESPACE}">'
        "<System>"
        f"<EventID>{event_id}</EventID>"
        f'<TimeCreated SystemTime="{timestamp}" />'
        "</System>"
        "<EventData>"
        f'<Data Name="SubjectUserName">{subject_username}</Data>'
        f"{target_data}{source_data}"
        "</EventData>"
        "</Event>"
    )


def create_record(**changes: object) -> ElementTree.Element:
    return ElementTree.fromstring(create_event_xml(**changes))


class StaticCollector:
    def __init__(self, records: tuple[ElementTree.Element, ...]) -> None:
        self.records = records
        self.max_events: int | None = None

    def collect(self, max_events: int) -> tuple[ElementTree.Element, ...]:
        self.max_events = max_events
        return self.records


class RecordingDetector:
    def __init__(self) -> None:
        self.events = ()

    def detect(self, events: object) -> list[object]:
        self.events = tuple(events)
        return []


def create_recording_analyzer(
    records: tuple[ElementTree.Element, ...],
) -> tuple[WindowsNativeEventAnalyzer, StaticCollector, RecordingDetector]:
    collector = StaticCollector(records)
    detector = RecordingDetector()
    analyzer = WindowsNativeEventAnalyzer(
        collector=collector,
        windows_parser=WindowsAuthenticationParser(),
        brute_force_detector=detector,
        off_hours_detector=RecordingDetector(),
        password_spray_detector=RecordingDetector(),
        successful_login_after_failures_detector=RecordingDetector(),
    )
    return analyzer, collector, detector


def create_detection_analyzer(
    records: tuple[ElementTree.Element, ...],
) -> WindowsNativeEventAnalyzer:
    return WindowsNativeEventAnalyzer(
        collector=StaticCollector(records),
        windows_parser=WindowsAuthenticationParser(),
        brute_force_detector=BruteForceDetector(
            failure_threshold=3,
            window=timedelta(minutes=5),
        ),
        off_hours_detector=OffHoursLoginDetector(
            allowed_weekdays={0, 1, 2, 3, 4},
            start_time=time(8),
            end_time=time(18),
        ),
        password_spray_detector=PasswordSprayDetector(
            username_threshold=3,
            window=timedelta(minutes=5),
        ),
        successful_login_after_failures_detector=(
            SuccessfulLoginAfterFailuresDetector(
                failure_threshold=3,
                window=timedelta(minutes=5),
            )
        ),
    )


def test_collector_queries_supported_security_events_safely(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    invocation: dict[str, object] = {}

    def run(command: list[str], **options: object) -> subprocess.CompletedProcess[str]:
        invocation["command"] = command
        invocation["options"] = options
        return subprocess.CompletedProcess(
            args=command,
            returncode=0,
            stdout=f"<Events>{create_event_xml()}</Events>",
            stderr="",
        )

    monkeypatch.setattr("login_log_analyzer.windows_native_analysis.sys.platform", "win32")
    monkeypatch.setattr("login_log_analyzer.windows_native_analysis.subprocess.run", run)

    records = WindowsEventLogCollector().collect(25)

    assert len(records) == 1
    command = invocation["command"]
    options = invocation["options"]
    assert isinstance(command, list)
    assert command[:3] == ["wevtutil", "qe", "Security"]
    assert f"/q:{WINDOWS_SECURITY_QUERY}" in command
    assert "EventID=4624" in WINDOWS_SECURITY_QUERY
    assert "EventID=4625" in WINDOWS_SECURITY_QUERY
    assert "/c:25" in command
    assert "/f:xml" in command
    assert isinstance(options, dict)
    assert options["shell"] is False


def test_collector_accepts_multiple_concatenated_xml_events(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    output = (
        '<?xml version="1.0"?>'
        f"{create_event_xml(event_id=4624)}"
        '<?xml version="1.0"?>'
        f"{create_event_xml(event_id=4625)}"
    )
    monkeypatch.setattr("login_log_analyzer.windows_native_analysis.sys.platform", "win32")
    monkeypatch.setattr(
        "login_log_analyzer.windows_native_analysis.subprocess.run",
        lambda *args, **kwargs: subprocess.CompletedProcess(
            args=args[0], returncode=0, stdout=output, stderr=""
        ),
    )

    records = WindowsEventLogCollector().collect(2)

    assert len(records) == 2


def test_collector_returns_empty_collection_for_empty_output(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("login_log_analyzer.windows_native_analysis.sys.platform", "win32")
    monkeypatch.setattr(
        "login_log_analyzer.windows_native_analysis.subprocess.run",
        lambda *args, **kwargs: subprocess.CompletedProcess(
            args=args[0], returncode=0, stdout="", stderr=""
        ),
    )

    assert WindowsEventLogCollector().collect() == ()


def test_collector_rejects_unsupported_platform(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("login_log_analyzer.windows_native_analysis.sys.platform", "linux")

    with pytest.raises(WindowsNativeUnsupportedPlatformError, match="only on Windows"):
        WindowsEventLogCollector().collect()


@pytest.mark.parametrize("max_events", [0, -1, True, 1.5])
def test_collector_rejects_invalid_event_limit(max_events: object) -> None:
    with pytest.raises(ValueError, match="positive integer"):
        WindowsEventLogCollector().collect(max_events)


def test_collector_reports_unavailable_wevtutil(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("login_log_analyzer.windows_native_analysis.sys.platform", "win32")
    monkeypatch.setattr(
        "login_log_analyzer.windows_native_analysis.subprocess.run",
        lambda *args, **kwargs: (_ for _ in ()).throw(FileNotFoundError()),
    )

    with pytest.raises(WindowsNativeCollectorUnavailableError, match="wevtutil"):
        WindowsEventLogCollector().collect()


def test_collector_reports_security_query_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("login_log_analyzer.windows_native_analysis.sys.platform", "win32")
    monkeypatch.setattr(
        "login_log_analyzer.windows_native_analysis.subprocess.run",
        lambda *args, **kwargs: subprocess.CompletedProcess(
            args=args[0], returncode=5, stdout="", stderr="Access is denied."
        ),
    )

    with pytest.raises(WindowsNativeQueryError, match="Access is denied"):
        WindowsEventLogCollector().collect()


def test_collector_rejects_malformed_xml(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("login_log_analyzer.windows_native_analysis.sys.platform", "win32")
    monkeypatch.setattr(
        "login_log_analyzer.windows_native_analysis.subprocess.run",
        lambda *args, **kwargs: subprocess.CompletedProcess(
            args=args[0], returncode=0, stdout="<Event>", stderr=""
        ),
    )

    with pytest.raises(WindowsNativeOutputError, match="malformed XML"):
        WindowsEventLogCollector().collect()


@pytest.mark.parametrize(
    ("event_id", "expected_outcome"),
    [
        (4624, AuthenticationOutcome.SUCCESS),
        (4625, AuthenticationOutcome.FAILURE),
    ],
)
def test_analyzer_normalizes_supported_event_ids(
    event_id: int,
    expected_outcome: AuthenticationOutcome,
) -> None:
    analyzer, _, detector = create_recording_analyzer(
        (create_record(event_id=event_id),)
    )

    result = analyzer.analyze()

    assert result.parsed_event_count == 1
    event = detector.events[0]
    assert event.outcome is expected_outcome
    assert event.platform is AuthenticationPlatform.WINDOWS


def test_analyzer_uses_target_username_instead_of_subject_username() -> None:
    analyzer, _, detector = create_recording_analyzer(
        (
            create_record(
                username="PreservedTarget",
                subject_username="UnrelatedSubject",
            ),
        )
    )

    analyzer.analyze()

    assert detector.events[0].username == "PreservedTarget"


@pytest.mark.parametrize(
    ("source_ip", "expected_source_ip"),
    [
        ("192.0.2.25", ip_address("192.0.2.25")),
        ("2001:db8::25", ip_address("2001:db8::25")),
        ("-", None),
        (None, None),
    ],
)
def test_analyzer_normalizes_source_address(
    source_ip: str | None,
    expected_source_ip: object,
) -> None:
    analyzer, _, detector = create_recording_analyzer(
        (create_record(source_ip=source_ip),)
    )

    analyzer.analyze()

    assert detector.events[0].source_ip == expected_source_ip


def test_analyzer_preserves_timezone_aware_system_time() -> None:
    analyzer, _, detector = create_recording_analyzer(
        (create_record(timestamp="2026-08-18T15:15:00+03:00"),)
    )

    analyzer.analyze()

    assert detector.events[0].timestamp.utcoffset() == timedelta(hours=3)


def test_analyzer_processes_multiple_records_and_passes_limit() -> None:
    analyzer, collector, detector = create_recording_analyzer(
        (create_record(), create_record(event_id=4625, username="Second"))
    )

    result = analyzer.analyze(max_events=12)

    assert result.collected_record_count == 2
    assert result.parsed_event_count == 2
    assert len(detector.events) == 2
    assert collector.max_events == 12


def test_analyzer_continues_after_malformed_individual_event() -> None:
    analyzer, _, detector = create_recording_analyzer(
        (create_record(username=None), create_record(username="ValidTarget"))
    )

    result = analyzer.analyze()

    assert result.parsed_event_count == 1
    assert result.record_errors == (
        WindowsNativeRecordError(
            record_number=1,
            message="event is missing TargetUserName",
        ),
    )
    assert detector.events[0].username == "ValidTarget"


def test_native_pipeline_produces_all_detector_findings() -> None:
    records = tuple(
        create_record(
            event_id=4625,
            timestamp=f"2026-08-18T03:0{minute}:00-03:00",
            username="Administrator",
            source_ip="198.51.100.50",
        )
        for minute in range(3)
    ) + (
        create_record(
            event_id=4625,
            timestamp="2026-08-18T03:03:00-03:00",
            username="User1",
            source_ip="198.51.100.50",
        ),
        create_record(
            event_id=4625,
            timestamp="2026-08-18T03:04:00-03:00",
            username="User2",
            source_ip="198.51.100.50",
        ),
        create_record(
            timestamp="2026-08-18T03:05:00-03:00",
            username="NightAnalyst",
            source_ip=None,
        ),
    )

    result = create_detection_analyzer(records).analyze()

    assert len(result.brute_force_findings) == 1
    assert len(result.off_hours_findings) == 1
    assert len(result.password_spray_findings) == 1


def test_native_result_and_record_errors_are_immutable() -> None:
    analyzer, _, _ = create_recording_analyzer((create_record(username=None),))

    result = analyzer.analyze()

    assert isinstance(result, WindowsNativeAnalysisResult)
    assert isinstance(result.successful_login_after_failures_findings, tuple)
    with pytest.raises(FrozenInstanceError):
        result.collected_record_count = 2
    with pytest.raises(FrozenInstanceError):
        result.record_errors[0].record_number = 2


def test_native_pipeline_detects_successful_login_after_failures() -> None:
    records = tuple(
        create_record(
            event_id=4625,
            timestamp=f"2026-08-18T09:0{minute}:00+00:00",
            username="Admin",
            source_ip="192.0.2.50",
        )
        for minute in range(3)
    ) + (
        create_record(
            event_id=4624,
            timestamp="2026-08-18T09:03:00+00:00",
            username="Admin",
            source_ip="192.0.2.50",
        ),
    )

    result = create_detection_analyzer(records).analyze()

    assert len(result.successful_login_after_failures_findings) == 1
    assert result.successful_login_after_failures_findings[0].failure_count == 3

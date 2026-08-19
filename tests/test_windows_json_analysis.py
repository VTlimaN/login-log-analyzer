import json
from dataclasses import FrozenInstanceError
from datetime import time, timedelta
from pathlib import Path

import pytest

from login_log_analyzer.brute_force import BruteForceDetector
from login_log_analyzer.multiple_source_ips import MultipleSourceIPsDetector
from login_log_analyzer.off_hours import OffHoursLoginDetector
from login_log_analyzer.password_spray import PasswordSprayDetector
from login_log_analyzer.success_after_failures import (
    SuccessfulLoginAfterFailuresDetector,
)
from login_log_analyzer.windows_authentication import WindowsAuthenticationParser
from login_log_analyzer.windows_account_lockout import WindowsAccountLockoutParser
from login_log_analyzer.windows_json_analysis import (
    WindowsJsonAnalysisResult,
    WindowsJsonFileAnalyzer,
    WindowsJsonFormatError,
    WindowsJsonRecordError,
)


def create_analyzer(
    *,
    brute_force_threshold: int = 3,
    password_spray_threshold: int = 3,
) -> WindowsJsonFileAnalyzer:
    return WindowsJsonFileAnalyzer(
        windows_parser=WindowsAuthenticationParser(),
        account_lockout_parser=WindowsAccountLockoutParser(),
        brute_force_detector=BruteForceDetector(
            failure_threshold=brute_force_threshold,
            window=timedelta(minutes=5),
        ),
        off_hours_detector=OffHoursLoginDetector(
            allowed_weekdays={0, 1, 2, 3, 4},
            start_time=time(8),
            end_time=time(18),
        ),
        password_spray_detector=PasswordSprayDetector(
            username_threshold=password_spray_threshold,
            window=timedelta(minutes=5),
        ),
        successful_login_after_failures_detector=(
            SuccessfulLoginAfterFailuresDetector(
                failure_threshold=3,
                window=timedelta(minutes=5),
            )
        ),
        multiple_source_ips_detector=MultipleSourceIPsDetector(
            source_ip_threshold=3,
            window=timedelta(minutes=5),
        ),
    )


def create_record(**changes: object) -> dict[str, object]:
    record: dict[str, object] = {
        "event_id": 4624,
        "timestamp": "2026-08-18T09:15:00-03:00",
        "username": "Analyst",
        "source_ip": "192.0.2.25",
    }
    record.update(changes)
    return record


def write_document(path: Path, document: object) -> None:
    path.write_text(json.dumps(document), encoding="utf-8")


def test_analyzes_valid_empty_array(tmp_path: Path) -> None:
    path = tmp_path / "empty.json"
    write_document(path, [])

    result = create_analyzer().analyze(path)

    assert result.total_records == 0
    assert result.parsed_event_count == 0
    assert result.unsupported_record_count == 0
    assert result.record_error_count == 0
    assert result.brute_force_findings == ()
    assert result.off_hours_findings == ()
    assert result.password_spray_findings == ()
    assert result.successful_login_after_failures_findings == ()
    assert result.multiple_source_ips_findings == ()
    assert result.account_lockout_events == ()
    assert result.account_lockout_count == 0


def test_empty_file_is_invalid_json(tmp_path: Path) -> None:
    path = tmp_path / "empty.json"
    path.write_text("", encoding="utf-8")

    with pytest.raises(json.JSONDecodeError):
        create_analyzer().analyze(path)


def test_invalid_json_syntax_fails_document(tmp_path: Path) -> None:
    path = tmp_path / "invalid.json"
    path.write_text('[{"event_id": 4624}', encoding="utf-8")

    with pytest.raises(json.JSONDecodeError):
        create_analyzer().analyze(path)


@pytest.mark.parametrize("document", [{}, "events", 4624, None])
def test_rejects_non_array_top_level_value(
    tmp_path: Path,
    document: object,
) -> None:
    path = tmp_path / "invalid-root.json"
    write_document(path, document)

    with pytest.raises(WindowsJsonFormatError, match="array"):
        create_analyzer().analyze(path)


@pytest.mark.parametrize("event_id", [4624, 4625])
def test_parses_supported_event_ids(tmp_path: Path, event_id: int) -> None:
    path = tmp_path / "supported.json"
    write_document(path, [create_record(event_id=event_id)])

    result = create_analyzer().analyze(path)

    assert result.total_records == 1
    assert result.parsed_event_count == 1
    assert result.unsupported_record_count == 0
    assert result.record_error_count == 0


def test_counts_unsupported_event_id_without_requiring_authentication_fields(
    tmp_path: Path,
) -> None:
    path = tmp_path / "unsupported.json"
    write_document(path, [{"event_id": 4634, "provider": "Security"}])

    result = create_analyzer().analyze(path)

    assert result.total_records == 1
    assert result.parsed_event_count == 0
    assert result.unsupported_record_count == 1
    assert result.record_error_count == 0


def test_parses_valid_account_lockout_record(tmp_path: Path) -> None:
    path = tmp_path / "lockout.json"
    write_document(
        path,
        [
            create_record(
                event_id=4740,
                timestamp="2026-08-19T10:30:00-03:00",
                username="DemoUser",
                target_domain="DEMO",
                caller_computer="WS-042",
                recording_computer="DC01.demo.invalid",
                source_ip=None,
            )
        ],
    )

    result = create_analyzer().analyze(path)

    assert result.parsed_event_count == 0
    assert result.account_lockout_count == 1
    event = result.account_lockout_events[0]
    assert event.username == "DemoUser"
    assert event.timestamp.utcoffset() == timedelta(hours=-3)
    assert event.target_domain == "DEMO"
    assert event.caller_computer == "WS-042"
    assert event.recording_computer == "DC01.demo.invalid"


def test_mixed_authentication_and_lockout_records_preserve_counts(
    tmp_path: Path,
) -> None:
    path = tmp_path / "mixed-event-families.json"
    write_document(
        path,
        [
            create_record(event_id=4624),
            create_record(event_id=4625),
            create_record(event_id=4740, caller_computer=None),
        ],
    )

    result = create_analyzer().analyze(path)

    assert result.total_records == 3
    assert result.parsed_event_count == 2
    assert result.account_lockout_count == 1
    assert result.unsupported_record_count == 0


def test_malformed_lockout_is_recoverable_and_later_record_is_processed(
    tmp_path: Path,
) -> None:
    path = tmp_path / "recoverable-lockout.json"
    malformed = create_record(event_id=4740)
    del malformed["username"]
    write_document(
        path,
        [malformed, create_record(event_id=4740, username="LaterUser")],
    )

    result = create_analyzer().analyze(path)

    assert result.record_error_count == 1
    assert result.record_errors[0].record_number == 1
    assert "username" in result.record_errors[0].message
    assert result.account_lockout_count == 1
    assert result.account_lockout_events[0].username == "LaterUser"


def test_lockouts_are_not_passed_to_authentication_detectors(tmp_path: Path) -> None:
    path = tmp_path / "lockout-isolation.json"
    write_document(
        path,
        [
            create_record(
                event_id=4740,
                username="Admin",
                source_ip=f"192.0.2.{number}",
            )
            for number in range(1, 7)
        ],
    )

    result = create_analyzer().analyze(path)

    assert result.parsed_event_count == 0
    assert result.account_lockout_count == 6
    assert result.brute_force_findings == ()
    assert result.password_spray_findings == ()
    assert result.successful_login_after_failures_findings == ()
    assert result.multiple_source_ips_findings == ()


def test_reports_malformed_supported_record(tmp_path: Path) -> None:
    path = tmp_path / "malformed.json"
    record = create_record()
    del record["username"]
    write_document(path, [record])

    result = create_analyzer().analyze(path)

    assert result.record_errors == (
        WindowsJsonRecordError(
            record_number=1,
            message="username must be a string",
        ),
    )


def test_reports_non_object_array_element(tmp_path: Path) -> None:
    path = tmp_path / "non-object.json"
    write_document(path, ["not an event"])

    result = create_analyzer().analyze(path)

    assert result.record_errors == (
        WindowsJsonRecordError(
            record_number=1,
            message="record must be a JSON object",
        ),
    )


@pytest.mark.parametrize(
    ("timestamp", "message"),
    [
        (None, "ISO 8601 string with timezone"),
        (4624, "ISO 8601 string with timezone"),
        ("not-a-timestamp", "valid ISO 8601"),
        ("2026-08-18T09:15:00", "timezone information"),
    ],
)
def test_reports_timestamp_record_errors(
    tmp_path: Path,
    timestamp: object,
    message: str,
) -> None:
    path = tmp_path / "timestamp.json"
    write_document(path, [create_record(timestamp=timestamp)])

    result = create_analyzer().analyze(path)

    assert result.record_error_count == 1
    assert message in result.record_errors[0].message


def test_reports_missing_timestamp(tmp_path: Path) -> None:
    path = tmp_path / "missing-timestamp.json"
    record = create_record()
    del record["timestamp"]
    write_document(path, [record])

    result = create_analyzer().analyze(path)

    assert result.record_error_count == 1
    assert "timestamp" in result.record_errors[0].message


def test_reports_invalid_source_ip_through_windows_parser(tmp_path: Path) -> None:
    path = tmp_path / "invalid-ip.json"
    write_document(path, [create_record(source_ip="999.999.999.999")])

    result = create_analyzer().analyze(path)

    assert result.record_error_count == 1
    assert "source IP" in result.record_errors[0].message


def test_mixed_records_continue_after_errors(tmp_path: Path) -> None:
    path = tmp_path / "mixed.json"
    malformed_record = create_record(event_id=4625)
    del malformed_record["username"]
    write_document(
        path,
        [
            create_record(),
            create_record(event_id=4625, username="Admin"),
            {"event_id": 4634},
            malformed_record,
            create_record(timestamp="invalid"),
            create_record(
                event_id=4625,
                timestamp="2026-08-18T09:20:00-03:00",
                username="LaterUser",
            ),
        ],
    )

    result = create_analyzer().analyze(path)

    assert result.total_records == 6
    assert result.parsed_event_count == 3
    assert result.unsupported_record_count == 1
    assert result.record_error_count == 2
    assert tuple(error.record_number for error in result.record_errors) == (4, 5)


def test_complete_pipeline_produces_all_detector_findings(tmp_path: Path) -> None:
    path = tmp_path / "attack.json"
    records = [
        create_record(
            event_id=4625,
            timestamp=f"2026-08-18T03:0{minute}:00-03:00",
            username="Administrator",
            source_ip="198.51.100.50",
        )
        for minute in range(3)
    ]
    records.extend(
        [
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
        ]
    )
    write_document(path, records)

    result = create_analyzer().analyze(path)

    assert len(result.brute_force_findings) == 1
    assert result.brute_force_findings[0].username == "Administrator"
    assert len(result.password_spray_findings) == 1
    assert result.password_spray_findings[0].usernames == (
        "Administrator",
        "User1",
        "User2",
    )
    assert len(result.off_hours_findings) == 1
    assert result.off_hours_findings[0].username == "NightAnalyst"
    assert result.off_hours_findings[0].timestamp.utcoffset() == timedelta(hours=-3)


def test_analyzer_uses_supplied_detector_configuration(tmp_path: Path) -> None:
    path = tmp_path / "configured.json"
    records = [
        create_record(
            event_id=4625,
            timestamp=f"2026-08-18T09:0{minute}:00+00:00",
            username="Admin",
            source_ip="192.0.2.50",
        )
        for minute in range(3)
    ]
    records.extend(
        [
            create_record(
                event_id=4625,
                timestamp="2026-08-18T09:03:00+00:00",
                username="User1",
                source_ip="192.0.2.50",
            ),
            create_record(
                event_id=4625,
                timestamp="2026-08-18T09:04:00+00:00",
                username="User2",
                source_ip="192.0.2.50",
            ),
        ]
    )
    write_document(path, records)

    result = create_analyzer(
        brute_force_threshold=4,
        password_spray_threshold=4,
    ).analyze(path)

    assert result.brute_force_findings == ()
    assert result.password_spray_findings == ()


def test_pipeline_detects_successful_login_after_failures(tmp_path: Path) -> None:
    path = tmp_path / "success-after-failures.json"
    records = [
        create_record(
            event_id=4625,
            timestamp=f"2026-08-18T09:0{minute}:00+00:00",
            username="Admin",
            source_ip="192.0.2.50",
        )
        for minute in range(3)
    ]
    records.append(
        create_record(
            event_id=4624,
            timestamp="2026-08-18T09:03:00+00:00",
            username="Admin",
            source_ip="192.0.2.50",
        )
    )
    write_document(path, records)

    result = create_analyzer().analyze(path)

    assert len(result.successful_login_after_failures_findings) == 1
    assert result.successful_login_after_failures_findings[0].failure_count == 3


def test_pipeline_detects_multiple_source_ips(tmp_path: Path) -> None:
    path = tmp_path / "multiple-source-ips.json"
    records = [
        create_record(
            event_id=4625,
            timestamp=f"2026-08-18T09:0{minute}:00+00:00",
            username="Admin",
            source_ip=f"192.0.2.{minute + 1}",
        )
        for minute in range(3)
    ]
    write_document(path, records)

    result = create_analyzer().analyze(path)

    assert len(result.multiple_source_ips_findings) == 1
    assert result.multiple_source_ips_findings[0].distinct_source_ip_count == 3


def test_missing_file_error_propagates(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        create_analyzer().analyze(tmp_path / "missing.json")


def test_directory_path_error_propagates(tmp_path: Path) -> None:
    with pytest.raises((IsADirectoryError, PermissionError)):
        create_analyzer().analyze(tmp_path)


def test_invalid_utf8_error_propagates(tmp_path: Path) -> None:
    path = tmp_path / "invalid-utf8.json"
    path.write_bytes(b"\xff\xfe")

    with pytest.raises(UnicodeDecodeError):
        create_analyzer().analyze(path)


def test_result_and_record_errors_are_immutable(tmp_path: Path) -> None:
    path = tmp_path / "immutable.json"
    write_document(path, ["invalid"])

    result = create_analyzer().analyze(path)

    assert isinstance(result, WindowsJsonAnalysisResult)
    assert isinstance(result.record_errors, tuple)
    assert isinstance(result.record_errors[0], WindowsJsonRecordError)
    assert isinstance(result.successful_login_after_failures_findings, tuple)
    assert isinstance(result.multiple_source_ips_findings, tuple)
    assert isinstance(result.account_lockout_events, tuple)
    with pytest.raises(FrozenInstanceError):
        result.total_records = 2
    with pytest.raises(FrozenInstanceError):
        result.record_errors[0].record_number = 2

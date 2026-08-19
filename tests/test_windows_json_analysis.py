import json
from dataclasses import FrozenInstanceError
from datetime import time, timedelta
from pathlib import Path

import pytest

from login_log_analyzer.brute_force import BruteForceDetector
from login_log_analyzer.off_hours import OffHoursLoginDetector
from login_log_analyzer.password_spray import PasswordSprayDetector
from login_log_analyzer.windows_authentication import WindowsAuthenticationParser
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
    with pytest.raises(FrozenInstanceError):
        result.total_records = 2
    with pytest.raises(FrozenInstanceError):
        result.record_errors[0].record_number = 2

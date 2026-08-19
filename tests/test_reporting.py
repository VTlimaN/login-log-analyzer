import csv
import json
from datetime import datetime
from ipaddress import ip_address
from pathlib import Path

import pytest

from login_log_analyzer.authentication import AuthenticationPlatform
from login_log_analyzer.brute_force import BruteForceFinding
from login_log_analyzer.linux_file_analysis import (
    LinuxLogAnalysisResult,
    LinuxLogParseError,
)
from login_log_analyzer.off_hours import OffHoursLoginFinding
from login_log_analyzer.password_spray import PasswordSprayFinding
from login_log_analyzer.reporting import (
    CSV_COLUMNS,
    ReportConfigurationError,
    export_csv_report,
    export_json_report,
    validate_report_destinations,
)
from login_log_analyzer.success_after_failures import (
    SuccessfulLoginAfterFailuresFinding,
)
from login_log_analyzer.windows_json_analysis import (
    WindowsJsonAnalysisResult,
    WindowsJsonRecordError,
)
from login_log_analyzer.windows_native_analysis import (
    WindowsNativeAnalysisResult,
    WindowsNativeRecordError,
)


FIRST = datetime.fromisoformat("2026-08-18T09:00:00-03:00")
LAST = datetime.fromisoformat("2026-08-18T09:04:00-03:00")


def findings() -> tuple[
    tuple[BruteForceFinding, ...],
    tuple[OffHoursLoginFinding, ...],
    tuple[PasswordSprayFinding, ...],
    tuple[SuccessfulLoginAfterFailuresFinding, ...],
]:
    return (
        (
            BruteForceFinding(
                username="Admin, Produção",
                source_ip=ip_address("192.0.2.10"),
                first_observed=FIRST,
                last_observed=LAST,
                failure_count=5,
            ),
        ),
        (
            OffHoursLoginFinding(
                username="Analyst",
                timestamp=FIRST,
                source_ip=None,
                platform=AuthenticationPlatform.WINDOWS,
            ),
        ),
        (
            PasswordSprayFinding(
                source_ip=ip_address("2001:db8::25"),
                first_observed=FIRST,
                last_observed=LAST,
                distinct_username_count=3,
                usernames=("Admin", "Guest", "User"),
            ),
        ),
        (
            SuccessfulLoginAfterFailuresFinding(
                username="Admin",
                source_ip=ip_address("192.0.2.10"),
                first_failure=FIRST,
                last_failure=LAST,
                successful_login=datetime.fromisoformat(
                    "2026-08-18T09:05:00-03:00"
                ),
                failure_count=5,
                platform=AuthenticationPlatform.WINDOWS,
            ),
        ),
    )


def linux_result(*, include_findings: bool = True) -> LinuxLogAnalysisResult:
    brute_force, off_hours, password_spray, success_after_failures = (
        findings() if include_findings else ((), (), (), ())
    )
    return LinuxLogAnalysisResult(
        total_lines=8,
        parsed_event_count=6,
        unsupported_line_count=1,
        parse_errors=(LinuxLogParseError(7, "invalid source IP"),),
        brute_force_findings=brute_force,
        off_hours_findings=off_hours,
        password_spray_findings=password_spray,
        successful_login_after_failures_findings=success_after_failures,
    )


@pytest.mark.parametrize(
    ("result", "source", "summary_key", "error_key"),
    [
        (linux_result(), "linux_file", "total_lines", "line_number"),
        (
            WindowsJsonAnalysisResult(
                total_records=8,
                parsed_event_count=6,
                unsupported_record_count=1,
                record_errors=(WindowsJsonRecordError(7, "invalid timestamp"),),
                brute_force_findings=findings()[0],
                off_hours_findings=findings()[1],
                password_spray_findings=findings()[2],
                successful_login_after_failures_findings=findings()[3],
            ),
            "windows_json",
            "total_records",
            "record_number",
        ),
        (
            WindowsNativeAnalysisResult(
                collected_record_count=8,
                parsed_event_count=6,
                unsupported_record_count=1,
                record_errors=(WindowsNativeRecordError(7, "invalid event XML"),),
                brute_force_findings=findings()[0],
                off_hours_findings=findings()[1],
                password_spray_findings=findings()[2],
                successful_login_after_failures_findings=findings()[3],
            ),
            "windows_native",
            "collected_record_count",
            "record_number",
        ),
    ],
)
def test_exports_complete_json_contract(
    tmp_path: Path,
    result: object,
    source: str,
    summary_key: str,
    error_key: str,
) -> None:
    destination = tmp_path / f"{source}.json"

    export_json_report(result, destination)

    document = json.loads(destination.read_text(encoding="utf-8"))
    assert document["report_version"] == 1
    assert document["analysis_source"] == source
    assert summary_key in document["summary"]
    assert document["summary"]["brute_force_finding_count"] == 1
    assert document["errors"][0][error_key] == 7
    assert document["findings"]["brute_force"][0]["source_ip"] == "192.0.2.10"
    assert document["findings"]["brute_force"][0]["first_observed"].endswith("-03:00")
    assert document["findings"]["off_hours"][0]["source_ip"] is None
    assert document["findings"]["off_hours"][0]["platform"] == "windows"
    assert document["findings"]["password_spray"][0]["source_ip"] == "2001:db8::25"
    assert document["findings"]["password_spray"][0]["usernames"] == [
        "Admin",
        "Guest",
        "User",
    ]
    success_finding = document["findings"]["successful_login_after_failures"][0]
    assert success_finding == {
        "username": "Admin",
        "source_ip": "192.0.2.10",
        "first_failure": "2026-08-18T09:00:00-03:00",
        "last_failure": "2026-08-18T09:04:00-03:00",
        "successful_login": "2026-08-18T09:05:00-03:00",
        "failure_count": 5,
        "platform": "windows",
    }
    assert (
        document["summary"]["successful_login_after_failures_finding_count"]
        == 1
    )
    assert "Produção" in destination.read_text(encoding="utf-8")
    assert destination.read_bytes().endswith(b"\n")


def test_exports_unified_csv_with_quoting_and_stable_values(tmp_path: Path) -> None:
    destination = tmp_path / "findings.csv"

    export_csv_report(linux_result(), destination)

    with destination.open(encoding="utf-8", newline="") as report:
        rows = list(csv.DictReader(report))
    assert tuple(rows[0]) == CSV_COLUMNS
    assert [row["finding_type"] for row in rows] == [
        "brute_force",
        "off_hours",
        "password_spray",
        "successful_login_after_failures",
    ]
    assert rows[0]["username"] == "Admin, Produção"
    assert rows[0]["first_observed"].endswith("-03:00")
    assert rows[1]["source_ip"] == ""
    assert rows[1]["platform"] == "windows"
    assert rows[2]["source_ip"] == "2001:db8::25"
    assert rows[2]["usernames"] == "Admin;Guest;User"
    assert rows[3]["username"] == "Admin"
    assert rows[3]["platform"] == "windows"
    assert rows[3]["first_failure"] == "2026-08-18T09:00:00-03:00"
    assert rows[3]["last_failure"] == "2026-08-18T09:04:00-03:00"
    assert rows[3]["successful_login"] == "2026-08-18T09:05:00-03:00"
    assert rows[3]["failure_count"] == "5"


def test_exports_header_only_csv_when_there_are_no_findings(tmp_path: Path) -> None:
    destination = tmp_path / "empty.csv"

    export_csv_report(linux_result(include_findings=False), destination)

    with destination.open(encoding="utf-8", newline="") as report:
        rows = list(csv.reader(report))
    assert rows == [list(CSV_COLUMNS)]


def test_rejects_existing_destination_and_allows_explicit_overwrite(tmp_path: Path) -> None:
    destination = tmp_path / "report.json"
    destination.write_text("old", encoding="utf-8")

    with pytest.raises(FileExistsError):
        export_json_report(linux_result(), destination)

    export_json_report(linux_result(), destination, overwrite=True)

    assert json.loads(destination.read_text(encoding="utf-8"))["report_version"] == 1


@pytest.mark.parametrize("kind", ["directory", "missing_parent"])
def test_rejects_invalid_destination_paths(tmp_path: Path, kind: str) -> None:
    destination = (
        tmp_path if kind == "directory" else tmp_path / "missing" / "report.json"
    )

    with pytest.raises((IsADirectoryError, FileNotFoundError)):
        export_json_report(linux_result(), destination)


def test_rejects_same_json_and_csv_destination(tmp_path: Path) -> None:
    destination = tmp_path / "report"

    with pytest.raises(ReportConfigurationError):
        validate_report_destinations(destination, destination, overwrite=False)


def test_removes_temporary_file_when_atomic_replace_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    destination = tmp_path / "report.json"

    def fail_replace(source: Path, target: Path) -> None:
        raise PermissionError("denied")

    monkeypatch.setattr("login_log_analyzer.reporting.os.replace", fail_replace)

    with pytest.raises(PermissionError):
        export_json_report(linux_result(), destination)

    assert not destination.exists()
    assert list(tmp_path.iterdir()) == []

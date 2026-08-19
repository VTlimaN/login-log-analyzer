import csv
import io
import json
import os
import tempfile
from pathlib import Path

from login_log_analyzer.account_lifecycle import AccountLifecycleEvent
from login_log_analyzer.account_lockout import AccountLockoutEvent
from login_log_analyzer.brute_force import BruteForceFinding
from login_log_analyzer.brute_force_lockout import (
    BruteForceAccountLockoutFinding,
)
from login_log_analyzer.linux_file_analysis import LinuxLogAnalysisResult
from login_log_analyzer.multiple_source_ips import MultipleSourceIPsFinding
from login_log_analyzer.off_hours import OffHoursLoginFinding
from login_log_analyzer.password_spray import PasswordSprayFinding
from login_log_analyzer.success_after_failures import (
    SuccessfulLoginAfterFailuresFinding,
)
from login_log_analyzer.windows_json_analysis import WindowsJsonAnalysisResult
from login_log_analyzer.windows_native_analysis import WindowsNativeAnalysisResult


REPORT_VERSION = 1
CSV_COLUMNS = (
    "finding_type",
    "username",
    "source_ip",
    "platform",
    "first_observed",
    "last_observed",
    "timestamp",
    "failure_count",
    "distinct_username_count",
    "usernames",
    "first_failure",
    "last_failure",
    "successful_login",
    "distinct_source_ip_count",
    "source_ips",
    "lockout_timestamp",
    "correlation_delay_seconds",
)

AnalysisResult = (
    LinuxLogAnalysisResult
    | WindowsJsonAnalysisResult
    | WindowsNativeAnalysisResult
)


class ReportConfigurationError(ValueError):
    pass


def export_json_report(
    result: AnalysisResult,
    destination: Path,
    *,
    overwrite: bool = False,
) -> None:
    document = _json_document(result)
    content = json.dumps(
        document,
        ensure_ascii=False,
        indent=2,
        sort_keys=True,
    ) + "\n"
    _write_text(destination, content, overwrite=overwrite, newline=None)


def export_csv_report(
    result: AnalysisResult,
    destination: Path,
    *,
    overwrite: bool = False,
) -> None:
    report = io.StringIO(newline="")
    writer = csv.DictWriter(report, fieldnames=CSV_COLUMNS)
    writer.writeheader()
    writer.writerows(_csv_rows(result))
    _write_text(destination, report.getvalue(), overwrite=overwrite, newline="")


def validate_report_destinations(
    json_destination: Path | None,
    csv_destination: Path | None,
    *,
    overwrite: bool,
) -> None:
    if (
        json_destination is not None
        and csv_destination is not None
        and _normalized_path(json_destination) == _normalized_path(csv_destination)
    ):
        raise ReportConfigurationError(
            "JSON and CSV report destinations must be different"
        )

    for destination in (json_destination, csv_destination):
        if destination is not None:
            _validate_destination(destination, overwrite=overwrite)


def _json_document(result: AnalysisResult) -> dict[str, object]:
    source, summary, errors = _source_data(result)
    summary.update(
        {
            "brute_force_finding_count": len(result.brute_force_findings),
            "off_hours_finding_count": len(result.off_hours_findings),
            "password_spray_finding_count": len(result.password_spray_findings),
            "successful_login_after_failures_finding_count": len(
                result.successful_login_after_failures_findings
            ),
            "multiple_source_ips_finding_count": len(
                result.multiple_source_ips_findings
            ),
        }
    )
    document: dict[str, object] = {
        "report_version": REPORT_VERSION,
        "analysis_source": source,
        "summary": summary,
        "errors": errors,
        "findings": {
            "brute_force": [
                _brute_force_json(finding)
                for finding in result.brute_force_findings
            ],
            "off_hours": [
                _off_hours_json(finding) for finding in result.off_hours_findings
            ],
            "password_spray": [
                _password_spray_json(finding)
                for finding in result.password_spray_findings
            ],
            "successful_login_after_failures": [
                _successful_login_after_failures_json(finding)
                for finding in result.successful_login_after_failures_findings
            ],
            "multiple_source_ips": [
                _multiple_source_ips_json(finding)
                for finding in result.multiple_source_ips_findings
            ],
        },
    }
    if isinstance(result, (WindowsJsonAnalysisResult, WindowsNativeAnalysisResult)):
        document["brute_force_account_lockout"] = [
            _brute_force_account_lockout_json(finding)
            for finding in result.brute_force_account_lockout_findings
        ]
        document["account_lockouts"] = [
            _account_lockout_json(event)
            for event in result.account_lockout_events
        ]
        document["account_lifecycle"] = [
            _account_lifecycle_json(event)
            for event in result.account_lifecycle_events
        ]
    return document


def _source_data(
    result: AnalysisResult,
) -> tuple[str, dict[str, int], list[dict[str, object]]]:
    if isinstance(result, LinuxLogAnalysisResult):
        return (
            "linux_file",
            {
                "total_lines": result.total_lines,
                "parsed_event_count": result.parsed_event_count,
                "unsupported_line_count": result.unsupported_line_count,
                "parse_error_count": result.parse_error_count,
            },
            [
                {"line_number": error.line_number, "message": error.message}
                for error in result.parse_errors
            ],
        )
    if isinstance(result, WindowsJsonAnalysisResult):
        return (
            "windows_json",
            {
                "total_records": result.total_records,
                "parsed_event_count": result.parsed_event_count,
                "unsupported_record_count": result.unsupported_record_count,
                "record_error_count": result.record_error_count,
                "account_lockout_count": result.account_lockout_count,
                "account_lifecycle_count": result.account_lifecycle_count,
                "brute_force_account_lockout_count": (
                    result.brute_force_account_lockout_finding_count
                ),
            },
            [
                {"record_number": error.record_number, "message": error.message}
                for error in result.record_errors
            ],
        )
    if isinstance(result, WindowsNativeAnalysisResult):
        return (
            "windows_native",
            {
                "collected_record_count": result.collected_record_count,
                "parsed_event_count": result.parsed_event_count,
                "unsupported_record_count": result.unsupported_record_count,
                "record_error_count": result.record_error_count,
                "account_lockout_count": result.account_lockout_count,
                "account_lifecycle_count": result.account_lifecycle_count,
                "brute_force_account_lockout_count": (
                    result.brute_force_account_lockout_finding_count
                ),
            },
            [
                {"record_number": error.record_number, "message": error.message}
                for error in result.record_errors
            ],
        )
    raise TypeError("unsupported analysis result type")


def _brute_force_json(finding: BruteForceFinding) -> dict[str, object]:
    return {
        "username": finding.username,
        "source_ip": str(finding.source_ip),
        "first_observed": finding.first_observed.isoformat(),
        "last_observed": finding.last_observed.isoformat(),
        "failure_count": finding.failure_count,
    }


def _brute_force_account_lockout_json(
    finding: BruteForceAccountLockoutFinding,
) -> dict[str, object]:
    return {
        "username": finding.username,
        "source_ip": str(finding.source_ip),
        "brute_force_first_failure": (
            finding.brute_force_first_failure.isoformat()
        ),
        "brute_force_last_failure": finding.brute_force_last_failure.isoformat(),
        "brute_force_failure_count": finding.brute_force_failure_count,
        "lockout_timestamp": finding.lockout_timestamp.isoformat(),
        "correlation_delay_seconds": finding.correlation_delay.total_seconds(),
    }


def _off_hours_json(finding: OffHoursLoginFinding) -> dict[str, object]:
    return {
        "username": finding.username,
        "timestamp": finding.timestamp.isoformat(),
        "source_ip": (
            str(finding.source_ip) if finding.source_ip is not None else None
        ),
        "platform": finding.platform.value,
    }


def _password_spray_json(finding: PasswordSprayFinding) -> dict[str, object]:
    return {
        "source_ip": str(finding.source_ip),
        "first_observed": finding.first_observed.isoformat(),
        "last_observed": finding.last_observed.isoformat(),
        "distinct_username_count": finding.distinct_username_count,
        "usernames": list(finding.usernames),
    }


def _successful_login_after_failures_json(
    finding: SuccessfulLoginAfterFailuresFinding,
) -> dict[str, object]:
    return {
        "username": finding.username,
        "source_ip": str(finding.source_ip),
        "first_failure": finding.first_failure.isoformat(),
        "last_failure": finding.last_failure.isoformat(),
        "successful_login": finding.successful_login.isoformat(),
        "failure_count": finding.failure_count,
        "platform": finding.platform.value,
    }


def _account_lockout_json(event: AccountLockoutEvent) -> dict[str, object]:
    return {
        "timestamp": event.timestamp.isoformat(),
        "username": event.username,
        "platform": event.platform.value,
        "target_domain": event.target_domain,
        "caller_computer": event.caller_computer,
        "recording_computer": event.recording_computer,
    }


def _account_lifecycle_json(
    event: AccountLifecycleEvent,
) -> dict[str, object]:
    return {
        "timestamp": event.timestamp.isoformat(),
        "username": event.username,
        "action": event.action.value,
        "platform": event.platform.value,
        "target_domain": event.target_domain,
        "subject_username": event.subject_username,
        "subject_domain": event.subject_domain,
        "recording_computer": event.recording_computer,
    }


def _multiple_source_ips_json(
    finding: MultipleSourceIPsFinding,
) -> dict[str, object]:
    return {
        "username": finding.username,
        "first_observed": finding.first_observed.isoformat(),
        "last_observed": finding.last_observed.isoformat(),
        "distinct_source_ip_count": finding.distinct_source_ip_count,
        "source_ips": [str(source_ip) for source_ip in finding.source_ips],
    }


def _csv_rows(result: AnalysisResult) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    rows.extend(_brute_force_csv(finding) for finding in result.brute_force_findings)
    rows.extend(_off_hours_csv(finding) for finding in result.off_hours_findings)
    rows.extend(
        _password_spray_csv(finding) for finding in result.password_spray_findings
    )
    rows.extend(
        _successful_login_after_failures_csv(finding)
        for finding in result.successful_login_after_failures_findings
    )
    rows.extend(
        _multiple_source_ips_csv(finding)
        for finding in result.multiple_source_ips_findings
    )
    if isinstance(result, (WindowsJsonAnalysisResult, WindowsNativeAnalysisResult)):
        rows.extend(
            _brute_force_account_lockout_csv(finding)
            for finding in result.brute_force_account_lockout_findings
        )
    return rows


def _empty_csv_row() -> dict[str, object]:
    return {column: "" for column in CSV_COLUMNS}


def _brute_force_csv(finding: BruteForceFinding) -> dict[str, object]:
    row = _empty_csv_row()
    row.update(
        {
            "finding_type": "brute_force",
            "username": finding.username,
            "source_ip": str(finding.source_ip),
            "first_observed": finding.first_observed.isoformat(),
            "last_observed": finding.last_observed.isoformat(),
            "failure_count": finding.failure_count,
        }
    )
    return row


def _off_hours_csv(finding: OffHoursLoginFinding) -> dict[str, object]:
    row = _empty_csv_row()
    row.update(
        {
            "finding_type": "off_hours",
            "username": finding.username,
            "source_ip": (
                str(finding.source_ip) if finding.source_ip is not None else ""
            ),
            "platform": finding.platform.value,
            "timestamp": finding.timestamp.isoformat(),
        }
    )
    return row


def _password_spray_csv(finding: PasswordSprayFinding) -> dict[str, object]:
    row = _empty_csv_row()
    row.update(
        {
            "finding_type": "password_spray",
            "source_ip": str(finding.source_ip),
            "first_observed": finding.first_observed.isoformat(),
            "last_observed": finding.last_observed.isoformat(),
            "distinct_username_count": finding.distinct_username_count,
            "usernames": ";".join(finding.usernames),
        }
    )
    return row


def _successful_login_after_failures_csv(
    finding: SuccessfulLoginAfterFailuresFinding,
) -> dict[str, object]:
    row = _empty_csv_row()
    row.update(
        {
            "finding_type": "successful_login_after_failures",
            "username": finding.username,
            "source_ip": str(finding.source_ip),
            "platform": finding.platform.value,
            "first_failure": finding.first_failure.isoformat(),
            "last_failure": finding.last_failure.isoformat(),
            "successful_login": finding.successful_login.isoformat(),
            "failure_count": finding.failure_count,
        }
    )
    return row


def _multiple_source_ips_csv(
    finding: MultipleSourceIPsFinding,
) -> dict[str, object]:
    row = _empty_csv_row()
    row.update(
        {
            "finding_type": "multiple_source_ips",
            "username": finding.username,
            "first_observed": finding.first_observed.isoformat(),
            "last_observed": finding.last_observed.isoformat(),
            "distinct_source_ip_count": finding.distinct_source_ip_count,
            "source_ips": ";".join(str(source_ip) for source_ip in finding.source_ips),
        }
    )
    return row


def _brute_force_account_lockout_csv(
    finding: BruteForceAccountLockoutFinding,
) -> dict[str, object]:
    row = _empty_csv_row()
    row.update(
        {
            "finding_type": "brute_force_account_lockout",
            "username": finding.username,
            "source_ip": str(finding.source_ip),
            "first_observed": finding.brute_force_first_failure.isoformat(),
            "last_observed": finding.brute_force_last_failure.isoformat(),
            "failure_count": finding.brute_force_failure_count,
            "lockout_timestamp": finding.lockout_timestamp.isoformat(),
            "correlation_delay_seconds": (
                finding.correlation_delay.total_seconds()
            ),
        }
    )
    return row


def _write_text(
    destination: Path,
    content: str,
    *,
    overwrite: bool,
    newline: str | None,
) -> None:
    _validate_destination(destination, overwrite=overwrite)
    temporary_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            newline=newline,
            dir=destination.parent,
            prefix=f".{destination.name}.",
            suffix=".tmp",
            delete=False,
        ) as temporary_file:
            temporary_file.write(content)
            temporary_path = Path(temporary_file.name)

        if not overwrite and destination.exists():
            raise FileExistsError(f"report destination already exists: {destination}")
        os.replace(temporary_path, destination)
        temporary_path = None
    finally:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)


def _validate_destination(destination: Path, *, overwrite: bool) -> None:
    if destination.exists():
        if destination.is_dir():
            raise IsADirectoryError(f"report destination is a directory: {destination}")
        if not overwrite:
            raise FileExistsError(f"report destination already exists: {destination}")

    parent = destination.parent
    if not parent.exists():
        raise FileNotFoundError(f"report directory does not exist: {parent}")
    if not parent.is_dir():
        raise NotADirectoryError(f"report parent is not a directory: {parent}")


def _normalized_path(path: Path) -> str:
    return os.path.normcase(str(path.resolve(strict=False)))

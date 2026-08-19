from dataclasses import FrozenInstanceError
from datetime import time, timedelta, timezone
from pathlib import Path

import pytest

from login_log_analyzer.brute_force import BruteForceDetector
from login_log_analyzer.linux_authentication import LinuxAuthenticationParser
from login_log_analyzer.linux_file_analysis import (
    LinuxLogAnalysisResult,
    LinuxLogFileAnalyzer,
    LinuxLogParseError,
)
from login_log_analyzer.off_hours import OffHoursLoginDetector
from login_log_analyzer.password_spray import PasswordSprayDetector
from login_log_analyzer.success_after_failures import (
    SuccessfulLoginAfterFailuresDetector,
)


def create_analyzer(
    *,
    brute_force_threshold: int = 3,
    password_spray_threshold: int = 3,
) -> LinuxLogFileAnalyzer:
    return LinuxLogFileAnalyzer(
        parser=LinuxAuthenticationParser(year=2026, timezone_info=timezone.utc),
        brute_force_detector=BruteForceDetector(
            failure_threshold=brute_force_threshold,
            window=timedelta(minutes=5),
        ),
        off_hours_detector=OffHoursLoginDetector(
            allowed_weekdays={0, 1, 2, 3, 4, 5, 6},
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
    )


def write_log(path: Path, lines: list[str]) -> None:
    path.write_text("\n".join(lines), encoding="utf-8")


def test_analyzes_empty_file(tmp_path: Path) -> None:
    log_path = tmp_path / "empty.log"
    log_path.write_text("", encoding="utf-8")

    result = create_analyzer().analyze(log_path)

    assert result.total_lines == 0
    assert result.parsed_event_count == 0
    assert result.unsupported_line_count == 0
    assert result.parse_error_count == 0
    assert result.brute_force_findings == ()
    assert result.off_hours_findings == ()
    assert result.password_spray_findings == ()
    assert result.successful_login_after_failures_findings == ()


def test_analyzes_file_with_only_unsupported_lines(tmp_path: Path) -> None:
    log_path = tmp_path / "unsupported.log"
    write_log(
        log_path,
        [
            "Aug 18 09:15:00 host sudo: analyst : COMMAND=/usr/bin/id",
            "Aug 18 09:16:00 host sshd[10]: Disconnected from user analyst",
        ],
    )

    result = create_analyzer().analyze(log_path)

    assert result.total_lines == 2
    assert result.parsed_event_count == 0
    assert result.unsupported_line_count == 2
    assert result.parse_error_count == 0
    assert result.brute_force_findings == ()
    assert result.off_hours_findings == ()
    assert result.password_spray_findings == ()
    assert result.successful_login_after_failures_findings == ()


def test_mixed_file_counts_lines_and_continues_after_parse_error(
    tmp_path: Path,
) -> None:
    log_path = tmp_path / "mixed.log"
    write_log(
        log_path,
        [
            "Aug 18 09:15:00 host sudo: analyst : COMMAND=/usr/bin/id",
            "Aug 18 09:16:00 host sshd[10]: "
            "Failed password for admin from INVALID-IP port 50000 ssh2",
            "Aug 18 09:17:00 host sshd[10]: "
            "Accepted password for analyst from 192.0.2.25 port 50001 ssh2",
            "Aug 18 09:18:00 host sshd[10]: "
            "Failed password for invalid user Visitor "
            "from 192.0.2.25 port 50002 ssh2",
        ],
    )

    result = create_analyzer().analyze(log_path)

    assert result.total_lines == 4
    assert result.parsed_event_count == 2
    assert result.unsupported_line_count == 1
    assert result.parse_error_count == 1
    assert result.parse_errors == (
        LinuxLogParseError(
            line_number=2,
            message="invalid source IP in Linux SSH authentication message",
        ),
    )


def test_complete_pipeline_produces_all_detector_findings(tmp_path: Path) -> None:
    log_path = tmp_path / "attack.log"
    write_log(
        log_path,
        [
            "Aug 18 03:00:00 host sshd[10]: "
            "Failed password for admin from 192.0.2.50 port 50000 ssh2",
            "Aug 18 03:01:00 host sshd[10]: "
            "Failed password for admin from 192.0.2.50 port 50001 ssh2",
            "Aug 18 03:02:00 host sshd[10]: "
            "Failed password for admin from 192.0.2.50 port 50002 ssh2",
            "Aug 18 03:03:00 host sshd[10]: "
            "Failed password for user1 from 192.0.2.50 port 50003 ssh2",
            "Aug 18 03:04:00 host sshd[10]: "
            "Failed password for invalid user user2 "
            "from 192.0.2.50 port 50004 ssh2",
            "Aug 18 03:05:00 host sshd[10]: "
            "Accepted password for analyst from 192.0.2.60 port 50005 ssh2",
        ],
    )

    result = create_analyzer().analyze(log_path)

    assert result.total_lines == 6
    assert result.parsed_event_count == 6
    assert result.parse_error_count == 0
    assert len(result.brute_force_findings) == 1
    assert result.brute_force_findings[0].username == "admin"
    assert len(result.password_spray_findings) == 1
    assert result.password_spray_findings[0].usernames == (
        "admin",
        "user1",
        "user2",
    )
    assert len(result.off_hours_findings) == 1
    assert result.off_hours_findings[0].username == "analyst"


def test_analyzer_uses_supplied_detector_configuration(tmp_path: Path) -> None:
    log_path = tmp_path / "configured.log"
    write_log(
        log_path,
        [
            "Aug 18 09:00:00 host sshd[10]: "
            "Failed password for admin from 192.0.2.50 port 50000 ssh2",
            "Aug 18 09:01:00 host sshd[10]: "
            "Failed password for admin from 192.0.2.50 port 50001 ssh2",
            "Aug 18 09:02:00 host sshd[10]: "
            "Failed password for user1 from 192.0.2.50 port 50002 ssh2",
            "Aug 18 09:03:00 host sshd[10]: "
            "Failed password for user2 from 192.0.2.50 port 50003 ssh2",
        ],
    )

    result = create_analyzer(
        brute_force_threshold=5,
        password_spray_threshold=5,
    ).analyze(log_path)

    assert result.brute_force_findings == ()
    assert result.password_spray_findings == ()


def test_parser_year_and_timezone_remain_explicit(tmp_path: Path) -> None:
    log_path = tmp_path / "historical.log"
    write_log(
        log_path,
        [
            "Dec 31 03:00:00 host sshd[10]: "
            "Accepted password for analyst from 192.0.2.50 port 50000 ssh2"
        ],
    )
    analyzer = LinuxLogFileAnalyzer(
        parser=LinuxAuthenticationParser(
            year=2040,
            timezone_info=timezone(timedelta(hours=-3)),
        ),
        brute_force_detector=BruteForceDetector(
            failure_threshold=3,
            window=timedelta(minutes=5),
        ),
        off_hours_detector=OffHoursLoginDetector(
            allowed_weekdays={0, 1, 2, 3, 4, 5, 6},
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

    result = analyzer.analyze(log_path)

    assert result.off_hours_findings[0].timestamp.year == 2040
    assert result.off_hours_findings[0].timestamp.utcoffset() == timedelta(hours=-3)


def test_pipeline_detects_successful_login_after_failures(tmp_path: Path) -> None:
    log_path = tmp_path / "success-after-failures.log"
    write_log(
        log_path,
        [
            "Aug 18 09:00:00 host sshd[10]: "
            "Failed password for admin from 192.0.2.50 port 50000 ssh2",
            "Aug 18 09:01:00 host sshd[10]: "
            "Failed password for admin from 192.0.2.50 port 50001 ssh2",
            "Aug 18 09:02:00 host sshd[10]: "
            "Failed password for admin from 192.0.2.50 port 50002 ssh2",
            "Aug 18 09:03:00 host sshd[10]: "
            "Accepted password for admin from 192.0.2.50 port 50003 ssh2",
        ],
    )

    result = create_analyzer().analyze(log_path)

    assert len(result.successful_login_after_failures_findings) == 1
    finding = result.successful_login_after_failures_findings[0]
    assert finding.username == "admin"
    assert finding.failure_count == 3


def test_reads_crlf_and_final_line_without_newline(tmp_path: Path) -> None:
    log_path = tmp_path / "line-endings.log"
    log_path.write_bytes(
        b"Aug 18 09:00:00 host sshd[10]: Accepted password for analyst "
        b"from 192.0.2.50 port 50000 ssh2\r\n"
        b"Aug 18 09:01:00 host sudo: analyst : COMMAND=/usr/bin/id"
    )

    result = create_analyzer().analyze(log_path)

    assert result.total_lines == 2
    assert result.parsed_event_count == 1
    assert result.unsupported_line_count == 1


def test_missing_file_error_propagates(tmp_path: Path) -> None:
    missing_path = tmp_path / "missing.log"

    with pytest.raises(FileNotFoundError):
        create_analyzer().analyze(missing_path)


def test_directory_path_error_propagates(tmp_path: Path) -> None:
    with pytest.raises((IsADirectoryError, PermissionError)):
        create_analyzer().analyze(tmp_path)


def test_invalid_utf8_error_propagates(tmp_path: Path) -> None:
    log_path = tmp_path / "invalid-utf8.log"
    log_path.write_bytes(b"\xff\xfe")

    with pytest.raises(UnicodeDecodeError):
        create_analyzer().analyze(log_path)


def test_result_and_nested_collections_are_immutable(tmp_path: Path) -> None:
    log_path = tmp_path / "malformed.log"
    write_log(
        log_path,
        [
            "Aug 18 09:16:00 host sshd[10]: "
            "Failed password for admin from INVALID-IP port 50000 ssh2"
        ],
    )

    result = create_analyzer().analyze(log_path)

    assert isinstance(result, LinuxLogAnalysisResult)
    assert isinstance(result.parse_errors, tuple)
    assert isinstance(result.brute_force_findings, tuple)
    assert isinstance(result.off_hours_findings, tuple)
    assert isinstance(result.password_spray_findings, tuple)
    assert isinstance(result.successful_login_after_failures_findings, tuple)
    with pytest.raises(FrozenInstanceError):
        result.total_lines = 2

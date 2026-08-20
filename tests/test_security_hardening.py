import csv
import json
import subprocess
from datetime import datetime, timezone
from io import StringIO
from ipaddress import ip_address
from pathlib import Path

import pytest

from login_log_analyzer.account_lifecycle import (
    AccountLifecycleAction,
    AccountLifecycleEvent,
)
from login_log_analyzer.authentication import AuthenticationPlatform
from login_log_analyzer.brute_force import BruteForceFinding
from login_log_analyzer.cli import (
    main,
    render_account_lifecycle_events,
    render_brute_force_findings,
)
from login_log_analyzer.linux_file_analysis import LinuxLogAnalysisResult
from login_log_analyzer.password_spray import PasswordSprayFinding
from login_log_analyzer.presentation_security import (
    escape_control_characters,
    neutralize_csv_text,
)
from login_log_analyzer.reporting import export_csv_report, export_json_report
from login_log_analyzer.windows_native_analysis import (
    MAX_WINDOWS_NATIVE_EVENT_LIMIT,
    WindowsEventLogCollector,
    WindowsNativeQueryError,
)


TIMESTAMP = datetime(2026, 8, 19, 12, 0, tzinfo=timezone.utc)


def result_with(
    *,
    brute_force: tuple[BruteForceFinding, ...] = (),
    password_spray: tuple[PasswordSprayFinding, ...] = (),
) -> LinuxLogAnalysisResult:
    return LinuxLogAnalysisResult(
        total_lines=0,
        parsed_event_count=0,
        unsupported_line_count=0,
        parse_errors=(),
        brute_force_findings=brute_force,
        off_hours_findings=(),
        password_spray_findings=password_spray,
        successful_login_after_failures_findings=(),
        multiple_source_ips_findings=(),
    )


def brute_force(username: str) -> BruteForceFinding:
    return BruteForceFinding(
        username=username,
        source_ip=ip_address("192.0.2.10"),
        first_observed=TIMESTAMP,
        last_observed=TIMESTAMP,
        failure_count=5,
    )


def read_csv(path: Path) -> list[dict[str, str]]:
    with path.open("r", encoding="utf-8", newline="") as report_file:
        return list(csv.DictReader(report_file))


def test_terminal_esc_bel_and_newline_are_neutralized() -> None:
    username = "\x1b[2J\x1b]0;fake-title\x07admin\nforged"
    output = StringIO()

    render_brute_force_findings((brute_force(username),), output)

    rendered = output.getvalue()
    assert "\x1b" not in rendered
    assert "\x07" not in rendered
    assert "admin\nforged" not in rendered
    assert r"\x1b[2J\x1b]0;fake-title\x07admin\x0aforged" in rendered


def test_terminal_unicode_controls_are_neutralized_without_changing_unicode() -> None:
    assert escape_control_characters("José\u202eAdmin") == r"José\u202eAdmin"


def test_account_lifecycle_terminal_fields_are_neutralized() -> None:
    event = AccountLifecycleEvent(
        timestamp=TIMESTAMP,
        username="user\nforged",
        action=AccountLifecycleAction.CREATED,
        platform=AuthenticationPlatform.WINDOWS,
        target_domain="\x1b[2JLAB",
        subject_username="actor\x07",
        subject_domain="DOMAIN\rforged",
        recording_computer="DC01\x7f",
    )
    output = StringIO()

    render_account_lifecycle_events((event,), output)

    rendered = output.getvalue()
    assert "\x1b" not in rendered
    assert "\x07" not in rendered
    assert "user\nforged" not in rendered
    for escaped in (r"user\x0aforged", r"\x1b[2JLAB", r"actor\x07"):
        assert escaped in rendered
    assert event.username == "user\nforged"
    assert event.target_domain == "\x1b[2JLAB"


@pytest.mark.parametrize("trigger", ["=", "+", "-", "@"])
def test_csv_formula_prefixes_are_neutralized(
    tmp_path: Path,
    trigger: str,
) -> None:
    destination = tmp_path / "findings.csv"
    export_csv_report(
        result_with(brute_force=(brute_force(f"{trigger}SUM(1,1)"),)),
        destination,
    )

    username = read_csv(destination)[0]["username"]
    assert username == f"'{trigger}SUM(1,1)"
    assert not username.startswith(trigger)


def test_password_spray_username_list_neutralizes_formula_and_controls(
    tmp_path: Path,
) -> None:
    destination = tmp_path / "findings.csv"
    finding = PasswordSprayFinding(
        source_ip=ip_address("192.0.2.20"),
        first_observed=TIMESTAMP,
        last_observed=TIMESTAMP,
        distinct_username_count=2,
        usernames=("=CMD()", "safe\nname"),
    )

    export_csv_report(result_with(password_spray=(finding,)), destination)

    assert read_csv(destination)[0]["usernames"] == r"'=CMD();safe\x0aname"


def test_safe_csv_text_remains_unchanged() -> None:
    assert neutralize_csv_text("José.Admin") == "José.Admin"


def test_json_preserves_original_domain_value(tmp_path: Path) -> None:
    destination = tmp_path / "report.json"
    username = "\x1b[2J=Admin"

    export_json_report(
        result_with(brute_force=(brute_force(username),)),
        destination,
    )

    document = json.loads(destination.read_text(encoding="utf-8"))
    assert document["findings"]["brute_force"][0]["username"] == username


def test_oversized_windows_json_is_rejected_cleanly(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    path = tmp_path / "oversized.json"
    path.write_text("[{},{}]", encoding="utf-8")
    monkeypatch.setattr(
        "login_log_analyzer.windows_json_analysis.MAX_WINDOWS_JSON_FILE_BYTES",
        4,
    )

    assert main(["analyze-windows", str(path)]) == 1
    captured = capsys.readouterr()
    assert "exceeds the 4-byte limit" in captured.err
    assert "Traceback" not in captured.err


def test_oversized_linux_log_is_rejected_cleanly(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    path = tmp_path / "oversized.log"
    path.write_text("12345", encoding="utf-8")
    monkeypatch.setattr(
        "login_log_analyzer.linux_file_analysis.MAX_LINUX_LOG_FILE_BYTES",
        4,
    )

    assert main(
        [
            "analyze-linux",
            str(path),
            "--year",
            "2026",
            "--timezone-offset=-03:00",
        ]
    ) == 1
    captured = capsys.readouterr()
    assert "exceeds the 4-byte limit" in captured.err
    assert "Traceback" not in captured.err


def test_deeply_nested_windows_json_is_rejected_cleanly(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    path = tmp_path / "deep.json"
    path.write_text("[" * 5_000 + "]" * 5_000, encoding="utf-8")

    assert main(["analyze-windows", str(path)]) == 1
    captured = capsys.readouterr()
    assert "nesting is too deep" in captured.err
    assert "Traceback" not in captured.err


def test_native_event_limit_has_upper_bound(
    capsys: pytest.CaptureFixture[str],
) -> None:
    with pytest.raises(ValueError, match=str(MAX_WINDOWS_NATIVE_EVENT_LIMIT)):
        WindowsEventLogCollector().collect(MAX_WINDOWS_NATIVE_EVENT_LIMIT + 1)

    with pytest.raises(SystemExit) as error:
        main(
            [
                "analyze-windows-native",
                "--max-events",
                str(MAX_WINDOWS_NATIVE_EVENT_LIMIT + 1),
            ]
        )
    assert error.value.code == 2
    assert "Traceback" not in capsys.readouterr().err


def test_native_stderr_is_control_safe_and_bounded(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    detail = "\x1b]0;fake\x07denied\nforged" + "x" * 2_000

    def run(command: list[str], **options: object) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(command, 5, stdout="", stderr=detail)

    monkeypatch.setattr("login_log_analyzer.windows_native_analysis.sys.platform", "win32")
    monkeypatch.setattr("login_log_analyzer.windows_native_analysis.subprocess.run", run)

    with pytest.raises(WindowsNativeQueryError) as error:
        WindowsEventLogCollector().collect()

    message = str(error.value)
    assert "\x1b" not in message
    assert "\x07" not in message
    assert "denied\nforged" not in message
    assert r"\x1b]0;fake\x07denied\x0aforged" in message
    assert message.endswith("... [truncated]")


def test_hostile_native_error_is_safe_at_cli_boundary(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    class FailingAnalyzer:
        def analyze(self, max_events: int) -> object:
            raise WindowsNativeQueryError("\x1b[2Jdenied\nforged")

    monkeypatch.setattr(
        "login_log_analyzer.cli.create_windows_native_analyzer",
        lambda arguments: FailingAnalyzer(),
    )

    assert main(["analyze-windows-native"]) == 1
    captured = capsys.readouterr()
    assert "\x1b" not in captured.err
    assert "denied\nforged" not in captured.err
    assert r"\x1b[2Jdenied\x0aforged" in captured.err
    assert "Traceback" not in captured.err


def test_report_temporary_file_is_removed_after_link_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    destination = tmp_path / "report.json"

    def fail_link(source: Path, target: Path) -> None:
        raise PermissionError("denied")

    monkeypatch.setattr("login_log_analyzer.reporting.os.link", fail_link)

    with pytest.raises(PermissionError):
        export_json_report(result_with(), destination)

    assert list(tmp_path.iterdir()) == []

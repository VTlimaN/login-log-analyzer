import json
from datetime import datetime
from pathlib import Path

import pytest

from login_log_analyzer.account_lockout import AccountLockoutEvent
from login_log_analyzer.authentication import AuthenticationPlatform
from login_log_analyzer.cli import main
from login_log_analyzer.windows_native_analysis import WindowsNativeAnalysisResult


def write_document(path: Path, records: list[dict[str, object]]) -> None:
    path.write_text(json.dumps(records), encoding="utf-8")


def lockout_record(**changes: object) -> dict[str, object]:
    record: dict[str, object] = {
        "event_id": 4740,
        "timestamp": "2026-08-19T10:30:00-03:00",
        "username": "DemoUser",
        "target_domain": "DEMO",
        "caller_computer": "WS-042",
        "recording_computer": "DC01.demo.invalid",
    }
    record.update(changes)
    return record


def test_windows_json_displays_lockout_count_and_details(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    path = tmp_path / "lockout.json"
    write_document(path, [lockout_record()])

    exit_code = main(["analyze-windows", str(path)])

    assert exit_code == 0
    output = capsys.readouterr().out
    assert "Eventos de autenticação: 0" in output
    assert "Bloqueios de conta: 1" in output
    assert "Bloqueios de conta observados" in output
    assert "DemoUser | 2026-08-19T10:30:00-03:00" in output
    assert "domínio: DEMO" in output
    assert "computador de origem: WS-042" in output
    assert "computador de registro: DC01.demo.invalid" in output


def test_windows_json_displays_missing_optional_context(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    path = tmp_path / "missing-context.json"
    write_document(
        path,
        [
            lockout_record(
                target_domain=None,
                caller_computer=None,
                recording_computer=None,
            )
        ],
    )

    assert main(["analyze-windows", str(path)]) == 0

    output = capsys.readouterr().out
    assert "domínio: N/A" in output
    assert "computador de origem: N/A" in output
    assert "computador de registro: N/A" in output


def test_windows_json_mixed_authentication_and_lockout_returns_success(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    path = tmp_path / "mixed.json"
    write_document(
        path,
        [
            {
                "event_id": 4625,
                "timestamp": "2026-08-19T10:29:00-03:00",
                "username": "DemoUser",
                "source_ip": "192.0.2.25",
            },
            lockout_record(),
        ],
    )

    assert main(["analyze-windows", str(path)]) == 0

    output = capsys.readouterr().out
    assert "Eventos de autenticação: 1" in output
    assert "Bloqueios de conta: 1" in output


class NativeLockoutAnalyzer:
    def analyze(self, max_events: int) -> WindowsNativeAnalysisResult:
        return WindowsNativeAnalysisResult(
            collected_record_count=2,
            parsed_event_count=1,
            unsupported_record_count=0,
            record_errors=(),
            brute_force_findings=(),
            off_hours_findings=(),
            password_spray_findings=(),
            successful_login_after_failures_findings=(),
            multiple_source_ips_findings=(),
            account_lockout_events=(
                AccountLockoutEvent(
                    timestamp=datetime.fromisoformat(
                        "2026-08-19T10:30:00-03:00"
                    ),
                    username="NativeUser",
                    platform=AuthenticationPlatform.WINDOWS,
                    target_domain="DEMO",
                    caller_computer="WS-043",
                    recording_computer="DC02.demo.invalid",
                ),
            ),
        )


def test_windows_native_displays_lockout_and_returns_success(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(
        "login_log_analyzer.cli.create_windows_native_analyzer",
        lambda arguments: NativeLockoutAnalyzer(),
    )

    exit_code = main(["analyze-windows-native"])

    assert exit_code == 0
    output = capsys.readouterr().out
    assert "Eventos de autenticação: 1" in output
    assert "Bloqueios de conta: 1" in output
    assert "NativeUser | 2026-08-19T10:30:00-03:00" in output
    assert "computador de origem: WS-043" in output


def test_linux_cli_remains_free_of_windows_lockout_output(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    path = tmp_path / "empty.log"
    path.write_text("", encoding="utf-8")

    exit_code = main(
        [
            "analyze-linux",
            str(path),
            "--year",
            "2026",
            "--timezone-offset",
            "+00:00",
        ]
    )

    assert exit_code == 0
    assert "Bloqueios de conta" not in capsys.readouterr().out

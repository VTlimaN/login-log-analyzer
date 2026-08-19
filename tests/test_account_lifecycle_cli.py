import json
from datetime import datetime
from pathlib import Path

import pytest

from login_log_analyzer.account_lifecycle import (
    AccountLifecycleAction,
    AccountLifecycleEvent,
)
from login_log_analyzer.authentication import AuthenticationPlatform
from login_log_analyzer.cli import main
from login_log_analyzer.windows_native_analysis import WindowsNativeAnalysisResult


def lifecycle_record(**changes: object) -> dict[str, object]:
    record: dict[str, object] = {
        "event_id": 4720,
        "timestamp": "2026-08-19T14:00:00-03:00",
        "username": "LifecycleUser",
        "target_domain": "LAB",
        "subject_username": "Administrator",
        "subject_domain": "LAB",
        "recording_computer": "DC01.lab.invalid",
    }
    record.update(changes)
    return record


def write_document(path: Path, records: list[dict[str, object]]) -> None:
    path.write_text(json.dumps(records), encoding="utf-8")


def test_windows_json_displays_lifecycle_count_action_and_context(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    path = tmp_path / "lifecycle.json"
    write_document(path, [lifecycle_record()])

    exit_code = main(["analyze-windows", str(path)])

    assert exit_code == 0
    output = capsys.readouterr().out
    assert "Eventos de autenticação: 0" in output
    assert "Eventos de ciclo de vida de conta: 1" in output
    assert "Eventos de ciclo de vida de conta observados" in output
    assert "criada | LifecycleUser | 2026-08-19T14:00:00-03:00" in output
    assert "domínio alvo: LAB" in output
    assert "ator: Administrator" in output
    assert "domínio do ator: LAB" in output
    assert "computador de registro: DC01.lab.invalid" in output


def test_windows_json_displays_all_actions_and_missing_context(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    path = tmp_path / "actions.json"
    records = [
        lifecycle_record(
            event_id=event_id,
            target_domain=None,
            subject_username=None,
            subject_domain=None,
            recording_computer=None,
        )
        for event_id in (4720, 4722, 4725, 4726, 4767)
    ]
    write_document(path, records)

    assert main(["analyze-windows", str(path)]) == 0

    output = capsys.readouterr().out
    assert "Eventos de ciclo de vida de conta: 5" in output
    for action in ("criada", "habilitada", "desabilitada", "excluída", "desbloqueada"):
        assert action in output
    assert "domínio alvo: N/A" in output
    assert "ator: N/A" in output


def test_windows_json_mixes_lifecycle_observation_and_heuristic_finding(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    path = tmp_path / "mixed.json"
    failures = [
        {
            "event_id": 4625,
            "timestamp": f"2026-08-19T14:0{minute}:00-03:00",
            "username": "TargetUser",
            "source_ip": "192.0.2.25",
        }
        for minute in range(5)
    ]
    write_document(path, [*failures, lifecycle_record()])

    assert main(["analyze-windows", str(path)]) == 0

    output = capsys.readouterr().out
    assert "Eventos de autenticação: 5" in output
    assert "Eventos de ciclo de vida de conta: 1" in output
    assert "Achados de força bruta: 1" in output


class NativeLifecycleAnalyzer:
    def analyze(self, max_events: int) -> WindowsNativeAnalysisResult:
        return WindowsNativeAnalysisResult(
            collected_record_count=1,
            parsed_event_count=0,
            unsupported_record_count=0,
            record_errors=(),
            brute_force_findings=(),
            off_hours_findings=(),
            password_spray_findings=(),
            successful_login_after_failures_findings=(),
            multiple_source_ips_findings=(),
            account_lockout_events=(),
            account_lifecycle_events=(
                AccountLifecycleEvent(
                    timestamp=datetime.fromisoformat(
                        "2026-08-19T14:00:00-03:00"
                    ),
                    username="NativeUser",
                    action=AccountLifecycleAction.UNLOCKED,
                    platform=AuthenticationPlatform.WINDOWS,
                    subject_username="Operator",
                ),
            ),
        )


def test_windows_native_displays_lifecycle_observation(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(
        "login_log_analyzer.cli.create_windows_native_analyzer",
        lambda arguments: NativeLifecycleAnalyzer(),
    )

    assert main(["analyze-windows-native"]) == 0

    output = capsys.readouterr().out
    assert "Eventos de ciclo de vida de conta: 1" in output
    assert "desbloqueada | NativeUser" in output
    assert "ator: Operator" in output


def test_linux_cli_has_no_windows_lifecycle_output(
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
    assert "ciclo de vida" not in capsys.readouterr().out

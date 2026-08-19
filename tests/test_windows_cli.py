import json
from pathlib import Path

import pytest

from login_log_analyzer.cli import main


def write_document(path: Path, document: object) -> None:
    path.write_text(json.dumps(document), encoding="utf-8")


def create_record(**changes: object) -> dict[str, object]:
    record: dict[str, object] = {
        "event_id": 4624,
        "timestamp": "2026-08-18T09:00:00-03:00",
        "username": "Analyst",
        "source_ip": "192.0.2.25",
    }
    record.update(changes)
    return record


def windows_arguments(path: Path, *options: str) -> list[str]:
    return ["analyze-windows", str(path), *options]


def test_analyze_windows_help_documents_detector_options_without_temporal_context(
    capsys: pytest.CaptureFixture[str],
) -> None:
    with pytest.raises(SystemExit) as error:
        main(["analyze-windows", "--help"])

    assert error.value.code == 0
    output = capsys.readouterr().out
    assert "--brute-force-threshold" in output
    assert "--brute-force-window-minutes" in output
    assert "--password-spray-threshold" in output
    assert "--password-spray-window-minutes" in output
    assert "--allowed-weekdays" in output
    assert "mon,tue,wed,thu,fri" in output
    assert "--allowed-start" in output
    assert "--allowed-end" in output
    assert "--year" not in output
    assert "--timezone-offset" not in output


def test_analyzes_valid_empty_array(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    path = tmp_path / "empty.json"
    write_document(path, [])

    exit_code = main(windows_arguments(path))

    assert exit_code == 0
    output = capsys.readouterr().out
    assert f"Arquivo analisado: {path}" in output
    assert "Resumo Windows" in output
    assert "Registros totais: 0" in output
    assert "Eventos de autenticação: 0" in output
    assert "Registros não suportados: 0" in output
    assert "Erros de registro: 0" in output


def test_analyzes_windows_file_without_findings(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    path = tmp_path / "normal.json"
    write_document(path, [create_record()])

    exit_code = main(windows_arguments(path))

    assert exit_code == 0
    output = capsys.readouterr().out
    assert "Registros totais: 1" in output
    assert "Eventos de autenticação: 1" in output
    assert "Achados de força bruta: 0" in output
    assert "Achados fora do horário: 0" in output
    assert "Achados de password spraying: 0" in output


def test_returns_success_and_displays_windows_brute_force_finding(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    path = tmp_path / "brute-force.json"
    write_document(
        path,
        [
            create_record(
                event_id=4625,
                timestamp=f"2026-08-18T09:0{minute}:00-03:00",
                username="Administrator",
                source_ip="198.51.100.20",
            )
            for minute in range(5)
        ],
    )

    exit_code = main(windows_arguments(path))

    assert exit_code == 0
    output = capsys.readouterr().out
    assert "Força bruta" in output
    assert "Administrator | 198.51.100.20" in output
    assert "2026-08-18T09:00:00-03:00" in output
    assert "2026-08-18T09:04:00-03:00" in output
    assert "falhas: 5" in output


def test_displays_windows_off_hours_finding_with_missing_source_ip(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    path = tmp_path / "off-hours.json"
    write_document(
        path,
        [
            create_record(
                timestamp="2026-08-18T03:00:00-03:00",
                username="NightAnalyst",
                source_ip=None,
            )
        ],
    )

    assert main(windows_arguments(path)) == 0

    output = capsys.readouterr().out
    assert "Logins fora do horário" in output
    assert "NightAnalyst | 2026-08-18T03:00:00-03:00" in output
    assert "IP: N/A" in output
    assert "plataforma: windows" in output


def test_displays_windows_password_spray_finding(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    path = tmp_path / "password-spray.json"
    write_document(
        path,
        [
            create_record(
                event_id=4625,
                timestamp=f"2026-08-18T09:0{minute}:00+00:00",
                username=f"User{minute}",
                source_ip="203.0.113.30",
            )
            for minute in range(5)
        ],
    )

    assert main(windows_arguments(path)) == 0

    output = capsys.readouterr().out
    assert "Password spraying" in output
    assert "203.0.113.30" in output
    assert "usernames distintos: 5" in output
    assert "usernames: User0, User1, User2, User3, User4" in output


def test_reports_recoverable_record_error_without_raw_record(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    path = tmp_path / "record-error.json"
    raw_marker = "SENSITIVE-INVALID-IP"
    write_document(path, [create_record(source_ip=raw_marker)])

    exit_code = main(windows_arguments(path))

    assert exit_code == 0
    output = capsys.readouterr().out
    assert "Erros de registro: 1" in output
    assert "Registro 1: invalid source IP" in output
    assert raw_marker not in output


def test_displays_unsupported_record_count(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    path = tmp_path / "unsupported.json"
    write_document(path, [{"event_id": 4634}])

    assert main(windows_arguments(path)) == 0

    output = capsys.readouterr().out
    assert "Registros totais: 1" in output
    assert "Registros não suportados: 1" in output
    assert "Erros de registro: 0" in output


def test_missing_windows_file_returns_operational_error(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    path = tmp_path / "missing.json"

    exit_code = main(windows_arguments(path))

    captured = capsys.readouterr()
    assert exit_code == 1
    assert captured.out == ""
    assert "Erro ao analisar" in captured.err
    assert "Traceback" not in captured.err


def test_windows_directory_path_returns_operational_error(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    exit_code = main(windows_arguments(tmp_path))

    captured = capsys.readouterr()
    assert exit_code == 1
    assert captured.out == ""
    assert "Erro ao analisar" in captured.err
    assert "Traceback" not in captured.err


def test_invalid_windows_utf8_returns_operational_error(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    path = tmp_path / "invalid-utf8.json"
    path.write_bytes(b"\xff\xfe")

    exit_code = main(windows_arguments(path))

    captured = capsys.readouterr()
    assert exit_code == 1
    assert captured.out == ""
    assert "Erro ao analisar" in captured.err
    assert "Traceback" not in captured.err


def test_invalid_json_syntax_returns_operational_error_without_traceback(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    path = tmp_path / "invalid.json"
    path.write_text('[{"event_id": 4624}', encoding="utf-8")

    exit_code = main(windows_arguments(path))

    captured = capsys.readouterr()
    assert exit_code == 1
    assert captured.out == ""
    assert "Erro ao analisar" in captured.err
    assert "Traceback" not in captured.err


def test_invalid_json_root_returns_operational_error_without_traceback(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    path = tmp_path / "invalid-root.json"
    write_document(path, {"events": []})

    exit_code = main(windows_arguments(path))

    captured = capsys.readouterr()
    assert exit_code == 1
    assert captured.out == ""
    assert "top-level JSON value must be an array" in captured.err
    assert "Traceback" not in captured.err


@pytest.mark.parametrize(
    ("option", "value", "message"),
    [
        ("--brute-force-threshold", "0", "failure_threshold"),
        ("--brute-force-window-minutes", "0", "window"),
        ("--password-spray-threshold", "1", "username_threshold"),
        ("--password-spray-window-minutes", "-1", "window"),
        ("--allowed-end", "08:00", "start_time and end_time"),
    ],
)
def test_invalid_windows_detector_configuration_returns_exit_code_two(
    tmp_path: Path,
    option: str,
    value: str,
    message: str,
    capsys: pytest.CaptureFixture[str],
) -> None:
    exit_code = main(windows_arguments(tmp_path / "events.json", option, value))

    captured = capsys.readouterr()
    assert exit_code == 2
    assert message in captured.err
    assert "Traceback" not in captured.err

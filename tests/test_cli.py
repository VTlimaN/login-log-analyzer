from pathlib import Path

import pytest

from login_log_analyzer.cli import main


def write_log(path: Path, lines: list[str]) -> None:
    path.write_text("\n".join(lines), encoding="utf-8")


def linux_arguments(path: Path, *options: str) -> list[str]:
    return [
        "analyze-linux",
        str(path),
        "--year",
        "2026",
        "--timezone-offset",
        "+00:00",
        *options,
    ]


def test_top_level_help(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as error:
        main(["--help"])

    assert error.value.code == 0
    output = capsys.readouterr().out
    assert "analyze-linux" in output


def test_analyze_linux_help_documents_required_and_configurable_options(
    capsys: pytest.CaptureFixture[str],
) -> None:
    with pytest.raises(SystemExit) as error:
        main(["analyze-linux", "--help"])

    assert error.value.code == 0
    output = capsys.readouterr().out
    assert "--year" in output
    assert "--timezone-offset" in output
    assert "--brute-force-threshold" in output
    assert "--password-spray-threshold" in output
    assert "--allowed-weekdays" in output
    assert "mon,tue,wed,thu,fri" in output
    assert "default: None" not in output


def test_analyzes_file_without_findings(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    log_path = tmp_path / "normal.log"
    write_log(
        log_path,
        [
            "Aug 18 09:00:00 host sshd[10]: "
            "Accepted password for analyst from 192.0.2.10 port 50000 ssh2"
        ],
    )

    exit_code = main(linux_arguments(log_path))

    assert exit_code == 0
    output = capsys.readouterr().out
    assert f"Arquivo analisado: {log_path}" in output
    assert "Linhas totais: 1" in output
    assert "Eventos de autenticação: 1" in output
    assert "Achados de força bruta: 0" in output
    assert "Achados fora do horário: 0" in output
    assert "Achados de password spraying: 0" in output


def test_returns_success_and_displays_brute_force_finding(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    log_path = tmp_path / "brute-force.log"
    write_log(
        log_path,
        [
            f"Aug 18 09:0{minute}:00 host sshd[10]: "
            f"Failed password for Admin from 192.0.2.20 port {50000 + minute} ssh2"
            for minute in range(5)
        ],
    )

    exit_code = main(linux_arguments(log_path))

    assert exit_code == 0
    output = capsys.readouterr().out
    assert "Força bruta" in output
    assert "Admin | 192.0.2.20" in output
    assert "2026-08-18T09:00:00+00:00" in output
    assert "2026-08-18T09:04:00+00:00" in output
    assert "falhas: 5" in output


def test_displays_off_hours_finding(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    log_path = tmp_path / "off-hours.log"
    write_log(
        log_path,
        [
            "Aug 18 03:00:00 host sshd[10]: "
            "Accepted password for NightUser from 2001:db8::10 port 50000 ssh2"
        ],
    )

    assert main(linux_arguments(log_path, "--timezone-offset", "-03:00")) == 0

    output = capsys.readouterr().out
    assert "Logins fora do horário" in output
    assert "NightUser | 2026-08-18T03:00:00-03:00" in output
    assert "IP: 2001:db8::10" in output
    assert "plataforma: linux" in output


def test_displays_password_spray_finding(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    log_path = tmp_path / "password-spray.log"
    write_log(
        log_path,
        [
            f"Aug 18 09:0{minute}:00 host sshd[10]: "
            f"Failed password for User{minute} from 192.0.2.30 "
            f"port {50000 + minute} ssh2"
            for minute in range(5)
        ],
    )

    assert main(linux_arguments(log_path)) == 0

    output = capsys.readouterr().out
    assert "Password spraying" in output
    assert "192.0.2.30" in output
    assert "usernames distintos: 5" in output
    assert "usernames: User0, User1, User2, User3, User4" in output


def test_reports_parse_error_without_raw_log_content(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    log_path = tmp_path / "malformed.log"
    raw_marker = "SENSITIVE-INVALID-IP"
    write_log(
        log_path,
        [
            "Aug 18 09:00:00 host sshd[10]: "
            f"Failed password for admin from {raw_marker} port 50000 ssh2"
        ],
    )

    assert main(linux_arguments(log_path)) == 0

    output = capsys.readouterr().out
    assert "Erros de parsing: 1" in output
    assert "Linha 1: invalid source IP" in output
    assert raw_marker not in output


def test_missing_file_returns_operational_error(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    log_path = tmp_path / "missing.log"

    exit_code = main(linux_arguments(log_path))

    captured = capsys.readouterr()
    assert exit_code == 1
    assert captured.out == ""
    assert "Erro ao analisar" in captured.err
    assert str(log_path) in captured.err
    assert "Traceback" not in captured.err


def test_directory_path_returns_operational_error(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    exit_code = main(linux_arguments(tmp_path))

    captured = capsys.readouterr()
    assert exit_code == 1
    assert captured.out == ""
    assert "Erro ao analisar" in captured.err
    assert "Traceback" not in captured.err


@pytest.mark.parametrize(
    "offset",
    ["UTC", "03:00", "+3:00", "+24:00", "+01:60"],
)
def test_invalid_timezone_offset_is_a_usage_error(
    tmp_path: Path,
    offset: str,
    capsys: pytest.CaptureFixture[str],
) -> None:
    with pytest.raises(SystemExit) as error:
        main(linux_arguments(tmp_path / "log", "--timezone-offset", offset))

    assert error.value.code == 2
    captured = capsys.readouterr()
    assert "offset" in captured.err
    assert "Traceback" not in captured.err


@pytest.mark.parametrize("weekdays", ["", "mon,funday", "mon,,fri"])
def test_invalid_weekday_is_a_usage_error(
    tmp_path: Path,
    weekdays: str,
    capsys: pytest.CaptureFixture[str],
) -> None:
    with pytest.raises(SystemExit) as error:
        main(linux_arguments(tmp_path / "log", "--allowed-weekdays", weekdays))

    assert error.value.code == 2
    assert "weekday" in capsys.readouterr().err


@pytest.mark.parametrize("value", ["8:00", "24:00", "08:60", "8pm"])
def test_invalid_schedule_time_is_a_usage_error(
    tmp_path: Path,
    value: str,
    capsys: pytest.CaptureFixture[str],
) -> None:
    with pytest.raises(SystemExit) as error:
        main(linux_arguments(tmp_path / "log", "--allowed-start", value))

    assert error.value.code == 2
    assert "horário" in capsys.readouterr().err


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
def test_invalid_detector_configuration_returns_nonzero_without_traceback(
    tmp_path: Path,
    option: str,
    value: str,
    message: str,
    capsys: pytest.CaptureFixture[str],
) -> None:
    exit_code = main(linux_arguments(tmp_path / "log", option, value))

    captured = capsys.readouterr()
    assert exit_code == 2
    assert message in captured.err
    assert "Traceback" not in captured.err


def test_parser_uses_supplied_year(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    log_path = tmp_path / "historical.log"
    write_log(
        log_path,
        [
            "Aug 18 03:00:00 host sshd[10]: "
            "Accepted password for analyst from 192.0.2.40 port 50000 ssh2"
        ],
    )
    arguments = linux_arguments(log_path)
    arguments[arguments.index("2026")] = "2040"

    assert main(arguments) == 0

    assert "2040-08-18T03:00:00+00:00" in capsys.readouterr().out


def test_weekday_names_are_case_insensitive(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    log_path = tmp_path / "weekday.log"
    write_log(
        log_path,
        [
            "Aug 18 09:00:00 host sshd[10]: "
            "Accepted password for analyst from 192.0.2.50 port 50000 ssh2"
        ],
    )

    assert main(linux_arguments(log_path, "--allowed-weekdays", "TUE")) == 0

    assert "Achados fora do horário: 0" in capsys.readouterr().out

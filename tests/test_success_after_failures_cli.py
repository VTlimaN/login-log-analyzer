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


def failure(minute: int, *, username: str = "Admin") -> str:
    return (
        f"Aug 18 09:{minute:02d}:00 host sshd[10]: "
        f"Failed password for {username} from 192.0.2.25 "
        f"port {50000 + minute} ssh2"
    )


def success(minute: int, *, username: str = "Admin") -> str:
    return (
        f"Aug 18 09:{minute:02d}:00 host sshd[10]: "
        f"Accepted password for {username} from 192.0.2.25 "
        f"port {51000 + minute} ssh2"
    )


@pytest.mark.parametrize(
    "command",
    ["analyze-linux", "analyze-windows", "analyze-windows-native"],
)
def test_help_documents_success_after_failures_options(
    command: str,
    capsys: pytest.CaptureFixture[str],
) -> None:
    with pytest.raises(SystemExit) as error:
        main([command, "--help"])

    assert error.value.code == 0
    output = capsys.readouterr().out
    assert "--success-after-failures-threshold" in output
    assert "--success-after-failures-window-minutes" in output


def test_default_configuration_requires_five_failures(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    path = tmp_path / "below-default.log"
    write_log(path, [*(failure(minute) for minute in range(4)), success(4)])

    assert main(linux_arguments(path)) == 0
    assert "Achados de sucesso após falhas: 0" in capsys.readouterr().out


def test_finding_details_and_count_return_success(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    path = tmp_path / "finding.log"
    write_log(path, [*(failure(minute) for minute in range(5)), success(5)])

    exit_code = main(linux_arguments(path))

    assert exit_code == 0
    output = capsys.readouterr().out
    assert "Achados de sucesso após falhas: 1" in output
    assert "Login bem-sucedido após falhas repetidas" in output
    assert "Admin | 192.0.2.25" in output
    assert "primeira falha: 2026-08-18T09:00:00+00:00" in output
    assert "última falha: 2026-08-18T09:04:00+00:00" in output
    assert "sucesso: 2026-08-18T09:05:00+00:00" in output
    assert "falhas: 5" in output
    assert "plataforma: linux" in output


def test_custom_threshold_is_used(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    path = tmp_path / "custom-threshold.log"
    write_log(path, [failure(0), failure(1), success(2)])

    exit_code = main(
        linux_arguments(
            path,
            "--success-after-failures-threshold",
            "2",
        )
    )

    assert exit_code == 0
    assert "Achados de sucesso após falhas: 1" in capsys.readouterr().out


def test_custom_window_is_used(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    path = tmp_path / "custom-window.log"
    write_log(path, [failure(0), failure(6), success(7)])

    exit_code = main(
        linux_arguments(
            path,
            "--success-after-failures-threshold",
            "2",
            "--success-after-failures-window-minutes",
            "10",
        )
    )

    assert exit_code == 0
    assert "Achados de sucesso após falhas: 1" in capsys.readouterr().out


@pytest.mark.parametrize(
    ("option", "value", "message"),
    [
        ("--success-after-failures-threshold", "1", "failure_threshold"),
        ("--success-after-failures-window-minutes", "0", "window"),
    ],
)
def test_invalid_configuration_returns_exit_code_two(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    option: str,
    value: str,
    message: str,
) -> None:
    path = tmp_path / "events.log"
    path.write_text("", encoding="utf-8")

    exit_code = main(linux_arguments(path, option, value))

    assert exit_code == 2
    assert message in capsys.readouterr().err

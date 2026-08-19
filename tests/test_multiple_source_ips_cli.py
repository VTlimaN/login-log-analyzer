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


def failure(minute: int, source_ip: str, *, username: str = "Admin") -> str:
    return (
        f"Aug 18 09:{minute:02d}:00 host sshd[10]: "
        f"Failed password for {username} from {source_ip} "
        f"port {50000 + minute} ssh2"
    )


@pytest.mark.parametrize(
    "command",
    ["analyze-linux", "analyze-windows", "analyze-windows-native"],
)
def test_help_documents_multiple_source_ips_options(
    command: str,
    capsys: pytest.CaptureFixture[str],
) -> None:
    with pytest.raises(SystemExit) as error:
        main([command, "--help"])

    assert error.value.code == 0
    output = capsys.readouterr().out
    assert "--multiple-source-ips-threshold" in output
    assert "--multiple-source-ips-window-minutes" in output


def test_default_configuration_requires_five_source_ips(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    path = tmp_path / "below-default.log"
    write_log(
        path,
        [failure(minute, f"192.0.2.{minute + 1}") for minute in range(4)],
    )

    assert main(linux_arguments(path)) == 0
    assert "Achados de múltiplos IPs de origem: 0" in capsys.readouterr().out


def test_finding_details_and_ip_list_return_success(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    path = tmp_path / "finding.log"
    write_log(
        path,
        [failure(minute, f"192.0.2.{minute + 1}") for minute in range(5)],
    )

    exit_code = main(linux_arguments(path))

    assert exit_code == 0
    output = capsys.readouterr().out
    assert "Achados de múltiplos IPs de origem: 1" in output
    assert "Múltiplos IPs de origem contra uma conta" in output
    assert "Admin | 2026-08-18T09:00:00+00:00 -> 2026-08-18T09:04:00+00:00" in output
    assert "IPs distintos: 5" in output
    assert "IPs: 192.0.2.1, 192.0.2.2, 192.0.2.3, 192.0.2.4, 192.0.2.5" in output


def test_custom_threshold_is_used(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    path = tmp_path / "custom-threshold.log"
    write_log(path, [failure(0, "192.0.2.1"), failure(1, "192.0.2.2")])

    exit_code = main(
        linux_arguments(path, "--multiple-source-ips-threshold", "2")
    )

    assert exit_code == 0
    assert "Achados de múltiplos IPs de origem: 1" in capsys.readouterr().out


def test_custom_window_is_used(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    path = tmp_path / "custom-window.log"
    write_log(path, [failure(0, "192.0.2.1"), failure(15, "192.0.2.2")])

    exit_code = main(
        linux_arguments(
            path,
            "--multiple-source-ips-threshold",
            "2",
            "--multiple-source-ips-window-minutes",
            "20",
        )
    )

    assert exit_code == 0
    assert "Achados de múltiplos IPs de origem: 1" in capsys.readouterr().out


@pytest.mark.parametrize(
    ("option", "value", "message"),
    [
        ("--multiple-source-ips-threshold", "1", "source_ip_threshold"),
        ("--multiple-source-ips-window-minutes", "0", "window"),
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

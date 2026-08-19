import csv
import json
from pathlib import Path

import pytest

from login_log_analyzer.cli import main
from login_log_analyzer.windows_native_analysis import WindowsNativeAnalysisResult


class NativeAnalyzer:
    def analyze(self, max_events: int) -> WindowsNativeAnalysisResult:
        return WindowsNativeAnalysisResult(
            collected_record_count=0,
            parsed_event_count=0,
            unsupported_record_count=0,
            record_errors=(),
            brute_force_findings=(),
            off_hours_findings=(),
            password_spray_findings=(),
            successful_login_after_failures_findings=(),
            multiple_source_ips_findings=(),
            account_lockout_events=(),
        )


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


def test_report_options_are_available_for_all_analysis_commands(
    capsys: pytest.CaptureFixture[str],
) -> None:
    for command in (
        "analyze-linux",
        "analyze-windows",
        "analyze-windows-native",
    ):
        with pytest.raises(SystemExit) as error:
            main([command, "--help"])
        assert error.value.code == 0
        output = capsys.readouterr().out
        assert "--output-json" in output
        assert "--output-csv" in output
        assert "--overwrite" in output


def test_linux_exports_both_formats_and_preserves_success_for_findings(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    source = tmp_path / "linux.log"
    source.write_text(
        "\n".join(
            f"Aug 18 03:0{minute}:00 host sshd[10]: "
            f"Failed password for Admin from 192.0.2.10 port {50000 + minute} ssh2"
            for minute in range(5)
        ),
        encoding="utf-8",
    )
    json_path = tmp_path / "linux.json"
    csv_path = tmp_path / "linux.csv"

    exit_code = main(
        linux_arguments(
            source,
            "--output-json",
            str(json_path),
            "--output-csv",
            str(csv_path),
        )
    )

    assert exit_code == 0
    assert json.loads(json_path.read_text(encoding="utf-8"))["analysis_source"] == "linux_file"
    with csv_path.open(encoding="utf-8", newline="") as report:
        assert next(csv.DictReader(report))["finding_type"] == "brute_force"
    output = capsys.readouterr().out
    assert f"Relatório JSON salvo em: {json_path}" in output
    assert f"Relatório CSV salvo em: {csv_path}" in output


@pytest.mark.parametrize(("option", "suffix"), [("--output-json", ".json"), ("--output-csv", ".csv")])
def test_windows_json_exports_requested_format(
    tmp_path: Path,
    option: str,
    suffix: str,
) -> None:
    source = tmp_path / "windows.json"
    source.write_text("[]", encoding="utf-8")
    destination = tmp_path / f"report{suffix}"

    exit_code = main(["analyze-windows", str(source), option, str(destination)])

    assert exit_code == 0
    assert destination.exists()


@pytest.mark.parametrize(("option", "suffix"), [("--output-json", ".json"), ("--output-csv", ".csv")])
def test_windows_native_exports_requested_format(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    option: str,
    suffix: str,
) -> None:
    destination = tmp_path / f"native{suffix}"
    monkeypatch.setattr(
        "login_log_analyzer.cli.create_windows_native_analyzer",
        lambda arguments: NativeAnalyzer(),
    )

    exit_code = main(["analyze-windows-native", option, str(destination)])

    assert exit_code == 0
    assert destination.exists()


def test_no_export_keeps_existing_output_unchanged(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    source = tmp_path / "linux.log"
    source.write_text("", encoding="utf-8")

    assert main(linux_arguments(source)) == 0

    assert "Relatório" not in capsys.readouterr().out


def test_existing_destination_is_operational_failure_unless_overwrite_is_set(
    tmp_path: Path,
) -> None:
    source = tmp_path / "linux.log"
    source.write_text("", encoding="utf-8")
    destination = tmp_path / "report.json"
    destination.write_text("old", encoding="utf-8")

    assert main(linux_arguments(source, "--output-json", str(destination))) == 1
    assert destination.read_text(encoding="utf-8") == "old"
    assert (
        main(
            linux_arguments(
                source,
                "--output-json",
                str(destination),
                "--overwrite",
            )
        )
        == 0
    )


def test_duplicate_output_path_is_configuration_failure(tmp_path: Path) -> None:
    source = tmp_path / "linux.log"
    source.write_text("", encoding="utf-8")
    destination = tmp_path / "report"

    exit_code = main(
        linux_arguments(
            source,
            "--output-json",
            str(destination),
            "--output-csv",
            str(destination),
        )
    )

    assert exit_code == 2
    assert not destination.exists()


def test_report_write_failure_returns_operational_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "linux.log"
    source.write_text("", encoding="utf-8")

    def fail_export(*args: object, **kwargs: object) -> None:
        raise PermissionError("denied")

    monkeypatch.setattr("login_log_analyzer.cli.export_json_report", fail_export)

    assert (
        main(
            linux_arguments(
                source,
                "--output-json",
                str(tmp_path / "report.json"),
            )
        )
        == 1
    )

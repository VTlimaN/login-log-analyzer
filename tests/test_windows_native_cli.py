from datetime import datetime, timezone
from ipaddress import ip_address

import pytest

from login_log_analyzer.authentication import AuthenticationPlatform
from login_log_analyzer.brute_force import BruteForceFinding
from login_log_analyzer.cli import main
from login_log_analyzer.off_hours import OffHoursLoginFinding
from login_log_analyzer.password_spray import PasswordSprayFinding
from login_log_analyzer.windows_native_analysis import (
    WindowsNativeAnalysisResult,
    WindowsNativeQueryError,
    WindowsNativeRecordError,
)


def create_result(*, findings: bool = False) -> WindowsNativeAnalysisResult:
    timestamp = datetime(2026, 8, 18, 3, 0, tzinfo=timezone.utc)
    source_ip = ip_address("192.0.2.25")
    if not findings:
        return WindowsNativeAnalysisResult(
            collected_record_count=1,
            parsed_event_count=1,
            unsupported_record_count=0,
            record_errors=(),
            brute_force_findings=(),
            off_hours_findings=(),
            password_spray_findings=(),
            successful_login_after_failures_findings=(),
        )

    return WindowsNativeAnalysisResult(
        collected_record_count=7,
        parsed_event_count=6,
        unsupported_record_count=0,
        record_errors=(
            WindowsNativeRecordError(record_number=7, message="invalid source IP"),
        ),
        brute_force_findings=(
            BruteForceFinding(
                username="Admin",
                source_ip=source_ip,
                first_observed=timestamp,
                last_observed=timestamp,
                failure_count=5,
            ),
        ),
        off_hours_findings=(
            OffHoursLoginFinding(
                username="Analyst",
                timestamp=timestamp,
                source_ip=None,
                platform=AuthenticationPlatform.WINDOWS,
            ),
        ),
        password_spray_findings=(
            PasswordSprayFinding(
                source_ip=source_ip,
                first_observed=timestamp,
                last_observed=timestamp,
                distinct_username_count=5,
                usernames=("Admin", "User1", "User2", "User3", "User4"),
            ),
        ),
        successful_login_after_failures_findings=(),
    )


class FakeAnalyzer:
    def __init__(
        self,
        result: WindowsNativeAnalysisResult | None = None,
        error: Exception | None = None,
    ) -> None:
        self.result = result
        self.error = error
        self.max_events: int | None = None

    def analyze(self, max_events: int) -> WindowsNativeAnalysisResult:
        self.max_events = max_events
        if self.error is not None:
            raise self.error
        if self.result is None:
            raise AssertionError("test analyzer requires a result")
        return self.result


def test_top_level_help_displays_native_windows_command(
    capsys: pytest.CaptureFixture[str],
) -> None:
    with pytest.raises(SystemExit) as error:
        main(["--help"])

    assert error.value.code == 0
    assert "analyze-windows-native" in capsys.readouterr().out


def test_native_help_documents_limit_and_detector_options(
    capsys: pytest.CaptureFixture[str],
) -> None:
    with pytest.raises(SystemExit) as error:
        main(["analyze-windows-native", "--help"])

    assert error.value.code == 0
    output = capsys.readouterr().out
    assert "--max-events" in output
    assert "default: 100" in output
    assert "--brute-force-threshold" in output
    assert "--password-spray-threshold" in output
    assert "--allowed-weekdays" in output
    assert "--year" not in output
    assert "--timezone-offset" not in output


@pytest.mark.parametrize(("arguments", "expected_limit"), [([], 100), (["--max-events", "12"], 12)])
def test_native_happy_path_uses_configured_limit(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    arguments: list[str],
    expected_limit: int,
) -> None:
    analyzer = FakeAnalyzer(result=create_result())
    monkeypatch.setattr(
        "login_log_analyzer.cli.create_windows_native_analyzer",
        lambda parsed_arguments: analyzer,
    )

    exit_code = main(["analyze-windows-native", *arguments])

    assert exit_code == 0
    assert analyzer.max_events == expected_limit
    output = capsys.readouterr().out
    assert "Resumo da coleta nativa Windows" in output
    assert "Registros coletados: 1" in output
    assert "Eventos de autenticação: 1" in output
    assert "Achados de força bruta: 0" in output


def test_native_findings_and_record_errors_return_success(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(
        "login_log_analyzer.cli.create_windows_native_analyzer",
        lambda arguments: FakeAnalyzer(result=create_result(findings=True)),
    )

    exit_code = main(["analyze-windows-native"])

    assert exit_code == 0
    output = capsys.readouterr().out
    assert "Erros de registro: 1" in output
    assert "Registro 7: invalid source IP" in output
    assert "Força bruta" in output
    assert "Logins fora do horário" in output
    assert "Password spraying" in output


def test_native_operational_failure_returns_one_without_traceback(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(
        "login_log_analyzer.cli.create_windows_native_analyzer",
        lambda arguments: FakeAnalyzer(
            error=WindowsNativeQueryError("Security log query failed")
        ),
    )

    exit_code = main(["analyze-windows-native"])

    captured = capsys.readouterr()
    assert exit_code == 1
    assert captured.out == ""
    assert "Erro na coleta nativa Windows" in captured.err
    assert "Traceback" not in captured.err


def test_native_unsupported_platform_returns_one_without_traceback(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr("login_log_analyzer.windows_native_analysis.sys.platform", "linux")

    exit_code = main(["analyze-windows-native"])

    captured = capsys.readouterr()
    assert exit_code == 1
    assert "supported only on Windows" in captured.err
    assert "Traceback" not in captured.err


@pytest.mark.parametrize("value", ["0", "-1", "not-a-number"])
def test_invalid_native_event_limit_returns_two(
    value: str,
    capsys: pytest.CaptureFixture[str],
) -> None:
    with pytest.raises(SystemExit) as error:
        main(["analyze-windows-native", "--max-events", value])

    assert error.value.code == 2
    assert "inteiro positivo" in capsys.readouterr().err


def test_invalid_native_detector_configuration_returns_two(
    capsys: pytest.CaptureFixture[str],
) -> None:
    exit_code = main(
        ["analyze-windows-native", "--brute-force-threshold", "0"]
    )

    captured = capsys.readouterr()
    assert exit_code == 2
    assert "failure_threshold" in captured.err
    assert "Traceback" not in captured.err

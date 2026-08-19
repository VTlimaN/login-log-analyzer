import json
from datetime import datetime, timedelta
from ipaddress import ip_address
from pathlib import Path

import pytest

from login_log_analyzer.account_lockout import AccountLockoutEvent
from login_log_analyzer.authentication import AuthenticationPlatform
from login_log_analyzer.brute_force import BruteForceFinding
from login_log_analyzer.brute_force_lockout import BruteForceAccountLockoutFinding
from login_log_analyzer.cli import main
from login_log_analyzer.windows_native_analysis import WindowsNativeAnalysisResult


def records(lockout_minute: int = 10) -> list[dict[str, object]]:
    values = [
        {
            "event_id": 4625,
            "timestamp": f"2026-08-19T12:0{minute}:00+00:00",
            "username": "alice",
            "source_ip": "192.0.2.90",
        }
        for minute in range(5)
    ]
    values.append(
        {
            "event_id": 4740,
            "timestamp": f"2026-08-19T12:{lockout_minute:02d}:00+00:00",
            "username": "alice",
        }
    )
    return values


def write_records(path: Path, values: list[dict[str, object]]) -> None:
    path.write_text(json.dumps(values), encoding="utf-8")


def test_correlation_option_is_windows_only(
    capsys: pytest.CaptureFixture[str],
) -> None:
    for command in ("analyze-windows", "analyze-windows-native"):
        with pytest.raises(SystemExit) as error:
            main([command, "--help"])
        assert error.value.code == 0
        output = capsys.readouterr().out
        assert "--brute-force-lockout-window-minutes" in output
        assert "15" in output

    with pytest.raises(SystemExit) as error:
        main(["analyze-linux", "--help"])
    assert error.value.code == 0
    assert "--brute-force-lockout-window-minutes" not in capsys.readouterr().out


def test_windows_json_displays_correlated_count_and_details(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    path = tmp_path / "correlation.json"
    write_records(path, records())

    exit_code = main(["analyze-windows", str(path)])

    assert exit_code == 0
    output = capsys.readouterr().out
    assert "Achados de força bruta: 1" in output
    assert "Bloqueios de conta: 1" in output
    assert "Correlações de força bruta + bloqueio: 1" in output
    assert "Correlações de força bruta seguidas por bloqueio" in output
    assert "alice | 192.0.2.90" in output
    assert "falhas: 5" in output
    assert "bloqueio: 2026-08-19T12:10:00+00:00" in output
    assert "atraso: 360s" in output


def test_windows_json_custom_window_can_exclude_correlation(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    path = tmp_path / "custom-window.json"
    write_records(path, records())

    exit_code = main(
        [
            "analyze-windows",
            str(path),
            "--brute-force-lockout-window-minutes",
            "5",
        ]
    )

    assert exit_code == 0
    output = capsys.readouterr().out
    assert "Achados de força bruta: 1" in output
    assert "Bloqueios de conta: 1" in output
    assert "Correlações de força bruta + bloqueio: 0" in output


def test_windows_json_outside_default_window_does_not_correlate(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    path = tmp_path / "outside-window.json"
    write_records(path, records(lockout_minute=20))

    assert main(["analyze-windows", str(path)]) == 0

    assert "Correlações de força bruta + bloqueio: 0" in capsys.readouterr().out


def test_invalid_correlation_window_returns_exit_code_two(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    path = tmp_path / "events.json"
    write_records(path, [])

    with pytest.raises(SystemExit) as error:
        main(
            [
                "analyze-windows",
                str(path),
                "--brute-force-lockout-window-minutes",
                "0",
            ]
        )

    assert error.value.code == 2
    assert "inteiro positivo" in capsys.readouterr().err


class NativeCorrelationAnalyzer:
    def analyze(self, max_events: int) -> WindowsNativeAnalysisResult:
        first = datetime.fromisoformat("2026-08-19T12:00:00+00:00")
        last = datetime.fromisoformat("2026-08-19T12:04:00+00:00")
        locked = datetime.fromisoformat("2026-08-19T12:10:00+00:00")
        brute_force = BruteForceFinding(
            username="native-user",
            source_ip=ip_address("2001:db8::90"),
            first_observed=first,
            last_observed=last,
            failure_count=5,
        )
        lockout = AccountLockoutEvent(
            timestamp=locked,
            username="native-user",
            platform=AuthenticationPlatform.WINDOWS,
        )
        correlated = BruteForceAccountLockoutFinding(
            username="native-user",
            source_ip=ip_address("2001:db8::90"),
            brute_force_first_failure=first,
            brute_force_last_failure=last,
            brute_force_failure_count=5,
            lockout_timestamp=locked,
            correlation_delay=timedelta(minutes=6),
        )
        return WindowsNativeAnalysisResult(
            collected_record_count=6,
            parsed_event_count=5,
            unsupported_record_count=0,
            record_errors=(),
            brute_force_findings=(brute_force,),
            off_hours_findings=(),
            password_spray_findings=(),
            successful_login_after_failures_findings=(),
            multiple_source_ips_findings=(),
            account_lockout_events=(lockout,),
            brute_force_account_lockout_findings=(correlated,),
        )


def test_windows_native_displays_correlated_finding(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(
        "login_log_analyzer.cli.create_windows_native_analyzer",
        lambda arguments: NativeCorrelationAnalyzer(),
    )

    assert main(["analyze-windows-native"]) == 0

    output = capsys.readouterr().out
    assert "Correlações de força bruta + bloqueio: 1" in output
    assert "native-user | 2001:db8::90" in output
    assert "atraso: 360s" in output

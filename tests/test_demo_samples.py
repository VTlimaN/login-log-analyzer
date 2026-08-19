from pathlib import Path

import pytest

from login_log_analyzer.cli import main


PROJECT_ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize(
    "arguments",
    [
        [
            "analyze-linux",
            str(PROJECT_ROOT / "samples" / "demo_linux_attack.log"),
            "--year",
            "2026",
            "--timezone-offset=-03:00",
        ],
        [
            "analyze-windows",
            str(PROJECT_ROOT / "samples" / "demo_windows_attack.json"),
        ],
    ],
)
def test_documented_demo_produces_all_finding_categories(
    arguments: list[str],
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert main(arguments) == 0

    output = capsys.readouterr().out
    assert "Eventos de autenticação: 10" in output
    assert "Achados de força bruta: 1" in output
    assert "Achados fora do horário: 1" in output
    assert "Achados de password spraying: 1" in output
    assert "Erros de parsing: 0" in output or "Erros de registro: 0" in output


def test_account_lockout_sample_produces_direct_observation(
    capsys: pytest.CaptureFixture[str],
) -> None:
    arguments = [
        "analyze-windows",
        str(PROJECT_ROOT / "samples" / "windows_account_lockout.json"),
    ]

    assert main(arguments) == 0

    output = capsys.readouterr().out
    assert "Eventos de autenticação: 0" in output
    assert "Bloqueios de conta: 1" in output
    assert "DemoLockedUser" in output
    assert "DEMO-WS-042" in output


def test_account_lifecycle_sample_produces_direct_observations(
    capsys: pytest.CaptureFixture[str],
) -> None:
    arguments = [
        "analyze-windows",
        str(PROJECT_ROOT / "samples" / "windows_account_lifecycle.json"),
    ]

    assert main(arguments) == 0

    output = capsys.readouterr().out
    assert "Eventos de autenticação: 0" in output
    assert "Eventos de ciclo de vida de conta: 5" in output
    assert "DemoLifecycleUser" in output
    for action in ("criada", "habilitada", "desabilitada", "excluída", "desbloqueada"):
        assert action in output

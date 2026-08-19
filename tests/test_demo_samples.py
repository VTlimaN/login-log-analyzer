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

import importlib


def test_package_can_be_imported() -> None:
    package = importlib.import_module("login_log_analyzer")

    assert package.__name__ == "login_log_analyzer"


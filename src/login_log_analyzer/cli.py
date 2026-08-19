import argparse
import json
import re
import sys
from collections.abc import Sequence
from datetime import time, timedelta, timezone
from pathlib import Path
from typing import TextIO

from login_log_analyzer.brute_force import BruteForceDetector, BruteForceFinding
from login_log_analyzer.linux_authentication import LinuxAuthenticationParser
from login_log_analyzer.linux_file_analysis import (
    LinuxLogAnalysisResult,
    LinuxLogFileAnalyzer,
)
from login_log_analyzer.off_hours import OffHoursLoginDetector, OffHoursLoginFinding
from login_log_analyzer.password_spray import (
    PasswordSprayDetector,
    PasswordSprayFinding,
)
from login_log_analyzer.windows_authentication import WindowsAuthenticationParser
from login_log_analyzer.windows_json_analysis import (
    WindowsJsonAnalysisResult,
    WindowsJsonFileAnalyzer,
    WindowsJsonFormatError,
)


DEFAULT_BRUTE_FORCE_THRESHOLD = 5
DEFAULT_BRUTE_FORCE_WINDOW_MINUTES = 5
DEFAULT_PASSWORD_SPRAY_THRESHOLD = 5
DEFAULT_PASSWORD_SPRAY_WINDOW_MINUTES = 10
DEFAULT_ALLOWED_WEEKDAYS = "mon,tue,wed,thu,fri"
DEFAULT_ALLOWED_START = "08:00"
DEFAULT_ALLOWED_END = "18:00"
WEEKDAY_NUMBERS = {
    "mon": 0,
    "tue": 1,
    "wed": 2,
    "thu": 3,
    "fri": 4,
    "sat": 5,
    "sun": 6,
}
UTC_OFFSET_PATTERN = re.compile(
    r"^(?P<sign>[+-])(?P<hours>\d{2}):(?P<minutes>\d{2})$"
)
TIME_PATTERN = re.compile(r"^(?P<hours>\d{2}):(?P<minutes>\d{2})$")


def parse_utc_offset(value: str) -> timezone:
    match = UTC_OFFSET_PATTERN.fullmatch(value)
    if match is None:
        raise argparse.ArgumentTypeError(
            "o offset deve usar o formato +HH:MM ou -HH:MM"
        )

    hours = int(match.group("hours"))
    minutes = int(match.group("minutes"))
    if hours > 23 or minutes > 59:
        raise argparse.ArgumentTypeError(
            "o offset UTC deve estar entre -23:59 e +23:59"
        )

    offset = timedelta(hours=hours, minutes=minutes)
    if match.group("sign") == "-":
        offset = -offset
    return timezone(offset)


def parse_weekdays(value: str) -> frozenset[int]:
    names = [name.strip().casefold() for name in value.split(",")]
    if not names or any(not name for name in names):
        raise argparse.ArgumentTypeError(
            "informe ao menos um weekday entre mon,tue,wed,thu,fri,sat,sun"
        )

    unknown_names = sorted({name for name in names if name not in WEEKDAY_NUMBERS})
    if unknown_names:
        raise argparse.ArgumentTypeError(
            f"weekday desconhecido: {', '.join(unknown_names)}"
        )
    return frozenset(WEEKDAY_NUMBERS[name] for name in names)


def parse_time(value: str) -> time:
    match = TIME_PATTERN.fullmatch(value)
    if match is None:
        raise argparse.ArgumentTypeError("o horário deve usar o formato HH:MM")

    hours = int(match.group("hours"))
    minutes = int(match.group("minutes"))
    if hours > 23 or minutes > 59:
        raise argparse.ArgumentTypeError("o horário deve estar entre 00:00 e 23:59")
    return time(hours, minutes)


def add_detector_arguments(command_parser: argparse.ArgumentParser) -> None:
    command_parser.add_argument(
        "--brute-force-threshold",
        type=int,
        default=DEFAULT_BRUTE_FORCE_THRESHOLD,
        help="quantidade de falhas para força bruta",
    )
    command_parser.add_argument(
        "--brute-force-window-minutes",
        type=int,
        default=DEFAULT_BRUTE_FORCE_WINDOW_MINUTES,
        help="janela de força bruta em minutos",
    )
    command_parser.add_argument(
        "--password-spray-threshold",
        type=int,
        default=DEFAULT_PASSWORD_SPRAY_THRESHOLD,
        help="quantidade de usernames distintos para password spraying",
    )
    command_parser.add_argument(
        "--password-spray-window-minutes",
        type=int,
        default=DEFAULT_PASSWORD_SPRAY_WINDOW_MINUTES,
        help="janela de password spraying em minutos",
    )
    command_parser.add_argument(
        "--allowed-weekdays",
        type=parse_weekdays,
        default=DEFAULT_ALLOWED_WEEKDAYS,
        metavar="DAYS",
        help=(
            "weekdays permitidos separados por vírgula: "
            "mon,tue,wed,thu,fri,sat,sun"
        ),
    )
    command_parser.add_argument(
        "--allowed-start",
        type=parse_time,
        default=DEFAULT_ALLOWED_START,
        metavar="HH:MM",
        help="início do horário permitido",
    )
    command_parser.add_argument(
        "--allowed-end",
        type=parse_time,
        default=DEFAULT_ALLOWED_END,
        metavar="HH:MM",
        help="fim exclusivo do horário permitido",
    )


def create_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="login-log-analyzer",
        description="Analisa eventos de autenticação normalizados.",
    )
    commands = parser.add_subparsers(dest="command", required=True)
    linux_parser = commands.add_parser(
        "analyze-linux",
        help="analisa um arquivo de autenticação Linux",
        description=(
            "Analisa o subconjunto suportado de eventos OpenSSH em um arquivo Linux."
        ),
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    linux_parser.add_argument("path", type=Path, help="arquivo de log Linux em UTF-8")
    linux_parser.add_argument(
        "--year",
        type=int,
        required=True,
        default=argparse.SUPPRESS,
        help="ano dos timestamps syslog",
    )
    linux_parser.add_argument(
        "--timezone-offset",
        type=parse_utc_offset,
        required=True,
        default=argparse.SUPPRESS,
        metavar="OFFSET",
        help="offset UTC explícito, por exemplo -03:00",
    )
    add_detector_arguments(linux_parser)

    windows_parser = commands.add_parser(
        "analyze-windows",
        help="analisa um arquivo JSON de autenticação Windows",
        description=(
            "Analisa eventos Windows 4624 e 4625 extraídos para um arquivo JSON."
        ),
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    windows_parser.add_argument(
        "path",
        type=Path,
        help="arquivo JSON Windows em UTF-8",
    )
    add_detector_arguments(windows_parser)
    return parser


def create_detectors(
    arguments: argparse.Namespace,
) -> tuple[BruteForceDetector, OffHoursLoginDetector, PasswordSprayDetector]:
    return (
        BruteForceDetector(
            failure_threshold=arguments.brute_force_threshold,
            window=timedelta(minutes=arguments.brute_force_window_minutes),
        ),
        OffHoursLoginDetector(
            allowed_weekdays=arguments.allowed_weekdays,
            start_time=arguments.allowed_start,
            end_time=arguments.allowed_end,
        ),
        PasswordSprayDetector(
            username_threshold=arguments.password_spray_threshold,
            window=timedelta(minutes=arguments.password_spray_window_minutes),
        ),
    )


def create_linux_analyzer(arguments: argparse.Namespace) -> LinuxLogFileAnalyzer:
    brute_force_detector, off_hours_detector, password_spray_detector = (
        create_detectors(arguments)
    )
    return LinuxLogFileAnalyzer(
        parser=LinuxAuthenticationParser(
            year=arguments.year,
            timezone_info=arguments.timezone_offset,
        ),
        brute_force_detector=brute_force_detector,
        off_hours_detector=off_hours_detector,
        password_spray_detector=password_spray_detector,
    )


def create_windows_analyzer(arguments: argparse.Namespace) -> WindowsJsonFileAnalyzer:
    brute_force_detector, off_hours_detector, password_spray_detector = (
        create_detectors(arguments)
    )
    return WindowsJsonFileAnalyzer(
        windows_parser=WindowsAuthenticationParser(),
        brute_force_detector=brute_force_detector,
        off_hours_detector=off_hours_detector,
        password_spray_detector=password_spray_detector,
    )


def render_brute_force_findings(
    findings: tuple[BruteForceFinding, ...],
    output: TextIO,
) -> None:
    if not findings:
        return

    print("\nForça bruta", file=output)
    for finding in findings:
        print(
            f"  {finding.username} | {finding.source_ip} | "
            f"{finding.first_observed.isoformat()} -> "
            f"{finding.last_observed.isoformat()} | "
            f"falhas: {finding.failure_count}",
            file=output,
        )


def render_off_hours_findings(
    findings: tuple[OffHoursLoginFinding, ...],
    output: TextIO,
) -> None:
    if not findings:
        return

    print("\nLogins fora do horário", file=output)
    for finding in findings:
        source_ip = str(finding.source_ip) if finding.source_ip is not None else "N/A"
        print(
            f"  {finding.username} | {finding.timestamp.isoformat()} | "
            f"IP: {source_ip} | plataforma: {finding.platform.value}",
            file=output,
        )


def render_password_spray_findings(
    findings: tuple[PasswordSprayFinding, ...],
    output: TextIO,
) -> None:
    if not findings:
        return

    print("\nPassword spraying", file=output)
    for finding in findings:
        print(
            f"  {finding.source_ip} | {finding.first_observed.isoformat()} -> "
            f"{finding.last_observed.isoformat()} | "
            f"usernames distintos: {finding.distinct_username_count} | "
            f"usernames: {', '.join(finding.usernames)}",
            file=output,
        )


def render_linux_result(
    path: Path,
    result: LinuxLogAnalysisResult,
    output: TextIO,
) -> None:
    print(f"Arquivo analisado: {path}", file=output)
    print("Resumo", file=output)
    print(f"  Linhas totais: {result.total_lines}", file=output)
    print(f"  Eventos de autenticação: {result.parsed_event_count}", file=output)
    print(f"  Linhas não suportadas: {result.unsupported_line_count}", file=output)
    print(f"  Erros de parsing: {result.parse_error_count}", file=output)
    print(f"  Achados de força bruta: {len(result.brute_force_findings)}", file=output)
    print(f"  Achados fora do horário: {len(result.off_hours_findings)}", file=output)
    print(
        f"  Achados de password spraying: {len(result.password_spray_findings)}",
        file=output,
    )

    if result.parse_errors:
        print("\nErros de parsing", file=output)
        for error in result.parse_errors:
            print(f"  Linha {error.line_number}: {error.message}", file=output)

    render_brute_force_findings(result.brute_force_findings, output)
    render_off_hours_findings(result.off_hours_findings, output)
    render_password_spray_findings(result.password_spray_findings, output)


def render_windows_result(
    path: Path,
    result: WindowsJsonAnalysisResult,
    output: TextIO,
) -> None:
    print(f"Arquivo analisado: {path}", file=output)
    print("Resumo Windows", file=output)
    print(f"  Registros totais: {result.total_records}", file=output)
    print(f"  Eventos de autenticação: {result.parsed_event_count}", file=output)
    print(
        f"  Registros não suportados: {result.unsupported_record_count}",
        file=output,
    )
    print(f"  Erros de registro: {result.record_error_count}", file=output)
    print(f"  Achados de força bruta: {len(result.brute_force_findings)}", file=output)
    print(f"  Achados fora do horário: {len(result.off_hours_findings)}", file=output)
    print(
        f"  Achados de password spraying: {len(result.password_spray_findings)}",
        file=output,
    )

    if result.record_errors:
        print("\nErros de registro", file=output)
        for error in result.record_errors:
            print(f"  Registro {error.record_number}: {error.message}", file=output)

    render_brute_force_findings(result.brute_force_findings, output)
    render_off_hours_findings(result.off_hours_findings, output)
    render_password_spray_findings(result.password_spray_findings, output)


def run_analyze_linux(
    arguments: argparse.Namespace,
    output: TextIO,
    error_output: TextIO,
) -> int:
    try:
        analyzer = create_linux_analyzer(arguments)
    except (TypeError, ValueError) as error:
        print(f"Erro de configuração: {error}", file=error_output)
        return 2

    try:
        result = analyzer.analyze(arguments.path)
    except (OSError, UnicodeError) as error:
        print(f"Erro ao analisar '{arguments.path}': {error}", file=error_output)
        return 1

    render_linux_result(arguments.path, result, output)
    return 0


def run_analyze_windows(
    arguments: argparse.Namespace,
    output: TextIO,
    error_output: TextIO,
) -> int:
    try:
        analyzer = create_windows_analyzer(arguments)
    except (TypeError, ValueError) as error:
        print(f"Erro de configuração: {error}", file=error_output)
        return 2

    try:
        result = analyzer.analyze(arguments.path)
    except (
        OSError,
        UnicodeError,
        json.JSONDecodeError,
        WindowsJsonFormatError,
    ) as error:
        print(f"Erro ao analisar '{arguments.path}': {error}", file=error_output)
        return 1

    render_windows_result(arguments.path, result, output)
    return 0


def normalize_timezone_offset_arguments(arguments: Sequence[str]) -> list[str]:
    normalized_arguments: list[str] = []
    argument_index = 0
    while argument_index < len(arguments):
        argument = arguments[argument_index]
        if (
            argument == "--timezone-offset"
            and argument_index + 1 < len(arguments)
            and arguments[argument_index + 1].startswith("-")
            and not arguments[argument_index + 1].startswith("--")
        ):
            normalized_arguments.append(
                f"--timezone-offset={arguments[argument_index + 1]}"
            )
            argument_index += 2
            continue
        normalized_arguments.append(argument)
        argument_index += 1
    return normalized_arguments


def main(arguments: Sequence[str] | None = None) -> int:
    parser = create_argument_parser()
    supplied_arguments = sys.argv[1:] if arguments is None else arguments
    parsed_arguments = parser.parse_args(
        normalize_timezone_offset_arguments(supplied_arguments)
    )
    if parsed_arguments.command == "analyze-linux":
        return run_analyze_linux(parsed_arguments, sys.stdout, sys.stderr)
    if parsed_arguments.command == "analyze-windows":
        return run_analyze_windows(parsed_arguments, sys.stdout, sys.stderr)
    parser.error("comando não suportado")
    return 2

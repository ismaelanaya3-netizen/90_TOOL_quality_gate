"""Command line interface (messages in Spanish)."""

from __future__ import annotations

import argparse
import sys
import webbrowser
from collections.abc import Sequence
from pathlib import Path

from qgate import __version__
from qgate.config import ConfigError
from qgate.models import CheckResult, Level, Verdict
from qgate.pyversion import PythonVersionError
from qgate.report import console

EXIT_OK = 0
EXIT_GATE_FAILED = 1
EXIT_CONFIG = 2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="qgate", description="Quality Gate Kit: calidad, pruebas y seguridad.")
    parser.add_argument("--version", action="version", version=f"qgate {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    init = sub.add_parser("init", help="Aplica el kit a un proyecto existente")
    init.add_argument("ruta_proyecto", type=Path)
    init.add_argument("--app-module", default="app.main:app")
    init.add_argument("--src", default="app")
    init.add_argument("--python", default=None, help="python_objetivo a escribir (p. ej. 3.11)")
    init.add_argument("--force", action="store_true", help="Sobrescribe plantillas existentes (con .bak)")

    run = sub.add_parser("run", help="Ejecuta el gate")
    run.add_argument("--level", choices=[lv.value for lv in Level], default=Level.STANDARD.value)
    run.add_argument("--profile", default=None)
    run.add_argument("--only", default="", help="Lista de checks separados por coma")
    run.add_argument("--ci", action="store_true", help="Modo CI: los checks omitidos fallan")
    run.add_argument("--python", default=None, help="Python objetivo (major.minor)")
    run.add_argument("--path", type=Path, default=Path(), help="Raíz del proyecto (por defecto, la actual)")

    report = sub.add_parser("report", help="Muestra la ruta del último informe")
    report.add_argument("--open", action="store_true", help="Abre report.html en el navegador")
    report.add_argument("--path", type=Path, default=Path())

    doctor = sub.add_parser("doctor", help="Diagnostica el entorno")
    doctor.add_argument("--path", type=Path, default=Path())

    exc = sub.add_parser("exceptions", help="Gestiona el registro de excepciones")
    exc_sub = exc.add_subparsers(dest="exc_command", required=True)
    exc_list = exc_sub.add_parser("list", help="Lista excepciones vigentes, por vencer y vencidas")
    exc_list.add_argument("--path", type=Path, default=Path())
    return parser


def cmd_run(args: argparse.Namespace) -> int:
    from qgate.runner import run_gate

    def progress(message: str, result: CheckResult | None) -> None:
        console.emit(console.progress_line(result) if result else message)

    only = [item.strip() for item in args.only.split(",") if item.strip()]
    gate = run_gate(
        args.path,
        level=Level(args.level),
        profile=args.profile,
        only=only or None,
        ci=True if args.ci else None,
        python_flag=args.python,
        progress=progress,
    )
    console.emit(console.summary(gate))
    return EXIT_GATE_FAILED if gate.verdict is Verdict.REJECTED else EXIT_OK


def cmd_report(args: argparse.Namespace) -> int:
    latest = (args.path / ".qgate" / "latest" / "report.html").resolve()
    if not latest.is_file():
        console.emit("No hay informes todavía. Ejecute primero: qgate run")
        return EXIT_CONFIG
    console.emit(f"Último informe: {latest}")
    if args.open:
        webbrowser.open(latest.as_uri())
    return EXIT_OK


def cmd_doctor(args: argparse.Namespace) -> int:
    from qgate.doctor import diagnose

    lines, healthy = diagnose(args.path)
    console.emit("\n".join(lines))
    console.emit("\nDiagnóstico: " + ("todo listo." if healthy else "faltan herramientas (ver arriba)."))
    return EXIT_OK if healthy else EXIT_GATE_FAILED


def cmd_exceptions(args: argparse.Namespace) -> int:
    from qgate.exceptions_registry import load_registry, render_list

    registry = load_registry(args.path.resolve())
    console.emit(render_list(registry))
    expired = [e for e in registry.items if e.state(registry.today) == "vencida"]
    return EXIT_GATE_FAILED if expired else EXIT_OK


def cmd_init(args: argparse.Namespace) -> int:
    from qgate.init_project import init_project

    for line in init_project(args.ruta_proyecto, args.app_module, args.src, args.python, args.force):
        console.emit(line)
    return EXIT_OK


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    handlers = {
        "run": cmd_run,
        "report": cmd_report,
        "doctor": cmd_doctor,
        "exceptions": cmd_exceptions,
        "init": cmd_init,
    }
    try:
        return handlers[args.command](args)
    except (ConfigError, PythonVersionError) as exc:
        console.emit(f"Error de configuración: {exc}", sys.stderr)
        return EXIT_CONFIG

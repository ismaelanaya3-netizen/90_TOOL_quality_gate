"""Readable console output in Spanish, with colours only on a TTY."""

from __future__ import annotations

import os
import sys
from typing import TextIO

from qgate.models import CheckResult, GateResult, Status, Verdict

_COLORS = {
    Status.PASS: "32",
    Status.FAIL: "31",
    Status.WARN: "33",
    Status.SKIPPED: "36",
    Status.ERROR: "35",
    Status.INFO: "37",
}
_VERDICT_COLORS = {Verdict.APPROVED: "32", Verdict.APPROVED_WITH_OMISSIONS: "33", Verdict.REJECTED: "31"}


def use_color(stream: TextIO) -> bool:
    if os.environ.get("NO_COLOR") or os.environ.get("QGATE_NO_COLOR"):
        return False
    return hasattr(stream, "isatty") and stream.isatty()


def paint(text: str, code: str, stream: TextIO) -> str:
    return f"\033[{code}m{text}\033[0m" if use_color(stream) else text


def emit(text: str, stream: TextIO | None = None) -> None:
    out = stream or sys.stdout
    try:
        out.write(text + "\n")
    except UnicodeEncodeError:  # legacy Windows code pages
        out.write(text.encode("ascii", "replace").decode("ascii") + "\n")
    out.flush()


def progress_line(result: CheckResult, stream: TextIO | None = None) -> str:
    out = stream or sys.stdout
    status = paint(f"{result.status.value:<7}", _COLORS[result.status], out)
    detail = f" — {result.reason}" if result.reason else ""
    return f"   {status} {result.check_id} ({result.duration_s:.1f} s){detail}"


def _cut(text: str, width: int) -> str:
    return text if len(text) <= width else text[: width - 1] + "…"


def summary(gate: GateResult, stream: TextIO | None = None) -> str:
    out = stream or sys.stdout
    header = f"{'Check':<16} {'Nivel':<9} {'Estado':<8} {'Hall.':>5} {'Supr.':>5} {'Tiempo':>7}  Detalle"
    lines = ["", "Resumen del Quality Gate", "=" * len(header), header, "-" * len(header)]
    for r in gate.results:
        status = paint(f"{r.status.value:<8}", _COLORS[r.status], out)
        suppressed = len(r.findings) - len(r.active_findings)
        lines.append(
            f"{r.check_id:<16} {r.level.value:<9} {status} {len(r.active_findings):>5} "
            f"{suppressed:>5} {r.duration_s:>6.1f}s  {_cut(r.reason, 70)}"
        )
    lines.append("-" * len(header))
    lines.append(f"Perfil: {gate.profile} | Nivel: {gate.level.value} | CI: {'sí' if gate.ci else 'no'}")
    lines.append(f"Python objetivo: {gate.target.version} (origen: {gate.target.source})")
    if gate.omissions:
        lines.append("Omisiones: " + ", ".join(f"{r.check_id} ({r.reason})" for r in gate.omissions))
    verdict = paint(f"VEREDICTO: {gate.verdict.value}", _VERDICT_COLORS[gate.verdict], out)
    lines += [verdict, f"Informe: {gate.out_dir}"]
    return "\n".join(lines)

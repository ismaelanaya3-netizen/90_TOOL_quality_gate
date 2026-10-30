"""Standard-level code checks: complexity (radon), typing (mypy) and SAST (bandit)."""

from __future__ import annotations

import json
import re
from pathlib import Path

from qgate import tools
from qgate.checks.base import Check, metric_rank
from qgate.context import RunContext
from qgate.fsutil import rel_posix
from qgate.models import CheckResult, Finding, Level, Metric, Severity

_RANK_VALUE = {letter: i + 1 for i, letter in enumerate("ABCDEF")}


def cc_rank(complexity: float) -> str:
    """Radon's ranking: A 1-5, B 6-10, C 11-20, D 21-30, E 31-40, F 41+."""
    for limit, letter in ((5, "A"), (10, "B"), (20, "C"), (30, "D"), (40, "E")):
        if complexity <= limit:
            return letter
    return "F"


def _exclude_arg(ctx: RunContext) -> str:
    return ",".join(p.rstrip("/*") or p for p in ctx.excludes)


class ComplexityCheck(Check):
    id = "complexity"
    title = "Complejidad ciclomática (radon)"
    level = Level.STANDARD
    tool = "radon"
    gate_key = "complejidad_peor"

    def execute(self, ctx: RunContext) -> CheckResult:
        result = self.new()
        result.tool_version = tools.version_of([*tools.python_module_cmd("radon"), "--version"])
        args = [*tools.python_module_cmd("radon"), "cc", "-j", "-s", "-i", _exclude_arg(ctx), *ctx.cfg.src]
        out = tools.run(args, cwd=ctx.root, timeout=600)
        try:
            data = json.loads(out.stdout or "{}")
        except json.JSONDecodeError:
            return self.error(f"radon falló: {out.stderr.strip()[:400]}")
        worst_allowed = ctx.threshold(self.gate_key) or 6
        blocks: list[tuple[str, dict[str, object]]] = []
        for filename, items in data.items():
            if not isinstance(items, list):
                continue
            rel = rel_posix(Path(filename), ctx.root) if Path(filename).is_absolute() else filename.replace("\\", "/")
            blocks += [(rel, item) for item in items if isinstance(item, dict)]
        for rel, item in blocks:
            letter = str(item.get("rank", "A"))
            if _RANK_VALUE.get(letter, 1) > worst_allowed:
                result.findings.append(
                    Finding("radon", f"CC-{letter}", Severity.MEDIUM,
                            f"{item.get('name')} tiene complejidad {item.get('complexity')} (rango {letter})",
                            rel, int(str(item.get("lineno", 0))))
                )  # fmt: skip
        self.suppress(ctx, result)
        excused = {(f.file, f.line) for f in result.findings if f.suppressed_by}
        kept = [item for rel, item in blocks if (rel, int(str(item.get("lineno", 0)))) not in excused]
        values = [float(str(item.get("complexity", 1))) for item in kept]
        worst = max((_RANK_VALUE.get(str(i.get("rank", "A")), 1) for i in kept), default=1)
        average = sum(values) / len(values) if values else 1.0
        result.metrics.append(metric_rank(self.gate_key, "Peor función (rango)", worst))
        result.metrics.append(
            metric_rank("complejidad_promedio", "Complejidad promedio (rango)", _RANK_VALUE[cc_rank(average)])
        )
        result.notes.append(f"{len(values)} bloques analizados; complejidad promedio {average:.2f}")
        return self.finalize(ctx, result)


_MYPY_RE = re.compile(
    r"^(?P<file>.+?):(?P<line>\d+):(?:\d+:)? (?P<kind>error): (?P<msg>.*?)(?:  \[(?P<code>[\w-]+)\])?$"
)


class TypingCheck(Check):
    id = "typing"
    title = "Tipado estricto (mypy --strict)"
    level = Level.STANDARD
    tool = "mypy"
    gate_key = "mypy_errores"

    def build_command(self, ctx: RunContext) -> list[str]:
        args = [
            *tools.python_module_cmd("mypy"), "--strict", "--python-version", ctx.target.version,
            "--no-error-summary", "--show-error-codes", "--no-color-output", "--no-pretty",
            "--cache-dir", str(ctx.root / ".qgate" / "mypy_cache"),
        ]  # fmt: skip
        if ctx.cfg.python_executable:
            args += ["--python-executable", ctx.cfg.python_executable]
        for flag in ctx.cfg.str_list("tipado", "argumentos", []):
            args.append(flag)
        return [*args, *ctx.cfg.src]

    def execute(self, ctx: RunContext) -> CheckResult:
        result = self.new()
        result.tool_version = tools.version_of([*tools.python_module_cmd("mypy"), "--version"])
        out = tools.run(self.build_command(ctx), cwd=ctx.root, timeout=900)
        if out.returncode not in {0, 1}:
            return self.error(f"mypy falló (código {out.returncode}): {(out.stderr or out.stdout).strip()[:400]}")
        for line in out.stdout.splitlines():
            match = _MYPY_RE.match(line.strip())
            if match:
                result.findings.append(
                    Finding("mypy", match.group("code") or "error", Severity.LOW, match.group("msg"),
                            match.group("file").replace("\\", "/"), int(match.group("line")))
                )  # fmt: skip
        self.suppress(ctx, result)
        result.metrics.append(self.count_metric(self.gate_key, "Errores de tipado", result))
        return self.finalize(ctx, result)


class BanditCheck(Check):
    id = "bandit"
    title = "SAST (bandit)"
    level = Level.STANDARD
    tool = "bandit"
    gate_key = "bandit_hallazgos"

    def execute(self, ctx: RunContext) -> CheckResult:
        result = self.new()
        result.tool_version = tools.version_of([*tools.python_module_cmd("bandit"), "--version"])
        args = [*tools.python_module_cmd("bandit"), "-r", *ctx.cfg.src, "-f", "json", "-q", "-x", _exclude_arg(ctx)]
        out = tools.run(args, cwd=ctx.root, timeout=900)
        try:
            data = json.loads(out.stdout or "{}")
        except json.JSONDecodeError:
            return self.error(f"bandit falló: {out.stderr.strip()[:400]}")
        for item in data.get("results", []):
            cwe = (item.get("issue_cwe") or {}).get("id")
            result.findings.append(
                Finding("bandit", str(item.get("test_id")), Severity.parse(str(item.get("issue_severity", "LOW"))),
                        str(item.get("issue_text", "")), rel_posix(Path(str(item.get("filename", ""))), ctx.root),
                        int(item.get("line_number", 0)), cwe=f"CWE-{cwe}" if cwe else "")
            )  # fmt: skip
        self.suppress(ctx, result)
        minimum = Severity.parse(str(ctx.profile_value("bandit_severidad_minima", "LOW")))
        counted = [f for f in result.active_findings if f.severity.rank >= minimum.rank]
        result.metrics.append(Metric(self.gate_key, f"Hallazgos bandit ≥ {minimum.value}", float(len(counted))))
        return self.finalize(ctx, result)

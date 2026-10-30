"""Tests + coverage (pytest, pytest-cov) producing junit.xml and coverage.xml."""

from __future__ import annotations

import json
import re
from fnmatch import fnmatchcase
from pathlib import Path
from typing import Any

from qgate import tools
from qgate.checks.base import Check, pct
from qgate.context import RunContext
from qgate.models import CheckResult, Finding, Level, Metric, Severity


def junit_counts(path: Path) -> dict[str, int]:
    """Read totals from the first ``<testsuite>`` tag (regex: no XML parser on input)."""
    text = path.read_text(encoding="utf-8", errors="replace") if path.is_file() else ""
    match = re.search(r"<testsuite\b[^>]*>", text)
    counts = {"tests": 0, "failures": 0, "errors": 0, "skipped": 0}
    if match:
        for key in counts:
            attr = re.search(rf'\b{key}="(\d+)"', match.group(0))
            counts[key] = int(attr.group(1)) if attr else 0
    return counts


def critical_coverage(data: dict[str, Any], patterns: list[str]) -> list[tuple[str, float]]:
    out = []
    for filename, info in data.get("files", {}).items():
        rel = str(filename).replace("\\", "/")
        if any(fnmatchcase(rel, p) for p in patterns):
            out.append((rel, float(info.get("summary", {}).get("percent_covered", 0.0))))
    return sorted(out)


class TestsCheck(Check):
    __test__ = False  # not a pytest test class
    id = "tests"
    title = "Pruebas + cobertura (pytest)"
    level = Level.STANDARD
    tool = "pytest"
    gate_key = "pruebas_fallidas"

    def build_command(self, ctx: RunContext) -> list[str]:
        out = ctx.out_dir
        args = [ctx.python, "-m", "pytest", ctx.cfg.tests, f"--junitxml={out / 'junit.xml'}", "--cov-branch"]
        args += [f"--cov={src}" for src in ctx.cfg.src]
        args += [
            f"--cov-report=xml:{out / 'coverage.xml'}",
            f"--cov-report=json:{out / 'coverage.json'}",
            "-q", "-p", "no:cacheprovider",
        ]  # fmt: skip
        return [*args, *ctx.cfg.str_list("pruebas", "argumentos", [])]

    def execute(self, ctx: RunContext) -> CheckResult:
        if not (ctx.root / ctx.cfg.tests).exists():
            result = self.new()
            result.findings.append(
                Finding("pytest", "no-tests", Severity.HIGH, f"No existe la carpeta '{ctx.cfg.tests}'")
            )
            result.metrics.append(Metric(self.gate_key, "Pruebas fallidas", 1.0))
            result.metrics.append(Metric("cobertura_total", "Cobertura total", 0.0, "%", "min"))
            self.suppress(ctx, result)
            return self.finalize(ctx, result)
        result = self.new()
        result.tool_version = tools.version_of([ctx.python, "-m", "pytest", "--version"])
        env = {str(k): str(v) for k, v in ctx.cfg.option("pruebas", "entorno", {}).items()}
        out = tools.run(
            self.build_command(ctx), cwd=ctx.root, timeout=float(ctx.cfg.option("pruebas", "timeout_s", 1800)), env=env
        )
        (ctx.out_dir / "pytest-output.txt").write_text(out.stdout + "\n" + out.stderr, encoding="utf-8")
        counts = junit_counts(ctx.out_dir / "junit.xml")
        failed = counts["failures"] + counts["errors"]
        if out.returncode not in {0, 1} and failed == 0:
            failed = 1
            reason = (
                "sin pruebas recolectadas" if out.returncode == 5 else f"pytest terminó con código {out.returncode}"
            )
            result.findings.append(Finding("pytest", "pytest-error", Severity.HIGH, reason))
        cov_path = ctx.out_dir / "coverage.json"
        data: dict[str, Any] = json.loads(cov_path.read_text(encoding="utf-8")) if cov_path.is_file() else {}
        total = float(data.get("totals", {}).get("percent_covered", 0.0))
        patterns = ctx.cfg.str_list("cobertura", "criticos", [])
        critical = critical_coverage(data, patterns)
        crit_limit = ctx.threshold("cobertura_critica")
        for rel, value in critical:
            if crit_limit is not None and value < crit_limit:
                result.findings.append(
                    Finding("pytest-cov", "critical-coverage", Severity.MEDIUM,
                            f"Cobertura {value:.1f}% en módulo crítico (exigido ≥ {crit_limit:.0f}%)", rel, 1)
                )  # fmt: skip
        self.suppress(ctx, result)
        result.metrics.append(Metric(self.gate_key, "Pruebas fallidas", float(failed)))
        result.metrics.append(Metric("cobertura_total", "Cobertura total", pct(total), "%", "min"))
        if critical:
            excused = {f.file for f in result.findings if f.suppressed_by}
            values = [v for rel, v in critical if rel not in excused] or [100.0]
            result.metrics.append(
                Metric("cobertura_critica", "Cobertura mínima en módulos críticos", pct(min(values)), "%", "min")
            )
        elif patterns:
            result.notes.append("Ningún archivo coincide con [cobertura].criticos")
        result.notes.append(
            f"{counts['tests']} pruebas, {counts['failures']} fallos, {counts['errors']} errores, "
            f"{counts['skipped']} omitidas"
        )
        result.notes.append(f"Módulos críticos: {', '.join(f'{r} {v:.1f}%' for r, v in critical) or 'no definidos'}")
        return self.finalize(ctx, result)

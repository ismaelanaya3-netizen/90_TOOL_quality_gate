"""Fast-level checks: formatting, lint, file size and Python version alignment."""

from __future__ import annotations

import json
import re
from pathlib import Path

from qgate import pyversion, tools
from qgate.checks.base import Check
from qgate.context import RunContext
from qgate.fsutil import count_lines, iter_files, rel_posix
from qgate.models import CheckResult, Finding, Level, Metric, Severity, Status

RUFF_TIMEOUT = 600


def ruff_base(ctx: RunContext, subcommand: str) -> list[str]:
    """``python -m ruff <subcommand>`` with target version and user exclusions."""
    args = [
        *tools.python_module_cmd("ruff"),
        subcommand,
        "--target-version",
        pyversion.ruff_target(ctx.target.version),
        "--force-exclude",
    ]
    for pattern in ctx.cfg.excludes:
        args += ["--extend-exclude", pattern]
    return args


def ruff_version() -> str:
    return tools.version_of([*tools.python_module_cmd("ruff"), "--version"])


class FormatCheck(Check):
    id = "format"
    title = "Formato (ruff format)"
    level = Level.FAST
    tool = "ruff"
    gate_key = "formato_diferencias"

    def build_command(self, ctx: RunContext) -> list[str]:
        return [*ruff_base(ctx, "format"), "--check", "--output-format", "concise", "."]

    def execute(self, ctx: RunContext) -> CheckResult:
        result = self.new()
        result.tool_version = ruff_version()
        out = tools.run(self.build_command(ctx), cwd=ctx.root, timeout=RUFF_TIMEOUT)
        if out.missing or (out.returncode not in {0, 1}):
            return self.error(f"ruff format falló: {out.stderr.strip()[:500]}")
        files: dict[str, int] = {}
        for line in out.stdout.splitlines():
            match = _FORMAT_RE.match(line.strip())
            if match:
                files.setdefault(match.group("file") or match.group("legacy"), int(match.group("line") or 1))
        if out.returncode == 1 and not files:
            files["."] = 1  # unknown output format: never let an unformatted tree pass
        for path, row in files.items():
            rel = rel_posix(ctx.root / path, ctx.root)
            result.findings.append(Finding("ruff", "format", Severity.LOW, "Archivo sin formatear", rel, row))
        self.suppress(ctx, result)
        result.metrics.append(self.count_metric(self.gate_key, "Archivos sin formato", result))
        return self.finalize(ctx, result)


_FORMAT_RE = re.compile(r"^(?:(?P<file>.+?):(?P<line>\d+):\d+: unformatted|Would reformat: (?P<legacy>.+))")


class LintCheck(Check):
    id = "lint"
    title = "Lint + seguridad básica (ruff)"
    level = Level.FAST
    tool = "ruff"
    gate_key = "lint_hallazgos"

    def build_command(self, ctx: RunContext) -> list[str]:
        rules = ",".join(ctx.profile_value("ruff_reglas", []))
        return [
            *ruff_base(ctx, "check"),
            "--select",
            rules,
            "--output-format",
            "json",
            "--no-fix",
            "--exit-zero",
            ".",
        ]

    def execute(self, ctx: RunContext) -> CheckResult:
        result = self.new()
        result.tool_version = ruff_version()
        out = tools.run(self.build_command(ctx), cwd=ctx.root, timeout=RUFF_TIMEOUT)
        try:
            items = json.loads(out.stdout or "[]")
        except json.JSONDecodeError:
            return self.error(f"Salida de ruff no interpretable: {out.stderr.strip()[:500]}")
        for item in items:
            code = str(item.get("code") or "syntax-error")
            severity = Severity.MEDIUM if code.startswith("S") else Severity.LOW
            result.findings.append(
                Finding(
                    tool="ruff",
                    rule=code,
                    severity=severity,
                    message=str(item.get("message", "")),
                    file=rel_posix(Path(item.get("filename", "")), ctx.root),
                    line=int((item.get("location") or {}).get("row", 0)),
                )
            )
        self.suppress(ctx, result)
        result.metrics.append(self.count_metric(self.gate_key, "Hallazgos de lint", result))
        return self.finalize(ctx, result)


class FileSizeCheck(Check):
    id = "file_size"
    title = "Tamaño de archivos .py"
    level = Level.FAST
    tool = "qgate"
    gate_key = "archivo_lineas_max"

    def execute(self, ctx: RunContext) -> CheckResult:
        result = self.new()
        limit = ctx.threshold("archivo_lineas_max") or float("inf")
        warn_at = ctx.threshold("archivo_lineas_aviso") or float("inf")
        sizes: dict[str, int] = {}
        warnings: list[str] = []
        for path in iter_files(ctx.root, ["."], [".py"], ctx.excludes):
            lines = count_lines(path)
            rel = rel_posix(path, ctx.root)
            sizes[rel] = lines
            if lines > limit:
                result.findings.append(
                    Finding("qgate", "file-too-long", Severity.MEDIUM,
                            f"{lines} líneas (máximo {int(limit)})", rel, 1)
                )  # fmt: skip
            elif lines > warn_at:
                warnings.append(f"{rel} ({lines})")
        self.suppress(ctx, result)
        excused = {f.file for f in result.findings if f.suppressed_by}
        active_max = max([0, *(n for rel, n in sizes.items() if rel not in excused)])
        result.metrics.append(Metric(self.gate_key, "Máximo de líneas por archivo", float(active_max)))
        warn = f"Archivos sobre {int(warn_at)} líneas: {', '.join(warnings)}" if warnings else ""
        return self.finalize(ctx, result, warn=warn)


_VERMIN_RE = re.compile(r"^(.*?):(\d+):(\d*):([^:]*):([^:]*):(.+)$")


class PythonVersionCheck(Check):
    id = "python_version"
    title = "Alineación con python_objetivo"
    level = Level.FAST
    tool = "vermin"
    gate_key = "version_python_desalineada"

    def interpreter_version(self, ctx: RunContext) -> str:
        code = "import sys;print('%d.%d.%d' % sys.version_info[:3])"
        out = tools.run([ctx.python, "-c", code], timeout=60)
        return out.stdout.strip() if out.ok else ""

    def vermin_findings(self, ctx: RunContext) -> list[Finding]:
        args = [
            *tools.python_module_cmd("vermin"),
            f"-t={ctx.target.version}-",
            "--violations",
            "--no-tips",
            "--no-parse-comments",
            "--format",
            "parsable",
        ]
        for pattern in ctx.cfg.excludes:
            args += ["--exclude-regex", pattern.replace("**", ".*").replace("*", "[^/]*")]
        out = tools.run([*args, *ctx.cfg.src], cwd=ctx.root, timeout=600)
        findings: list[Finding] = []
        for line in out.stdout.splitlines():
            match = _VERMIN_RE.match(line.strip())
            if not match or not match.group(2):
                continue
            findings.append(
                Finding(
                    "vermin", "requires-newer-python", Severity.MEDIUM,
                    f"{match.group(6).strip()} requiere Python {match.group(5)}",
                    rel_posix(Path(match.group(1)), ctx.root), int(match.group(2)),
                )
            )  # fmt: skip
        return findings

    def execute(self, ctx: RunContext) -> CheckResult:
        result = self.new()
        detected = self.interpreter_version(ctx)
        if not detected:
            return self.error(f"No se pudo ejecutar el intérprete '{ctx.python}'.")
        result.notes.append(
            f"Objetivo {ctx.target.version} ({ctx.target.source}); intérprete {detected} ({ctx.python})"
        )
        if tools.module_available("vermin"):
            result.tool_version = tools.version_of([*tools.python_module_cmd("vermin"), "--version"])
            result.findings.extend(self.vermin_findings(ctx))
        else:
            result.notes.append("vermin no instalado: solo se valida el intérprete y ruff --target-version.")
        self.suppress(ctx, result)
        result.metrics.append(self.count_metric("sintaxis_incompatible", "Sintaxis/APIs incompatibles", result))
        warn = ""
        if pyversion.major_minor(detected) != ctx.target.version:
            message = (
                f"El intérprete {detected} no coincide con python_objetivo {ctx.target.version} "
                f"(origen: {ctx.target.source})"
            )
            if ctx.ci and ctx.target.strict:
                result.status = Status.FAIL
                result.reason = message + " [CI con estricto_version=true]"
            elif ctx.ci:
                message += " [CI: estricto_version=false en qgate.toml, solo aviso]"
            warn = message
        result.metrics.append(
            Metric("version_python_desalineada", "Desalineación de versión (0 = alineado)",
                   0.0 if not warn else 1.0, direction="info")
        )  # fmt: skip
        return self.finalize(ctx, result, warn=warn)

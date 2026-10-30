"""Advanced SAST with versioned local Semgrep rules (+ public rulesets when online)."""

from __future__ import annotations

import json
from importlib import resources
from pathlib import Path

from qgate import net, tools
from qgate.checks.base import Check
from qgate.context import RunContext
from qgate.fsutil import rel_posix
from qgate.models import CheckResult, Finding, Level, Severity

PUBLIC_RULESETS = ["p/python", "p/owasp-top-ten"]
COUNTED = {Severity.HIGH, Severity.MEDIUM, Severity.CRITICAL}


def local_rules_dir() -> Path:
    return Path(str(resources.files("qgate").joinpath("rules").joinpath("semgrep")))


class SemgrepCheck(Check):
    id = "semgrep"
    title = "SAST avanzado (semgrep)"
    level = Level.STANDARD
    tool = "semgrep"
    gate_key = "semgrep_hallazgos"

    def configs(self, ctx: RunContext, result: CheckResult) -> list[str]:
        configs = [str(local_rules_dir())]
        configs += [str(ctx.root / extra) for extra in ctx.cfg.str_list("semgrep", "reglas_extra", [])]
        public = ctx.cfg.str_list("semgrep", "rulesets_publicos", PUBLIC_RULESETS)
        if public and net.reachable("https://semgrep.dev/c/p/python"):
            configs += public
            result.notes.append(f"Rulesets públicos incluidos: {', '.join(public)}")
        elif public:
            result.notes.append("Sin acceso a semgrep.dev: solo reglas locales versionadas.")
        return configs

    def execute(self, ctx: RunContext) -> CheckResult:
        exe = tools.find_executable("semgrep")
        if not exe:
            return self.skipped("semgrep no está instalado (pip install -r requirements-dev.lock).")
        result = self.new()
        result.tool_version = tools.version_of([exe, "--version"])
        args = [exe, "scan", "--json", "--metrics=off", "--disable-version-check", "--quiet"]
        for config in self.configs(ctx, result):
            args += ["--config", config]
        for pattern in ctx.cfg.excludes:
            args += ["--exclude", pattern]
        env = {"SEMGREP_SEND_METRICS": "off", "SEMGREP_ENABLE_VERSION_CHECK": "0"}
        out = tools.run([*args, *ctx.cfg.src], cwd=ctx.root, timeout=1200, env=env)
        try:
            data = json.loads(out.stdout or "{}")
        except json.JSONDecodeError:
            return self.error(f"semgrep falló: {out.stderr.strip()[:400]}")
        if out.returncode not in {0, 1} and not data.get("results"):
            return self.error(f"semgrep terminó con código {out.returncode}: {out.stderr.strip()[:400]}")
        for item in data.get("results", []):
            extra = item.get("extra", {})
            cwe = extra.get("metadata", {}).get("cwe", "")
            cwe_text = str(cwe[0] if isinstance(cwe, list) and cwe else cwe).split(":")[0]
            result.findings.append(
                Finding("semgrep", str(item.get("check_id", "")).rsplit(".", 1)[-1],
                        Severity.parse(str(extra.get("severity", "INFO"))), str(extra.get("message", "")).strip(),
                        rel_posix(ctx.root / str(item.get("path", "")), ctx.root),
                        int(item.get("start", {}).get("line", 0)), cwe=cwe_text)
            )  # fmt: skip
        if data.get("errors"):
            result.notes.append(f"semgrep reportó {len(data['errors'])} errores de análisis (ver report.json).")
        self.suppress(ctx, result)
        counted = [f for f in result.active_findings if f.severity in COUNTED]
        result.metrics.append(self.count_metric(self.gate_key, "Hallazgos ERROR/WARNING", result))
        result.metrics[-1].value = float(len(counted))
        return self.finalize(ctx, result)

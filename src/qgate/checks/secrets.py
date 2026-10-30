"""Secret detection: gitleaks (preferred) with detect-secrets as fallback."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

from qgate import tools
from qgate.checks import gitleaks_bin
from qgate.checks.base import Check
from qgate.context import RunContext
from qgate.fsutil import glob_to_regex, matches_any, rel_posix
from qgate.models import CheckResult, Finding, Level, Severity
from qgate.redact import mask

_GITLEAKS_PLACEHOLDER = "REDACTED"


def secret_excludes(ctx: RunContext) -> list[str]:
    return [*ctx.excludes, *ctx.cfg.str_list("secretos", "excluir", [])]


def gitleaks_config(ctx: RunContext) -> Path:
    """Write a config extending the default rules with path allowlists."""
    regexes = [f"(^|[/\\\\]){glob_to_regex(p)}" for p in secret_excludes(ctx)]
    body = ["[extend]", "useDefault = true", "", "[allowlist]", 'description = "qgate"', "paths = ["]
    body += [f"  '''{rx}'''," for rx in regexes]
    body.append("]")
    path = ctx.out_dir / "gitleaks.toml"
    path.write_text("\n".join(body) + "\n", encoding="utf-8")
    return path


class SecretsCheck(Check):
    id = "secrets"
    title = "Secretos en el código"
    level = Level.FAST
    tool = "gitleaks"
    gate_key = "secretos"

    def run_gitleaks(self, ctx: RunContext, binary: str, result: CheckResult) -> bool:
        # The raw report holds full secrets: it lives in a temp dir outside .qgate/ and is deleted.
        with tempfile.TemporaryDirectory(prefix="qgate-gitleaks-") as tmp:
            report = Path(tmp) / "gitleaks-report.json"
            args = [
                binary, "dir", ".", "--config", str(gitleaks_config(ctx)),
                "--report-format", "json", "--report-path", str(report),
                "--no-banner", "--exit-code", "0",
            ]  # fmt: skip
            out = tools.run(args, cwd=ctx.root, timeout=900)
            if not out.ok or not report.is_file():
                result.notes.append(f"gitleaks falló: {out.stderr.strip()[:300]}")
                return False
            items = json.loads(report.read_text(encoding="utf-8") or "[]")
        masked = [
            {**i, "Secret": mask(str(i.get("Secret", ""))), "Match": mask(str(i.get("Match", "")))} for i in items
        ]
        (ctx.out_dir / "gitleaks-report.json").write_text(json.dumps(masked, indent=2), encoding="utf-8")
        result.tool_version = gitleaks_bin.GITLEAKS_VERSION
        excludes = secret_excludes(ctx)
        for item in items:
            rel = str(item.get("File", "")).replace("\\", "/").removeprefix("./")
            if matches_any(rel, excludes):
                continue
            value = str(item.get("Secret", ""))
            known = value not in {"", _GITLEAKS_PLACEHOLDER}
            if known:
                ctx.secrets.add(value)
            shown = f" (valor: '{value}')" if known else ""
            result.findings.append(
                Finding("gitleaks", str(item.get("RuleID", "secret")), Severity.HIGH,
                        str(item.get("Description", "Posible secreto")) + shown, rel,
                        int(item.get("StartLine", 0)), cwe="CWE-798")
            )  # fmt: skip
        return True

    def run_detect_secrets(self, ctx: RunContext, result: CheckResult) -> bool:
        exe = tools.find_executable("detect-secrets")
        if not exe:
            return False
        args = [exe, "scan", "--all-files"]
        for pattern in secret_excludes(ctx):
            args += ["--exclude-files", glob_to_regex(pattern)]
        out = tools.run([*args, "."], cwd=ctx.root, timeout=900)
        if not out.ok:
            result.notes.append(f"detect-secrets falló: {out.stderr.strip()[:300]}")
            return False
        result.tool = "detect-secrets"
        result.tool_version = tools.version_of([exe, "--version"])
        data = json.loads(out.stdout or "{}")
        excludes = secret_excludes(ctx)
        for filename, items in data.get("results", {}).items():
            rel = rel_posix(ctx.root / filename, ctx.root)
            if matches_any(rel, excludes):
                continue
            for item in items:
                result.findings.append(
                    Finding("detect-secrets", str(item.get("type", "secret")), Severity.HIGH,
                            "Posible secreto detectado", rel, int(item.get("line_number", 0)),
                            cwe="CWE-798")
                )  # fmt: skip
        return True

    def execute(self, ctx: RunContext) -> CheckResult:
        result = self.new()
        binary, note = gitleaks_bin.ensure(ctx.root)
        if note:
            result.notes.append(note)
        ran = bool(binary) and self.run_gitleaks(ctx, str(binary), result)
        if not ran:
            ran = self.run_detect_secrets(ctx, result)
            if ran:
                result.notes.append("Se usó detect-secrets como alternativa a gitleaks.")
        if not ran:
            return self.skipped("Ni gitleaks ni detect-secrets están disponibles. Ejecute install.ps1 / install.sh.")
        self.suppress(ctx, result)
        result.metrics.append(self.count_metric(self.gate_key, "Secretos detectados", result))
        return self.finalize(ctx, result)

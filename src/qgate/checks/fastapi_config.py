"""Secure FastAPI configuration: AST analysis plus runtime introspection of the app."""

from __future__ import annotations

import ast
import json
from dataclasses import dataclass, field
from pathlib import Path

from qgate import tools
from qgate.checks.base import Check
from qgate.context import RunContext
from qgate.fsutil import iter_files, rel_posix
from qgate.models import CheckResult, Finding, Level, Severity

SECURITY_HEADERS = ["Content-Security-Policy", "X-Content-Type-Options", "X-Frame-Options", "Referrer-Policy"]
DOC_KWARGS = ("docs_url", "redoc_url", "openapi_url")

INTROSPECT = """
import importlib, json, os, sys
sys.path.insert(0, os.getcwd())
module, _, attr = sys.argv[1].partition(":")
app = getattr(importlib.import_module(module), attr or "app")
names = [getattr(m.cls, "__name__", str(m.cls)) for m in getattr(app, "user_middleware", [])]
print("QGATE_JSON" + json.dumps({"docs_url": app.docs_url, "redoc_url": app.redoc_url,
      "openapi_url": app.openapi_url, "debug": bool(app.debug), "middleware": names}))
"""


def production_env(ctx: RunContext) -> dict[str, str]:
    env = ctx.cfg.option("fastapi", "entorno_produccion", {})
    return {str(k): str(v) for k, v in env.items()} if isinstance(env, dict) else {}


@dataclass
class AstScan:
    findings: list[Finding] = field(default_factory=list)
    trusted_host: bool = False
    texts: str = ""


def _name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return ""


def _is_true(node: ast.AST | None) -> bool:
    return isinstance(node, ast.Constant) and node.value is True


def _has_star(node: ast.AST | None) -> bool:
    if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        return any(isinstance(e, ast.Constant) and e.value == "*" for e in node.elts)
    return isinstance(node, ast.Constant) and node.value in {"*", ".*"}


def _docs_exposed(kwargs: dict[str, ast.expr]) -> list[str]:
    """Docs kwargs missing (FastAPI default) or set to a literal string."""
    out = []
    for key in DOC_KWARGS:
        value = kwargs.get(key)
        if value is None or (isinstance(value, ast.Constant) and isinstance(value.value, str)):
            out.append(key)
    return out


def scan_file(path: Path, rel: str, scan: AstScan, allow_docs: bool) -> None:
    source = path.read_text(encoding="utf-8", errors="replace")
    scan.texts += source.lower()
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return
    for node in ast.walk(tree):
        if isinstance(node, ast.Name) and node.id == "TrustedHostMiddleware":
            scan.trusted_host = True
        if not isinstance(node, ast.Call):
            continue
        func = _name(node.func)
        kwargs = {k.arg: k.value for k in node.keywords if k.arg}
        if func in {"FastAPI", "Starlette"}:
            if _is_true(kwargs.get("debug")):
                scan.findings.append(_f("fastapi-debug", "debug=True en la aplicación", rel, node, Severity.HIGH))
            exposed = _docs_exposed(kwargs)
            if func == "FastAPI" and exposed and not allow_docs:
                scan.findings.append(
                    _f("fastapi-docs-exposed", f"Documentación expuesta por defecto: {', '.join(exposed)}", rel, node)
                )
        if func == "run" and (_is_true(kwargs.get("debug")) or _is_true(kwargs.get("reload"))):
            scan.findings.append(_f("fastapi-debug", "debug/reload activo al servir la app", rel, node, Severity.HIGH))
        args_names = [_name(a) for a in node.args]
        if "CORSMiddleware" in args_names and (
            _has_star(kwargs.get("allow_origins")) or _has_star(kwargs.get("allow_origin_regex"))
        ):
            scan.findings.append(_f("cors-wildcard", "CORS permite cualquier origen (*)", rel, node, Severity.HIGH))


def _f(rule: str, message: str, rel: str, node: ast.AST, severity: Severity = Severity.MEDIUM) -> Finding:
    cwe = {"cors-wildcard": "CWE-942", "fastapi-debug": "CWE-489", "fastapi-docs-exposed": "CWE-200"}.get(rule, "")
    return Finding("qgate-fastapi", rule, severity, message, rel, int(getattr(node, "lineno", 0)), cwe=cwe)


class FastApiConfigCheck(Check):
    id = "fastapi_config"
    title = "Configuración segura de FastAPI"
    level = Level.STANDARD
    tool = "qgate"
    gate_key = "fastapi_hallazgos"

    def introspect(self, ctx: RunContext) -> dict[str, object] | str:
        out = tools.run(
            [ctx.python, "-c", INTROSPECT, ctx.cfg.app_module], cwd=ctx.root, timeout=120, env=production_env(ctx)
        )
        for line in out.stdout.splitlines():
            if line.startswith("QGATE_JSON"):
                data: dict[str, object] = json.loads(line.removeprefix("QGATE_JSON"))
                return data
        return (out.stderr or out.stdout).strip()[-400:]

    def execute(self, ctx: RunContext) -> CheckResult:
        allow_docs = bool(ctx.cfg.option("fastapi", "permitir_docs", False))
        scan = AstScan()
        files = list(iter_files(ctx.root, ctx.cfg.src, [".py"], ctx.excludes))
        for path in files:
            scan_file(path, rel_posix(path, ctx.root), scan, allow_docs)
        if "fastapi" not in scan.texts and not ctx.cfg.app_module:
            return self.skipped("El proyecto no usa FastAPI.", mandatory=False)
        result = self.new()
        result.findings.extend(scan.findings)
        runtime: dict[str, object] | str = {}
        if ctx.cfg.app_module:
            runtime = self.introspect(ctx)
            if isinstance(runtime, str):
                return self.error(f"No se pudo importar {ctx.cfg.app_module}: {runtime}")
            result.notes.append(f"Inspección en modo producción: {json.dumps(runtime, ensure_ascii=False)}")
            result.findings = [f for f in result.findings if f.rule != "fastapi-docs-exposed"]
            exposed = [k for k in DOC_KWARGS if runtime.get(k)]
            if exposed and not allow_docs:
                result.findings.append(
                    Finding("qgate-fastapi", "fastapi-docs-exposed", Severity.MEDIUM,
                            f"En producción siguen expuestos: {', '.join(exposed)}", cwe="CWE-200")
                )  # fmt: skip
            if runtime.get("debug"):
                result.findings.append(
                    Finding("qgate-fastapi", "fastapi-debug", Severity.HIGH, "app.debug es True en producción")
                )
            middleware = runtime.get("middleware", [])
            scan.trusted_host = scan.trusted_host or (
                isinstance(middleware, list) and "TrustedHostMiddleware" in middleware
            )
        if not scan.trusted_host:
            result.findings.append(
                Finding(
                    "qgate-fastapi", "trusted-host-missing", Severity.MEDIUM, "No se configura TrustedHostMiddleware"
                )
            )
        for header in SECURITY_HEADERS:
            if header.lower() not in scan.texts:
                result.findings.append(
                    Finding("qgate-fastapi", "security-header-missing", Severity.MEDIUM,
                            f"No se encontró el header de seguridad {header}", cwe="CWE-693")
                )  # fmt: skip
        self.suppress(ctx, result)
        result.metrics.append(self.count_metric(self.gate_key, "Hallazgos de configuración", result))
        return self.finalize(ctx, result)

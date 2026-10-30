"""Full-level checks against the running app: schemathesis, HTTP behaviour, ZAP and locust."""

from __future__ import annotations

import csv
import json
import os
from pathlib import Path

from qgate import tools
from qgate.checks.app_server import AppStartError, RunningApp, dump_openapi, serve
from qgate.checks.base import Check
from qgate.checks.fastapi_config import SECURITY_HEADERS
from qgate.checks.tests_cov import junit_counts
from qgate.context import RunContext
from qgate.doctor import docker_available
from qgate.models import CheckResult, Finding, Level, Metric, Severity

API_CHECKS = "not_a_server_error,response_schema_conformance,content_type_conformance"
LEAK_MARKERS = ("Traceback (most recent call last)", 'File "', "sqlalchemy.exc", "pyodbc.")


class ApiPropertiesCheck(Check):
    id = "api_props"
    title = "Pruebas de API por propiedades (schemathesis)"
    level = Level.FULL
    tool = "schemathesis"
    gate_key = "api_fallos"

    def execute(self, ctx: RunContext) -> CheckResult:
        exe = tools.find_executable("schemathesis")
        if not exe:
            return self.skipped("schemathesis no está instalado.")
        if not ctx.cfg.app_module:
            return self.info("no hay app_module configurado (sin API que probar).")
        schema = ctx.out_dir / "openapi.json"
        problem = dump_openapi(ctx, schema)
        if problem:
            return self.error(f"No se pudo obtener el esquema OpenAPI: {problem}")
        result = self.new()
        result.tool_version = tools.version_of([exe, "--version"])
        report = ctx.out_dir / "schemathesis-junit.xml"
        examples = str(ctx.cfg.option("api", "max_ejemplos", 50))
        with serve(ctx, "schemathesis") as app:
            args = [
                exe, "run", str(schema), "--url", app.base_url, "--checks", API_CHECKS,
                "--max-examples", examples, "--seed", "1", "--report", "junit",
                "--report-junit-path", str(report), "--request-timeout", "15",
            ]  # fmt: skip
            out = tools.run(args, cwd=ctx.root, timeout=1800, env={"NO_COLOR": "1"})
        (ctx.out_dir / "schemathesis-output.txt").write_text(out.stdout + out.stderr, encoding="utf-8")
        counts = junit_counts(report)
        failures = counts["failures"] + counts["errors"]
        if out.returncode != 0 and failures == 0:
            failures = 1
        if failures:
            result.findings.append(
                Finding("schemathesis", "api-contract", Severity.HIGH,
                        f"{failures} operaciones con fallos (5xx o respuesta no conforme). Ver schemathesis-output.txt")
            )  # fmt: skip
        result.notes.append(f"{counts['tests']} operaciones probadas con hasta {examples} ejemplos cada una")
        self.suppress(ctx, result)
        result.metrics.append(
            Metric(self.gate_key, "Operaciones con fallos", float(failures if result.active_findings else 0))
        )
        return self.finalize(ctx, result)


NOT_FOUND_PATH = "/qgate-ruta-inexistente-404"


def _finding(rule: str, message: str, path: str, severity: Severity = Severity.MEDIUM, cwe: str = "") -> Finding:
    return Finding("qgate-http", rule, severity, message, path, 0, cwe)


def probe_pages(app: RunningApp, pages: list[str]) -> list[Finding]:
    findings = []
    for path in pages:
        resp = app.request("GET", path)
        if resp.status >= 400:
            findings.append(_finding("unexpected-status", f"GET {path} devolvió {resp.status}", path, Severity.HIGH))
        findings += [
            _finding("missing-header", f"GET {path} sin header {header}", path, cwe="CWE-693")
            for header in SECURITY_HEADERS
            if header.lower() not in resp.headers
        ]
        server = resp.headers.get("server", "")
        if any(ch.isdigit() for ch in server):
            findings.append(
                _finding("server-version-disclosed", f"Server revela versión: {server}", path, Severity.LOW, "CWE-200")
            )
    return findings


def probe_methods(app: RunningApp, health: str) -> list[Finding]:
    findings = []
    for method in ("TRACE", "DELETE", "PUT"):
        status = app.request(method, health).status
        if not 400 <= status < 500:
            findings.append(
                _finding("method-allowed", f"{method} {health} devolvió {status} (se esperaba 4xx)", health)
            )
    resp = app.request("GET", health, headers={"Host": "evil.example.com"})
    if resp.status < 400:
        findings.append(
            _finding("host-header", "Se acepta un Host arbitrario (falta TrustedHost)", health, cwe="CWE-644")
        )
    return findings


def probe_errors(app: RunningApp, health: str, max_kb: int) -> list[Finding]:
    findings = []
    missing = app.request("GET", NOT_FOUND_PATH)
    if missing.status != 404:
        findings.append(_finding("not-found-status", f"Ruta inexistente devolvió {missing.status}", NOT_FOUND_PATH))
    body = missing.body.decode("utf-8", errors="replace")
    if any(marker in body for marker in LEAK_MARKERS):
        findings.append(
            _finding("error-leak", "El 404 contiene trazas internas", NOT_FOUND_PATH, Severity.HIGH, "CWE-209")
        )
    big = b"x" * ((max_kb + 1) * 1024)
    status = app.request("POST", health, body=big, headers={"Content-Type": "application/octet-stream"}).status
    if status not in {400, 411, 413}:  # 405 means the body was never limited
        sev = Severity.HIGH if status >= 500 else Severity.MEDIUM
        findings.append(
            _finding("request-size", f"POST de {max_kb + 1} KB devolvió {status} (se esperaba 4xx)", health, sev)
        )
    return findings


def http_probes(app: RunningApp, ctx: RunContext) -> list[Finding]:
    health = str(ctx.cfg.option("fastapi", "ruta_salud", "/health"))
    pages = [health, *ctx.cfg.str_list("fastapi", "rutas_html", [])]
    max_kb = int(ctx.cfg.option("http", "tam_max_request_kb", 1024))
    return [*probe_pages(app, pages), *probe_methods(app, health), *probe_errors(app, health, max_kb)]


class HttpBehaviorCheck(Check):
    id = "http_behavior"
    title = "Headers y comportamiento HTTP"
    level = Level.FULL
    tool = "qgate"
    gate_key = "http_fallos"

    def execute(self, ctx: RunContext) -> CheckResult:
        if not ctx.cfg.app_module:
            return self.info("no hay app_module configurado (sin app que levantar).")
        result = self.new()
        with serve(ctx, "http") as app:
            result.findings.extend(http_probes(app, ctx))
        self.suppress(ctx, result)
        result.metrics.append(self.count_metric(self.gate_key, "Fallos de comportamiento HTTP", result))
        return self.finalize(ctx, result)


ZAP_HELP = (
    "Docker no está disponible. En Windows sin Docker: instale OWASP ZAP y ejecute "
    "'zap.bat -cmd -quickurl http://127.0.0.1:<puerto> -quickout zap.json' con la app levantada, "
    "o corra este check en un agente con Docker (etapa DeepScan)."
)


class ZapBaselineCheck(Check):
    id = "dast_zap"
    title = "DAST (OWASP ZAP baseline)"
    level = Level.FULL
    tool = "zap"
    gate_key = "zap_alertas"

    def execute(self, ctx: RunContext) -> CheckResult:
        if not ctx.cfg.app_module:
            return self.info("no hay app_module configurado (sin app que escanear).")
        if not docker_available():
            return self.skipped(ZAP_HELP)
        result = self.new()
        image = str(ctx.cfg.option("zap", "imagen", "ghcr.io/zaproxy/zaproxy:stable"))
        result.tool_version = image
        with serve(ctx, "zap") as app:
            args = [
                str(tools.find_executable("docker")), "run", "--rm", "--network", "host",
                "-v", f"{ctx.out_dir}:/zap/wrk:rw", image, "zap-baseline.py", "-t", app.base_url,
                "-J", "zap.json", "-I",
            ]  # fmt: skip
            out = tools.run(args, timeout=1800)
        report = ctx.out_dir / "zap.json"
        if not report.is_file():
            return self.error(f"ZAP no generó informe: {out.stderr.strip()[-400:]}")
        data = json.loads(report.read_text(encoding="utf-8"))
        for site in data.get("site", []):
            for alert in site.get("alerts", []):
                risk = int(alert.get("riskcode", 0))
                severity = {3: Severity.HIGH, 2: Severity.MEDIUM, 1: Severity.LOW}.get(risk, Severity.INFO)
                result.findings.append(
                    Finding("zap", str(alert.get("pluginid")), severity, str(alert.get("name")),
                            cwe=f"CWE-{alert.get('cweid')}" if alert.get("cweid") else "")
                )  # fmt: skip
        self.suppress(ctx, result)
        counted = [f for f in result.active_findings if f.severity in {Severity.HIGH, Severity.MEDIUM}]
        result.metrics.append(Metric(self.gate_key, "Alertas High/Medium", float(len(counted))))
        return self.finalize(ctx, result)


LOCUSTFILE = """
from locust import HttpUser, between, task

PATHS = {paths!r}


class GateUser(HttpUser):
    wait_time = between(0.1, 0.5)

    @task
    def browse(self):
        for path in PATHS:
            self.client.get(path, name=path)
"""


def read_locust_stats(path: Path) -> tuple[float, float, int]:
    """Return ``(p95_ms, error_pct, requests)`` from the Aggregated row."""
    with path.open(encoding="utf-8", newline="") as handle:
        for row in csv.DictReader(handle):
            if row.get("Name") == "Aggregated":
                total = int(row.get("Request Count", "0") or 0)
                failures = int(row.get("Failure Count", "0") or 0)
                p95 = float(row.get("95%", "0") or 0)
                return p95, (100.0 * failures / total if total else 100.0), total
    return 0.0, 100.0, 0


class LoadSmokeCheck(Check):
    id = "load_smoke"
    title = "Carga (smoke, locust headless)"
    level = Level.FULL
    tool = "locust"
    gate_key = "carga_p95_ms"

    def execute(self, ctx: RunContext) -> CheckResult:
        if not ctx.cfg.app_module:
            return self.info("no hay app_module configurado (sin app que cargar).")
        if not tools.module_available("locust"):
            return self.skipped("locust no está instalado.")
        result = self.new()
        result.tool_version = tools.version_of([*tools.python_module_cmd("locust"), "--version"])
        paths = ctx.cfg.str_list("carga", "rutas", [str(ctx.cfg.option("fastapi", "ruta_salud", "/health"))])
        locustfile = ctx.out_dir / "qgate_locustfile.py"
        locustfile.write_text(LOCUSTFILE.format(paths=paths), encoding="utf-8")
        users = str(ctx.cfg.option("carga", "usuarios", 20))
        duration = str(os.environ.get("QGATE_CARGA_DURACION_S", ctx.cfg.option("carga", "duracion_s", 30)))
        prefix = ctx.out_dir / "locust"
        with serve(ctx, "locust") as app:
            args = [
                *tools.python_module_cmd("locust"), "-f", str(locustfile), "--headless", "-u", users,
                "-r", users, "-t", f"{duration}s", "--host", app.base_url, "--csv", str(prefix),
                "--only-summary", "--loglevel", "WARNING",
            ]  # fmt: skip
            out = tools.run(args, cwd=ctx.out_dir, timeout=float(duration) + 180)
        stats = Path(f"{prefix}_stats.csv")
        if not stats.is_file():
            return self.error(f"locust no generó estadísticas: {out.stderr.strip()[-400:]}")
        p95, errors, total = read_locust_stats(stats)
        result.notes.append(f"{total} peticiones, {users} usuarios, {duration} s, rutas: {', '.join(paths)}")
        result.metrics.append(Metric(self.gate_key, "Latencia p95", p95, " ms"))
        result.metrics.append(Metric("carga_errores_pct", "Errores", round(errors, 2), "%"))
        return self.finalize(ctx, result)


__all__ = ["ApiPropertiesCheck", "AppStartError", "HttpBehaviorCheck", "LoadSmokeCheck", "ZapBaselineCheck"]

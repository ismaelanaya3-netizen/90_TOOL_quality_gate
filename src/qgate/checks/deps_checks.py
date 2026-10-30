"""Dependency checks: vulnerabilities, pinning, licenses and SBOM."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path

from qgate import net, tools
from qgate.checks.base import Check
from qgate.config import read_toml
from qgate.context import RunContext
from qgate.fsutil import rel_posix
from qgate.models import CheckResult, Finding, Level, Metric, Severity

DEFAULT_DENYLIST = [r"\bAGPL", r"(?<![L])GPL", r"GNU General Public", r"GNU Affero"]
_NAME_RE = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._\-]*)(\[[^\]]*\])?\s*(.*)$")


@dataclass
class Requirement:
    name: str
    spec: str
    file: str
    line: int
    raw: str

    @property
    def pinned(self) -> bool:
        return bool(re.match(r"^===?\s*[^\s,*]+$", self.spec.strip()))


def parse_requirements(path: Path, root: Path, seen: set[Path] | None = None) -> list[Requirement]:
    seen = seen if seen is not None else set()
    if path in seen or not path.is_file():
        return []
    seen.add(path)
    out: list[Requirement] = []
    rel = rel_posix(path, root)
    for number, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        line = raw.split(" #", 1)[0].strip()
        if not line or line.startswith("#") or line.startswith("--hash"):
            continue
        if line.startswith(("-r ", "--requirement ", "-c ", "--constraint ")):
            include = line.split(maxsplit=1)[1].strip()
            out += parse_requirements((path.parent / include).resolve(), root, seen)
            continue
        if line.startswith(("-e ", "--editable ")):
            out.append(Requirement(line.split(maxsplit=1)[1], "editable", rel, number, raw))
            continue
        if line.startswith("-"):
            continue
        requirement = line.split(";", 1)[0].rstrip("\\").strip()
        match = _NAME_RE.match(requirement)
        if match:
            out.append(Requirement(match.group(1), match.group(3).strip(), rel, number, raw))
    return out


def requirement_files(ctx: RunContext, section: str = "dependencias") -> list[Path]:
    names = ctx.cfg.str_list(section, "archivos", ctx.cfg.str_list("dependencias", "archivos", ["requirements.txt"]))
    return [ctx.root / name for name in names if (ctx.root / name).is_file()]


def normalize(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


class DepsAuditCheck(Check):
    id = "deps_audit"
    title = "Dependencias vulnerables (pip-audit)"
    level = Level.STANDARD
    tool = "pip-audit"
    gate_key = "vulnerabilidades"

    def build_command(self, ctx: RunContext, req: Path) -> list[str]:
        service = str(ctx.cfg.option("dependencias", "servicio", "pypi"))
        args = [
            *tools.python_module_cmd("pip_audit"), "-r", str(req), "--format", "json",
            "--progress-spinner", "off", "--vulnerability-service", service,
        ]  # fmt: skip
        if not ctx.cfg.option("dependencias", "auditar_transitivas", True):
            args += ["--no-deps", "--disable-pip"]
        return args

    def execute(self, ctx: RunContext) -> CheckResult:
        files = requirement_files(ctx)
        if not files:
            return self.skipped("No hay archivos de dependencias ([dependencias].archivos).")
        if not tools.module_available("pip_audit"):
            return self.skipped("pip-audit no está instalado.")
        service = str(ctx.cfg.option("dependencias", "servicio", "pypi"))
        url = "https://pypi.org/simple/pip/" if service == "pypi" else net.ENDPOINTS["OSV"]
        if not net.reachable(url):
            return self.skipped(f"Sin acceso a la base de vulnerabilidades ({service}).")
        result = self.new()
        result.tool_version = tools.version_of([*tools.python_module_cmd("pip_audit"), "--version"])
        for req in files:
            out = tools.run(self.build_command(ctx, req), cwd=ctx.root, timeout=1200)
            try:
                data = json.loads(out.stdout or "")
            except json.JSONDecodeError:
                return self.error(f"pip-audit falló con {req.name}: {out.stderr.strip()[-400:]}")
            for dep in data.get("dependencies", []):
                for vuln in dep.get("vulns", []):
                    fixes = ", ".join(vuln.get("fix_versions", [])) or "sin versión corregida"
                    result.findings.append(
                        Finding("pip-audit", str(vuln.get("id")), Severity.HIGH,
                                f"{dep.get('name')}=={dep.get('version')}: {vuln.get('id')} (corrige: {fixes})",
                                rel_posix(req, ctx.root), 1, cwe="CWE-1395")
                    )  # fmt: skip
        self.suppress(ctx, result)
        result.metrics.append(self.count_metric(self.gate_key, "Vulnerabilidades sin excepción", result))
        return self.finalize(ctx, result)


class DepsPinnedCheck(Check):
    id = "deps_pinned"
    title = "Dependencias fijadas (==)"
    level = Level.STANDARD
    tool = "qgate"
    gate_key = "dependencias_sin_fijar"

    def execute(self, ctx: RunContext) -> CheckResult:
        files = requirement_files(ctx)
        reqs = [r for f in files for r in parse_requirements(f, ctx.root)]
        if ctx.cfg.option("dependencias", "incluir_pyproject", False) and (ctx.root / "pyproject.toml").is_file():
            deps = read_toml(ctx.root / "pyproject.toml").get("project", {}).get("dependencies", [])
            for dep in deps:
                match = _NAME_RE.match(str(dep).split(";", 1)[0].strip())
                if match:
                    reqs.append(Requirement(match.group(1), match.group(3), "pyproject.toml", 1, str(dep)))
        if not files and not reqs:
            return self.skipped("No hay archivos de dependencias ([dependencias].archivos).")
        result = self.new()
        for req in reqs:
            if not req.pinned:
                result.findings.append(
                    Finding("qgate", "unpinned-dependency", Severity.MEDIUM,
                            f"'{req.raw.strip()}' no usa versión exacta (==)", req.file, req.line, cwe="CWE-1104")
                )  # fmt: skip
        self.suppress(ctx, result)
        result.notes.append(f"{len(reqs)} dependencias revisadas en {', '.join(f.name for f in files) or 'pyproject'}")
        result.metrics.append(self.count_metric(self.gate_key, "Dependencias sin fijar", result))
        return self.finalize(ctx, result)


class LicensesCheck(Check):
    id = "licenses"
    title = "Licencias de dependencias de runtime"
    level = Level.STANDARD
    tool = "pip-licenses"
    gate_key = "licencias_prohibidas"

    def execute(self, ctx: RunContext) -> CheckResult:
        reqs = [r for f in requirement_files(ctx, "licencias") for r in parse_requirements(f, ctx.root)]
        names = sorted({r.name for r in reqs if r.spec != "editable"})
        result = self.new()
        if not names:
            result.notes.append("Sin dependencias de runtime declaradas.")
            return self.finalize(ctx, result)
        if not tools.module_available("piplicenses"):
            return self.skipped("pip-licenses no está instalado.")
        result.tool_version = tools.version_of([*tools.python_module_cmd("piplicenses"), "--version"])
        args = [*tools.python_module_cmd("piplicenses"), "--format=json", "--from=mixed", f"--python={ctx.python}"]
        out = tools.run([*args, "--packages", *names], cwd=ctx.root, timeout=600)
        try:
            data = json.loads(out.stdout or "[]")
        except json.JSONDecodeError:
            return self.error(f"pip-licenses falló: {out.stderr.strip()[:400]}")
        denylist = [re.compile(rx) for rx in ctx.cfg.str_list("licencias", "denegadas", DEFAULT_DENYLIST)]
        allowed = {normalize(n) for n in ctx.cfg.str_list("licencias", "permitir_paquetes", [])}
        found = {normalize(str(item.get("Name", ""))) for item in data}
        for item in data:
            name, license_text = str(item.get("Name")), str(item.get("License", ""))
            if normalize(name) not in allowed and any(rx.search(license_text) for rx in denylist):
                result.findings.append(
                    Finding("pip-licenses", "license-denied", Severity.HIGH, f"{name}: licencia '{license_text}'")
                )
        missing = [n for n in names if normalize(n) not in found]
        self.suppress(ctx, result)
        result.metrics.append(self.count_metric(self.gate_key, "Licencias prohibidas", result))
        warn = f"No instaladas en el intérprete (no verificadas): {', '.join(missing)}" if missing else ""
        result.notes.append(f"{len(found)} paquetes verificados")
        return self.finalize(ctx, result, warn=warn)


class SbomCheck(Check):
    id = "sbom"
    title = "SBOM CycloneDX"
    level = Level.STANDARD
    tool = "cyclonedx-py"

    def execute(self, ctx: RunContext) -> CheckResult:
        exe = tools.find_executable("cyclonedx-py")
        if not exe:
            return self.skipped("cyclonedx-py no está instalado (paquete cyclonedx-bom).")
        result = self.new()
        result.tool_version = tools.version_of([exe, "--version"])
        target = ctx.out_dir / "sbom.cdx.json"
        files = requirement_files(ctx)
        args = [exe, "requirements", str(files[0])] if files else [exe, "environment", ctx.python]
        out = tools.run([*args, "--output-format", "JSON", "-o", str(target)], cwd=ctx.root, timeout=600)
        if not target.is_file():
            return self.error(f"No se generó el SBOM: {out.stderr.strip()[:400]}")
        components = len(json.loads(target.read_text(encoding="utf-8")).get("components", []))
        result.notes.append(f"sbom.cdx.json con {components} componentes")
        result.metrics.append(Metric("sbom_componentes", "Componentes en el SBOM", float(components), direction="info"))
        result.artifacts.append("sbom.cdx.json")
        return self.finalize(ctx, result)

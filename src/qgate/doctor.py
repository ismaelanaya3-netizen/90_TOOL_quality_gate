"""``qgate doctor``: environment diagnosis."""

from __future__ import annotations

import re
import sys
from importlib import resources
from pathlib import Path

from qgate import net, pyversion, tools
from qgate.checks import gitleaks_bin
from qgate.config import load_config

# (display name, lock package, version command)
TOOLS: list[tuple[str, str, list[str]]] = [
    ("ruff", "ruff", [*tools.python_module_cmd("ruff"), "--version"]),
    ("mypy", "mypy", [*tools.python_module_cmd("mypy"), "--version"]),
    ("pytest", "pytest", [*tools.python_module_cmd("pytest"), "--version"]),
    ("radon", "radon", [*tools.python_module_cmd("radon"), "--version"]),
    ("bandit", "bandit", [*tools.python_module_cmd("bandit"), "--version"]),
    ("pip-audit", "pip-audit", [*tools.python_module_cmd("pip_audit"), "--version"]),
    ("pip-licenses", "pip-licenses", [*tools.python_module_cmd("piplicenses"), "--version"]),
    ("vermin", "vermin", [*tools.python_module_cmd("vermin"), "--version"]),
    ("locust", "locust", [*tools.python_module_cmd("locust"), "--version"]),
]
EXECUTABLES = [("semgrep", "semgrep"), ("cyclonedx-py", "cyclonedx-bom"), ("schemathesis", "schemathesis"),
               ("detect-secrets", "detect-secrets")]  # fmt: skip

# check id -> requirement description, evaluated in ``capabilities``
NEEDS = {
    "secrets": "gitleaks o detect-secrets",
    "deps_audit": "pip-audit + red a PyPI/OSV",
    "semgrep": "semgrep (rulesets públicos solo con red)",
    "dast_zap": "Docker con imagen ZAP o ZAP instalado",
}


def lock_versions(root: Path) -> dict[str, str]:
    text = ""
    candidate = root / "requirements-dev.lock"
    if candidate.is_file():
        text = candidate.read_text(encoding="utf-8")
    if not text:
        ref = resources.files("qgate").joinpath("templates/requirements-dev.lock")
        if ref.is_file():
            text = ref.read_text(encoding="utf-8")
    versions = {}
    for line in text.splitlines():
        match = re.match(r"^([A-Za-z0-9_.\-]+)==([^\s;]+)", line.strip())
        if match:
            versions[match.group(1).lower().replace("_", "-")] = match.group(2)
    return versions


def docker_available() -> bool:
    exe = tools.find_executable("docker")
    return bool(exe) and tools.run([str(exe), "info"], timeout=30).ok


def diagnose(root: Path) -> tuple[list[str], bool]:
    lines: list[str] = []
    healthy = True
    cfg = load_config(root)
    target, source = pyversion.resolve(None, cfg.python_target)
    interp = cfg.python_executable or sys.executable
    code = "import sys;print('%d.%d.%d' % sys.version_info[:3])"
    found = tools.run([interp, "-c", code], timeout=60).stdout.strip()
    aligned = pyversion.major_minor(found) == target
    lines.append("== Python ==")
    lines.append(f"Objetivo: {target} (origen: {source})")
    lines.append(f"Intérprete: {interp} -> {found or 'NO EJECUTABLE'}")
    lines.append(f"¿Coinciden?: {'sí' if aligned else 'NO (WARN en local, FAIL en CI si estricto_version)'}")
    lines.append(f"qgate.toml: {'encontrado' if cfg.found else 'no encontrado (se usan valores por defecto)'}")
    lines.append("\n== Herramientas (instalada / lock) ==")
    lock = lock_versions(cfg.root)
    for name, package, cmd in TOOLS:
        version = tools.version_of(cmd)
        healthy &= _tool_line(lines, name, version, lock.get(package, ""))
    for name, package in EXECUTABLES:
        exe = tools.find_executable(name)
        version = tools.version_of([exe, "--version"]) if exe else ""
        healthy &= _tool_line(lines, name, version, lock.get(package, ""))
    leaks = gitleaks_bin.find(cfg.root)
    lines.append(f"gitleaks: {leaks or 'no encontrado'} (versión fijada {gitleaks_bin.GITLEAKS_VERSION})")
    docker = docker_available()
    lines.append(f"Docker: {'disponible' if docker else 'no disponible'}")
    lines.append("\n== Conectividad ==")
    reach = {name: net.reachable(url) for name, url in net.ENDPOINTS.items()}
    for name, ok in reach.items():
        lines.append(f"{name}: {'OK' if ok else 'sin acceso'}")
    lines.append("\n== Checks que podrán correr ==")
    lines += capabilities(leaks is not None or bool(tools.find_executable("detect-secrets")), reach, docker)
    return lines, healthy


def capabilities(secrets_ok: bool, reach: dict[str, bool], docker: bool) -> list[str]:
    status = {
        "secrets": secrets_ok or reach.get("GitHub", False),
        "deps_audit": reach.get("PyPI", False) or reach.get("OSV", False),
        "semgrep": bool(tools.find_executable("semgrep")),
        "dast_zap": docker,
    }
    lines = [f"{cid}: {'SÍ' if ok else 'NO'} — requiere {NEEDS[cid]}" for cid, ok in status.items()]
    if not reach.get("Semgrep Registry", False):
        lines.append("semgrep: solo reglas locales (sin acceso a semgrep.dev para p/python, p/owasp-top-ten)")
    lines.append("Resto de checks: SÍ si las herramientas de arriba están instaladas.")
    return lines


def _tool_line(lines: list[str], name: str, version: str, locked: str) -> bool:
    if not version:
        lines.append(f"{name}: NO INSTALADA (lock {locked or '-'})")
        return False
    mark = "OK" if not locked or locked == version else f"DIFERENTE al lock ({locked})"
    lines.append(f"{name}: {version} {mark}")
    return True

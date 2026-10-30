"""CLI commands, doctor and the full-level checks against running apps."""

from __future__ import annotations

from pathlib import Path

import pytest

from qgate import doctor
from qgate.cli import main
from qgate.models import GateResult, Level, Status, Verdict
from qgate.runner import run_gate
from tests.conftest import write_project

INSECURE_APP = """
from fastapi import FastAPI

app = FastAPI()


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}
"""


def test_cli_run_and_report(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    write_project(tmp_path, files={"app/a.py": "x = 1\n"})
    assert main(["report", "--path", str(tmp_path)]) == 2
    assert main(["run", "--path", str(tmp_path), "--level", "fast", "--only", "file_size,format"]) == 0
    assert main(["report", "--path", str(tmp_path)]) == 0
    out = capsys.readouterr().out
    assert "Python objetivo: 3.12 (origen: valor por defecto)" in out
    assert "VEREDICTO: APROBADO" in out
    assert "Último informe" in out


def test_cli_run_fails_with_exit_1(tmp_path: Path) -> None:
    write_project(tmp_path, files={"app/a.py": "x=1\n"})
    assert main(["run", "--path", str(tmp_path), "--level", "fast", "--only", "format", "--ci"]) == 1


def test_cli_unknown_check_is_config_error(tmp_path: Path) -> None:
    write_project(tmp_path)
    assert main(["run", "--path", str(tmp_path), "--only", "nope"]) == 2


def test_doctor(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    write_project(tmp_path, '[entorno]\npython_objetivo = "3.11"\n')
    main(["doctor", "--path", str(tmp_path)])
    out = capsys.readouterr().out
    assert "Objetivo: 3.11 (origen: qgate.toml [entorno].python_objetivo)" in out
    assert "ruff:" in out
    assert "Checks que podrán correr" in out
    assert doctor.lock_versions(Path(__file__).resolve().parents[1])["ruff"]


def test_doctor_capabilities_offline() -> None:
    lines = doctor.capabilities(False, {"PyPI": False}, False)
    assert any(line.startswith("deps_audit: NO") for line in lines)
    assert any("solo reglas locales" in line for line in lines)


@pytest.mark.slow
def test_full_checks_detect_insecure_app(tmp_path: Path) -> None:
    write_project(
        tmp_path,
        '[proyecto]\nsrc = ["app"]\napp_module = "app.main:app"\n[carga]\nduracion_s = 3\nusuarios = 2\n',
        {"app/__init__.py": "", "app/main.py": INSECURE_APP},
    )
    gate = run_gate(tmp_path, level=Level.FULL, only=["http_behavior", "fastapi_config", "load_smoke"], ci=False)
    by_id = {r.check_id: r for r in gate.results}
    http_rules = {f.rule for f in by_id["http_behavior"].findings}
    assert {"missing-header", "host-header", "request-size"} <= http_rules
    assert by_id["http_behavior"].status is Status.FAIL
    config_rules = {f.rule for f in by_id["fastapi_config"].findings}
    assert {"fastapi-docs-exposed", "trusted-host-missing", "security-header-missing"} <= config_rules
    assert by_id["load_smoke"].status is Status.PASS


def test_full_checks_skip_without_app(tmp_path: Path) -> None:
    write_project(tmp_path, files={"app/a.py": "x = 1\n"})
    gate = run_gate(tmp_path, level=Level.FULL, only=["api_props", "http_behavior", "dast_zap", "load_smoke"], ci=True)
    assert all(r.status is Status.SKIPPED and not r.mandatory for r in gate.results)
    assert gate.verdict is Verdict.APPROVED


def test_app_start_failure_is_reported(tmp_path: Path) -> None:
    write_project(
        tmp_path,
        '[proyecto]\nsrc = ["app"]\napp_module = "app.main:app"\n',
        {"app/__init__.py": "", "app/main.py": "raise RuntimeError('no arranca')\n"},
    )
    gate = run_gate(tmp_path, level=Level.FULL, only=["http_behavior", "fastapi_config", "api_props"], ci=False)
    assert all(r.status is Status.ERROR for r in gate.results)
    assert "no arranca" in gate.results[0].reason


@pytest.mark.demo
def test_demo_dashboard_passes_strict_full(demo_gate: GateResult) -> None:
    failing = {r.check_id: r.reason for r in demo_gate.results if r.status in {Status.FAIL, Status.ERROR}}
    assert failing == {}
    assert demo_gate.verdict in {Verdict.APPROVED, Verdict.APPROVED_WITH_OMISSIONS}
    omitted = {r.check_id for r in demo_gate.omissions}
    assert omitted <= {"dast_zap", "deps_audit", "secrets"}  # only environment limitations
    by_id = {r.check_id: r for r in demo_gate.results}
    coverage = next(m for m in by_id["tests"].metrics if m.key == "cobertura_total")
    assert coverage.value >= 90
    assert coverage.margin(70) is not None
    assert by_id["api_props"].status is Status.PASS
    assert by_id["http_behavior"].status is Status.PASS

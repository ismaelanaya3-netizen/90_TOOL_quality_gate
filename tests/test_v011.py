"""v0.1.1: strict version in CI, justified deactivations, secret masking, HTML grouping, INFO status."""

from __future__ import annotations

import datetime as dt
import json
import re
from pathlib import Path

import pytest

from qgate.config import load_config
from qgate.models import CheckResult, Finding, GateResult, Level, Severity, Status, Verdict
from qgate.redact import mask, redact_results
from qgate.report import console
from qgate.report.grouping import group_findings
from qgate.runner import run_gate
from tests.conftest import EXAMPLES, ROOT, write_project

# read from the fixture so the kit's own secret scan never sees a token in its tests
FAKE_TOKEN = re.search(
    r'"(ghp_\w+)"', (EXAMPLES / "vulnerable_fixtures" / "vulnapp" / "settings_fake.py").read_text(encoding="utf-8")
).group(1)  # type: ignore[union-attr]
TODAY = dt.date(2026, 10, 30)


# --- 1. python_version: estricto_version decides FAIL vs WARN under --ci ---------------------


@pytest.mark.parametrize(("strict", "expected"), [(True, Status.FAIL), (False, Status.WARN)])
def test_version_mismatch_in_ci_follows_estricto_version(tmp_path: Path, strict: bool, expected: Status) -> None:
    write_project(tmp_path, f"[entorno]\nestricto_version = {str(strict).lower()}\n", {"app/__init__.py": ""})
    gate = run_gate(tmp_path, level=Level.FAST, only=["python_version"], ci=True, python_flag="3.11")
    assert gate.results[0].status is expected
    assert gate.verdict is (Verdict.REJECTED if strict else Verdict.APPROVED)


def test_kit_config_warns_in_ci_by_design() -> None:
    """The kit deliberately uses estricto_version=false (multi-version library analysed as 3.10)."""
    cfg = load_config(ROOT)
    assert cfg.strict_version is False
    assert "DECISIÓN DELIBERADA" in (ROOT / "qgate.toml").read_text(encoding="utf-8")
    gate = run_gate(ROOT, level=Level.FAST, only=["python_version"], ci=True, python_flag="3.11")
    result = gate.results[0]
    assert result.status is Status.WARN
    assert "estricto_version=false" in result.reason


# --- 2. justified deactivations ----------------------------------------------------------------

WAIVER = """
[[checks.desactivados]]
check = "file_size"
justificacion = "Módulo generado por el ORM; se divide en el sprint 14 (DASH-88)."
responsable = "Ismael Anaya"
creada = {creada}
vence = {vence}
"""


def _waived_gate(root: Path, toml: str, ci: bool = False) -> GateResult:
    write_project(root, toml, {"app/a.py": "x = 1\n"})
    return run_gate(root, level=Level.FAST, only=["file_size", "format"], ci=ci, today=TODAY)


def test_justified_deactivation_is_an_omission(tmp_path: Path) -> None:
    gate = _waived_gate(tmp_path, WAIVER.format(creada="2026-10-01", vence="2027-01-15"), ci=True)
    result = next(r for r in gate.results if r.check_id == "file_size")
    assert result.status is Status.SKIPPED  # not converted to FAIL in CI: it is authorised
    assert result.waiver["responsable"] == "Ismael Anaya"
    assert gate.omissions == [result]
    assert gate.verdict is Verdict.APPROVED_WITH_OMISSIONS
    html = (Path(gate.out_dir) / "report.html").read_text(encoding="utf-8")
    assert "DASH-88" in html
    assert "vence 2027-01-15" in html
    data = json.loads((Path(gate.out_dir) / "report.json").read_text(encoding="utf-8"))
    assert data["summary"]["omissions"] == ["file_size"]
    assert next(c for c in data["checks"] if c["id"] == "file_size")["waiver"]["vence"] == "2027-01-15"


@pytest.mark.parametrize(
    "toml",
    [
        '[checks]\ndesactivados = ["file_size"]\n',
        WAIVER.format(creada="2026-10-01", vence="2027-01-15").replace('responsable = "Ismael Anaya"\n', ""),
        WAIVER.format(creada="2026-10-01", vence="2027-01-15").replace(
            "Módulo generado por el ORM; se divide en el sprint 14 (DASH-88).", "corto"
        ),
        WAIVER.format(creada="2026-01-01", vence="2027-01-15"),  # more than 180 days
    ],
    ids=["sin-justificacion", "sin-responsable", "justificacion-corta", "vigencia-excesiva"],
)
def test_invalid_deactivation_fails(tmp_path: Path, toml: str) -> None:
    gate = _waived_gate(tmp_path, toml)
    result = next(r for r in gate.results if r.check_id == "file_size")
    assert result.status is Status.FAIL
    assert "Desactiva" in result.reason
    assert gate.verdict is Verdict.REJECTED


def test_deactivation_without_check_id_is_config_error(tmp_path: Path) -> None:
    from qgate.cli import main

    write_project(tmp_path, '[[checks.desactivados]]\njustificacion = "sin id de check asociado"\n')
    assert main(["run", "--path", str(tmp_path), "--level", "fast"]) == 2


def test_expired_deactivation_runs_the_check_again(tmp_path: Path) -> None:
    gate = _waived_gate(tmp_path, WAIVER.format(creada="2026-05-01", vence="2026-10-01"))
    result = next(r for r in gate.results if r.check_id == "file_size")
    assert result.status is Status.PASS
    assert any("venció el 2026-10-01" in note for note in result.notes)
    assert gate.verdict is Verdict.APPROVED


# --- 3. secret masking -------------------------------------------------------------------------


def test_fixture_token_never_written_in_full(fixtures_gate: GateResult) -> None:
    qgate_dir = Path(fixtures_gate.out_dir).parent
    files = [p for p in qgate_dir.rglob("*") if p.is_file()]
    assert files
    leaks = [p for p in files if FAKE_TOKEN in p.read_text(encoding="utf-8", errors="ignore")]
    assert leaks == []
    report = (Path(fixtures_gate.out_dir) / "report.json").read_text(encoding="utf-8")
    assert "ghp_***" in report
    text = console.summary(fixtures_gate) + "".join(console.progress_line(r) for r in fixtures_gate.results)
    assert FAKE_TOKEN not in text


def test_secret_findings_are_masked_everywhere() -> None:
    bandit = Finding("bandit", "B105", Severity.LOW, "Possible hardcoded password: 'SuperSecreta123'", "a.py", 3)
    ruff = Finding("ruff", "S106", Severity.MEDIUM, 'Possible hardcoded password assigned to argument: "pwd"')
    other = Finding("semgrep", "x", Severity.LOW, "otra mención de SuperSecreta123", "b.py", 1)
    result = CheckResult("bandit", "B", Level.STANDARD, Status.FAIL, findings=[bandit, ruff, other])
    result.notes.append("nota con SuperSecreta123")
    redact_results([result], set())
    assert bandit.message.endswith("'Supe***'")
    assert ruff.message.endswith('"pwd"')  # ruff quotes the argument name, not the value (v0.1.2)
    assert "SuperSecreta123" not in other.message + result.notes[0]
    assert mask("ghp_abcdef") == "ghp_***"


# --- 4. HTML grouping --------------------------------------------------------------------------


def test_html_groups_duplicates_but_json_keeps_all(fixtures_gate: GateResult) -> None:
    html = (Path(fixtures_gate.out_dir) / "report.html").read_text(encoding="utf-8")
    assert "Detectado por: bandit (B307), ruff (S307), semgrep (qgate-eval-exec)" in html
    data = json.loads((Path(fixtures_gate.out_dir) / "report.json").read_text(encoding="utf-8"))
    eval_line = [
        f for c in data["checks"] for f in c["findings"] if f["file"] == "vulnapp/unsafe.py" and f["line"] == 10
    ]
    assert {f["tool"] for f in eval_line} == {"bandit", "ruff", "semgrep"}
    sarif = json.loads((Path(fixtures_gate.out_dir) / "results.sarif").read_text(encoding="utf-8"))
    total = sum(len(c["findings"]) for c in data["checks"])
    assert len(sarif["runs"][0]["results"]) == total
    for check in fixtures_gate.results:  # counts per check unchanged
        count = next((m for m in check.metrics if m.key.endswith("hallazgos")), None)
        if check.check_id in {"lint", "semgrep"} and count:
            assert count.value <= len(check.active_findings)


def test_group_findings_rules() -> None:
    def f(tool: str, rule: str, line: int, cwe: str = "", file: str = "a.py") -> dict[str, object]:
        return {"tool": tool, "rule": rule, "file": file, "line": line, "cwe": cwe, "severity": "MEDIUM",
                "message": rule, "suppressed_by": ""}  # fmt: skip

    groups = group_findings([
        f("bandit", "B608", 5, "CWE-89"), f("semgrep", "qgate-sql-injection-string-building", 5, "CWE-89"),
        f("ruff", "S608", 5), f("bandit", "B101", 5, "CWE-703"), f("ruff", "S608", 6),
        f("pytest", "no-tests", 0, file=""), f("pytest", "no-tests", 0, file=""),
    ])  # fmt: skip
    sizes = sorted(len(g.items) for g in groups)
    # v0.1.2: ruff S608 at line 6 joins the line-5 SQL group (same rule, compatible CWE, <= 2 lines)
    assert sizes == [1, 1, 1, 4]
    merged = next(g for g in groups if len(g.items) == 4)
    assert (
        merged.detected_by == "bandit (B608), ruff (S608), ruff (S608), semgrep (qgate-sql-injection-string-building)"
    )
    assert merged.cwe == "CWE-89"


# --- 5. INFO: nothing to verify ----------------------------------------------------------------


def test_licenses_without_runtime_dependencies_is_info(tmp_path: Path) -> None:
    write_project(tmp_path, "[licencias]\narchivos = []\n", {"app/a.py": "x = 1\n"})
    gate = run_gate(tmp_path, level=Level.STANDARD, only=["licenses", "fastapi_config"], ci=True)
    assert [r.status for r in gate.results] == [Status.INFO, Status.INFO]
    assert all(r.reason.startswith("Sin elementos que verificar") for r in gate.results)
    assert gate.verdict is Verdict.APPROVED
    junit = (Path(gate.out_dir) / "qgate-junit.xml").read_text(encoding="utf-8")
    assert "INFO: Sin elementos que verificar" in junit
    assert "s-INFO" in (Path(gate.out_dir) / "report.html").read_text(encoding="utf-8")


def test_fastapi_detected_by_import_not_by_text(tmp_path: Path) -> None:
    write_project(tmp_path, files={"app/a.py": 'TEXT = "fastapi se menciona pero no se importa"\n'})
    gate = run_gate(tmp_path, level=Level.STANDARD, only=["fastapi_config"], ci=False)
    assert gate.results[0].status is Status.INFO

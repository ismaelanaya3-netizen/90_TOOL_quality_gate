"""v0.1.2: dependency grouping/real lines, CWE precedence, Spanish messages, tolerant grouping, value masking."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from qgate import tools
from qgate.models import GateResult, Level, Status
from qgate.report.grouping import cwe_compatible, group_findings
from qgate.runner import run_gate
from tests.conftest import write_project


def f(tool: str, rule: str, line: int, cwe: str = "", file: str = "a.py", **extra: str) -> dict[str, Any]:
    finding = {"tool": tool, "rule": rule, "file": file, "line": line, "cwe": cwe, "severity": "MEDIUM",
               "message": f"{tool} {rule}", "suppressed_by": "", "package": ""}  # fmt: skip
    finding.update(extra)
    return finding


# --- 1. dependency findings: key = file + package + id, real line -------------------------------


def test_dependency_findings_never_merge_by_line_or_cwe() -> None:
    lock = "requirements-dev.lock"
    groups = group_findings([
        f("pip-audit", "CVE-2026-1", 0, "CWE-1395", lock, package="mcp"),
        f("pip-audit", "CVE-2026-2", 0, "CWE-1395", lock, package="mcp"),
        f("pip-audit", "CVE-2026-3", 0, "CWE-1395", lock, package="opentelemetry-api"),
        f("qgate", "unpinned-dependency", 2, "CWE-1104", "requirements.txt", package="requests"),
        f("qgate", "unpinned-dependency", 3, "CWE-1104", "requirements.txt", package="pyyaml"),
        f("pip-audit", "CVE-2026-4", 3, "CWE-1395", "requirements.txt", package="pyyaml"),
    ])  # fmt: skip
    assert len(groups) == 6
    assert {g.package for g in groups} == {"mcp", "opentelemetry-api", "requests", "pyyaml"}


AUDIT_JSON = {
    "dependencies": [
        {"name": "Jinja2", "version": "3.1.0", "vulns": [{"id": "GHSA-aaaa", "fix_versions": ["3.1.6"]}]},
        {"name": "urllib3", "version": "2.0.0", "vulns": [{"id": "CVE-2026-0001", "fix_versions": ["2.5.0"]}]},
        {"name": "idna", "version": "3.7", "vulns": [{"id": "PYSEC-2026-9", "fix_versions": []}]},
        {"name": "click", "version": "8.1.0", "vulns": []},
    ]
}


@pytest.fixture
def audited(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> GateResult:
    """deps_audit with a fake pip-audit answer: two vulnerable packages declared in the same lock."""
    write_project(
        tmp_path,
        '[dependencias]\narchivos = ["requirements.lock"]\nauditar_transitivas = false\n',
        {
            "requirements.lock": "# lock\n-r base.txt\nclick==8.1.0\njinja2==3.1.0\n\nurllib3==2.0.0\n",
            "base.txt": "pip==24.0\n",
        },
    )
    real_run = tools.run

    def fake_run(args: list[str], *a: Any, **k: Any) -> tools.ToolOutput:
        if "pip_audit" in args and "-r" in args:
            return tools.ToolOutput(1, json.dumps(AUDIT_JSON), "")
        return real_run(args, *a, **k)

    monkeypatch.setattr(tools, "run", fake_run)
    monkeypatch.setattr("qgate.checks.deps_checks.net.reachable", lambda url: True)
    return run_gate(tmp_path, level=Level.STANDARD, only=["deps_audit"], ci=False)


def test_pip_audit_reports_real_line(audited: GateResult) -> None:
    found = {x.package: (x.file, x.line) for x in audited.results[0].findings}
    assert found["jinja2"] == ("requirements.lock", 4)
    assert found["urllib3"] == ("requirements.lock", 6)
    assert found["idna"] == ("requirements.lock", 0)  # transitive: not declared
    transitive = next(x for x in audited.results[0].findings if x.package == "idna")
    assert "transitiva" in transitive.message
    assert audited.results[0].status is Status.FAIL


def test_two_vulnerable_packages_in_same_lock_are_two_html_rows(audited: GateResult) -> None:
    html = (Path(audited.out_dir) / "report.html").read_text(encoding="utf-8")
    rows = [r for r in html.split("<tr data-sev=")[1:] if "pip-audit" in r]
    assert len(rows) == 3
    assert "requirements.lock:4" in html
    assert "requirements.lock:6" in html
    assert "paquete: jinja2" in html


# --- 2-4. CWE precedence, Spanish message, tolerant grouping -------------------------------------


def test_cwe_precedence_and_compatibility() -> None:
    eval_group = group_findings([f("bandit", "B307", 10, "CWE-78"), f("semgrep", "qgate-eval-exec", 10, "CWE-95")])[0]
    assert eval_group.cwe == "CWE-95"
    assert eval_group.other_cwes == ["CWE-78"]
    yaml_group = group_findings(
        [f("bandit", "B506", 4, "CWE-20"), f("semgrep", "qgate-yaml-unsafe-load", 4, "CWE-502")]
    )
    assert yaml_group[0].cwe == "CWE-502"
    assert cwe_compatible("CWE-95", "CWE-78")
    assert cwe_compatible("", "CWE-89")
    assert not cwe_compatible("CWE-89", "CWE-78")


def test_spanish_message_preferred() -> None:
    group = group_findings([
        f("bandit", "B307", 10, "CWE-78", severity="HIGH", message="Use of possibly insecure function"),
        f("semgrep", "qgate-eval-exec", 10, "CWE-95", message="Uso de eval()/exec() con datos dinámicos."),
    ])[0]  # fmt: skip
    assert group.message.startswith("Uso de eval()")
    assert group.severity == "HIGH"


def test_tolerant_grouping_for_multiline_statements() -> None:
    groups = group_findings([
        f("bandit", "B608", 7, "CWE-89"), f("ruff", "S608", 7),
        f("semgrep", "qgate-sql-injection-string-building", 8, "CWE-89"),
        f("bandit", "B608", 13, "CWE-89"),  # same rule, 5 lines away: another statement
        f("bandit", "B307", 9, "CWE-78"),  # 1 line away but another rule
        f("semgrep", "qgate-sql-injection-string-building", 10, "CWE-78"),  # same rule, incompatible CWE
    ])  # fmt: skip
    places = sorted(g.place for g in groups)
    assert places == ["a.py:10", "a.py:13", "a.py:7-8", "a.py:9"]
    merged = next(g for g in groups if g.place == "a.py:7-8")
    assert merged.tools == ["bandit", "ruff", "semgrep"]


def test_fixtures_html_v012(fixtures_gate: GateResult) -> None:
    html = (Path(fixtures_gate.out_dir) / "report.html").read_text(encoding="utf-8")
    assert "vulnapp/db.py:7-8" in html
    assert "CWE-95<div class='muted'>también: CWE-78</div>" in html
    assert "CWE-502<div class='muted'>también: CWE-20</div>" in html
    assert "Uso de eval()/exec() con datos dinámicos" in html
    # gitleaks + bandit + ruff + semgrep on the token line: one hard-coded credential group
    assert (
        "Detectado por: bandit (B105), gitleaks (github-pat), ruff (S105), semgrep (qgate-hardcoded-credential)" in html
    )


# --- 5. value-only masking ----------------------------------------------------------------------


def test_masking_keeps_variable_names(fixtures_gate: GateResult) -> None:
    findings = {(x.tool, x.rule): x.message for r in fixtures_gate.results for x in r.findings}
    assert findings[("bandit", "B105")] == 'Possible hardcoded password: GITHUB_TOKEN = "ghp_***"'
    assert findings[("ruff", "S105")] == 'Possible hardcoded password assigned to: "GITHUB_TOKEN"'
    assert findings[("gitleaks", "github-pat")].endswith("(valor: 'ghp_***')")

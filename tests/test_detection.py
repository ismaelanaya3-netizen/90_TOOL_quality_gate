"""Quality control of the gate itself: every planted defect must be detected."""

from __future__ import annotations

import pytest

from qgate.models import GateResult, Status, Verdict

EXPECTED = [
    # each entry: planted defect, check id, tool and rule that must report it
    ("SQL con f-string", "semgrep", "semgrep", "qgate-sql-injection-string-building"),
    ("SQL con f-string", "bandit", "bandit", "B608"),
    ("eval", "bandit", "bandit", "B307"),
    ("eval", "semgrep", "semgrep", "qgate-eval-exec"),
    ("eval", "lint", "ruff", "S307"),
    ("shell=True", "bandit", "bandit", "B602"),
    ("shell=True", "semgrep", "semgrep", "qgate-subprocess-shell"),
    ("yaml.load inseguro", "bandit", "bandit", "B506"),
    ("yaml.load inseguro", "semgrep", "semgrep", "qgate-yaml-unsafe-load"),
    ("verify=False", "bandit", "bandit", "B501"),
    ("verify=False", "semgrep", "semgrep", "qgate-tls-verify-disabled"),
    ("CORS *", "fastapi_config", "qgate-fastapi", "cors-wildcard"),
    ("CORS *", "semgrep", "semgrep", "qgate-cors-wildcard"),
    ("debug=True", "fastapi_config", "qgate-fastapi", "fastapi-debug"),
    ("debug=True", "semgrep", "semgrep", "qgate-debug-enabled"),
    ("archivo de 1100 líneas", "file_size", "qgate", "file-too-long"),
    ("complejidad alta", "complexity", "radon", "CC-D"),
    ("dependencia sin fijar", "deps_pinned", "qgate", "unpinned-dependency"),
]


def _result(gate: GateResult, check: str):  # type: ignore[no-untyped-def]
    return next(r for r in gate.results if r.check_id == check)


def test_gate_rejects_fixtures(fixtures_gate: GateResult) -> None:
    assert fixtures_gate.verdict is Verdict.REJECTED


@pytest.mark.parametrize(("defect", "check", "tool", "rule"), EXPECTED, ids=[f"{e[0]}-{e[1]}" for e in EXPECTED])
def test_defect_detected(fixtures_gate: GateResult, defect: str, check: str, tool: str, rule: str) -> None:
    result = _result(fixtures_gate, check)
    rules = {(f.tool, f.rule) for f in result.active_findings}
    assert (tool, rule) in rules, f"{defect}: {check} no detectó {tool}/{rule}; encontrados {sorted(rules)}"
    assert result.status is Status.FAIL


def test_fake_secret_detected(fixtures_gate: GateResult) -> None:
    result = _result(fixtures_gate, "secrets")
    assert result.status is Status.FAIL
    files = {f.file for f in result.active_findings}
    assert "vulnapp/settings_fake.py" in files
    assert all(f.cwe == "CWE-798" for f in result.active_findings)


def test_findings_carry_location(fixtures_gate: GateResult) -> None:
    bandit = _result(fixtures_gate, "bandit")
    sql = next(f for f in bandit.findings if f.rule == "B608")
    assert sql.file == "vulnapp/db.py"
    assert sql.line > 0
    assert sql.cwe.startswith("CWE-")


def test_unpinned_dependencies_listed(fixtures_gate: GateResult) -> None:
    messages = " ".join(f.message for f in _result(fixtures_gate, "deps_pinned").findings)
    assert "requests" in messages
    assert "PyYAML>=6.0" in messages
    assert "fastapi" not in messages

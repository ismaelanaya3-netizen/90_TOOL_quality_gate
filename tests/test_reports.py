from __future__ import annotations

import json
import re
from pathlib import Path

import jsonschema
import pytest

from qgate.models import GateResult
from qgate.report import console
from tests.conftest import DATA


def _load(gate: GateResult, name: str) -> str:
    return (Path(gate.out_dir) / name).read_text(encoding="utf-8")


def test_sarif_is_valid_against_2_1_0_schema(fixtures_gate: GateResult) -> None:
    schema = json.loads((DATA / "sarif-schema-2.1.0.json").read_text(encoding="utf-8"))
    sarif = json.loads(_load(fixtures_gate, "results.sarif"))
    jsonschema.validate(sarif, schema)
    run = sarif["runs"][0]
    assert sarif["version"] == "2.1.0"
    assert run["tool"]["driver"]["name"] == "qgate"
    assert len(run["results"]) > 10
    ids = {rule["id"] for rule in run["tool"]["driver"]["rules"]}
    assert all(result["ruleId"] in ids for result in run["results"])
    assert all(
        r["locations"][0]["physicalLocation"]["region"]["startLine"] >= 1 for r in run["results"] if "locations" in r
    )


def test_json_report_schema(fixtures_gate: GateResult) -> None:
    data = json.loads(_load(fixtures_gate, "report.json"))
    assert data["schema_version"] == "1.0"
    assert data["verdict"] == "RECHAZADO"
    for key in ("project", "run", "python_target", "summary", "tools", "profiles", "checks", "exceptions"):
        assert key in data
    assert re.match(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}[+-]\d{2}:\d{2}", data["run"]["started_at"])
    metric = next(m for c in data["checks"] if c["id"] == "complexity" for m in c["metrics"])
    assert set(metric["thresholds"]) >= {"strict", "baseline"}
    assert "margins" in metric
    finding = next(f for c in data["checks"] for f in c["findings"] if f["tool"] == "bandit")
    assert {"tool", "rule", "severity", "file", "line", "message", "cwe"} <= set(finding)


def test_html_is_self_contained_and_spanish(fixtures_gate: GateResult) -> None:
    html = _load(fixtures_gate, "report.html")
    assert "<script src" not in html
    assert "<link" not in html
    assert not re.search(r"(src|href)=[\"']https?://", html)
    assert "RECHAZADO" in html
    assert "Márgenes frente a los perfiles" in html
    assert "prefers-color-scheme:dark" in html
    assert "@media print" in html


def test_junit_has_one_case_per_check(fixtures_gate: GateResult) -> None:
    xml = _load(fixtures_gate, "qgate-junit.xml")
    assert xml.startswith("<?xml")
    assert xml.count("<testcase") == len(fixtures_gate.results)
    assert "<failure" in xml


def test_console_summary(fixtures_gate: GateResult, capsys: pytest.CaptureFixture[str]) -> None:
    text = console.summary(fixtures_gate)
    assert "VEREDICTO: RECHAZADO" in text
    assert "\033[" not in text
    console.emit(console.progress_line(fixtures_gate.results[0]))
    assert fixtures_gate.results[0].check_id in capsys.readouterr().out


def test_tests_check_outputs_for_azure(demo_gate: GateResult) -> None:
    out = Path(demo_gate.out_dir)
    assert (out / "junit.xml").is_file()
    assert "<coverage" in (out / "coverage.xml").read_text(encoding="utf-8")
    sbom = json.loads((out / "sbom.cdx.json").read_text(encoding="utf-8"))
    assert sbom["bomFormat"] == "CycloneDX"

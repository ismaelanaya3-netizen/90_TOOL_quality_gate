"""Consolidated SARIF 2.1.0 (Azure DevOps Scans tab and GitHub code scanning)."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from qgate.models import Finding, GateResult, Severity

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
_LEVELS = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}
_SCORES = {
    Severity.CRITICAL: "9.5",
    Severity.HIGH: "8.0",
    Severity.MEDIUM: "5.5",
    Severity.LOW: "3.0",
    Severity.INFO: "1.0",
}


def rule_id(finding: Finding) -> str:
    return f"{finding.tool}/{finding.rule}"


def _fingerprint(finding: Finding) -> str:
    raw = f"{rule_id(finding)}|{finding.file}|{finding.line}|{finding.message}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:32]


def _rule(finding: Finding) -> dict[str, Any]:
    tags = ["security"] if finding.severity.rank >= Severity.MEDIUM.rank else ["quality"]
    if finding.cwe:
        tags.append(f"external/cwe/{finding.cwe.lower()}")
    return {
        "id": rule_id(finding),
        "name": finding.rule,
        "shortDescription": {"text": f"{finding.tool}: {finding.rule}"},
        "defaultConfiguration": {"level": _LEVELS[finding.severity]},
        "properties": {"tags": tags, "security-severity": _SCORES[finding.severity]},
    }


def _result(finding: Finding, rule_index: int) -> dict[str, Any]:
    item: dict[str, Any] = {
        "ruleId": rule_id(finding),
        "ruleIndex": rule_index,
        "level": _LEVELS[finding.severity],
        "message": {"text": finding.message or finding.rule},
        "partialFingerprints": {"qgate/v1": _fingerprint(finding)},
    }
    if finding.file:
        item["locations"] = [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": finding.file, "uriBaseId": "%SRCROOT%"},
                    "region": {"startLine": max(1, finding.line)},
                }
            }
        ]
    if finding.suppressed_by:
        item["suppressions"] = [
            {"kind": "external", "status": "accepted", "justification": f"qgate-exceptions: {finding.suppressed_by}"}
        ]
    return item


def build(gate: GateResult) -> dict[str, Any]:
    rules: list[dict[str, Any]] = []
    index: dict[str, int] = {}
    results: list[dict[str, Any]] = []
    for check in gate.results:
        for finding in check.findings:
            rid = rule_id(finding)
            if rid not in index:
                index[rid] = len(rules)
                rules.append(_rule(finding))
            results.append(_result(finding, index[rid]))
    root_uri = Path(str(gate.meta.get("root", "."))).resolve().as_uri() + "/"
    return {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "qgate",
                        "version": str(gate.meta.get("qgate_version", "0")),
                        "informationUri": "https://github.com/ismaelanaya3-netizen/90_TOOL_quality_gate",
                        "rules": rules,
                    }
                },
                "originalUriBaseIds": {"%SRCROOT%": {"uri": root_uri}},
                "automationDetails": {"id": f"qgate/{gate.level.value}/"},
                "results": results,
            }
        ],
    }


def write(gate: GateResult, out_dir: Path) -> Path:
    path = out_dir / "results.sarif"
    path.write_text(json.dumps(build(gate), indent=2, ensure_ascii=False), encoding="utf-8")
    return path

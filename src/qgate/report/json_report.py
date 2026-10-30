"""Stable, versioned ``report.json``."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from qgate.models import CheckResult, GateResult, Metric

SCHEMA_VERSION = "1.0"


def metric_dict(metric: Metric, profiles: dict[str, dict[str, Any]], active: str) -> dict[str, Any]:
    thresholds: dict[str, float | None] = {}
    margins: dict[str, float | None] = {}
    for name, values in profiles.items():
        raw = values.get(metric.key)
        limit = float(raw) if isinstance(raw, (int, float)) and not isinstance(raw, bool) else None
        thresholds[name] = limit
        margins[name] = metric.margin(limit)
    return {
        "key": metric.key,
        "label": metric.label,
        "value": metric.value,
        "display": metric.display,
        "unit": metric.unit,
        "direction": metric.direction,
        "thresholds": thresholds,
        "margins": margins,
        "passes_active_profile": not metric.violates(thresholds.get(active)),
    }


def check_dict(result: CheckResult, profiles: dict[str, dict[str, Any]], active: str) -> dict[str, Any]:
    return {
        "id": result.check_id,
        "title": result.title,
        "level": result.level.value,
        "status": result.status.value,
        "mandatory": result.mandatory,
        "tool": result.tool,
        "tool_version": result.tool_version,
        "duration_s": result.duration_s,
        "reason": result.reason,
        "notes": result.notes,
        "metrics": [metric_dict(m, profiles, active) for m in result.metrics],
        "findings": [f.to_dict() for f in result.findings],
        "applied_exceptions": result.applied_exceptions,
        "expired_exceptions": result.expired_exceptions,
    }


def build(gate: GateResult) -> dict[str, Any]:
    profiles: dict[str, dict[str, Any]] = gate.meta.get("profiles", {})
    findings = [f for r in gate.results for f in r.findings]
    return {
        "schema_version": SCHEMA_VERSION,
        "tool": {"name": "qgate", "version": gate.meta.get("qgate_version", "")},
        "project": {
            "name": gate.meta.get("project", ""),
            "root": gate.meta.get("root", ""),
            "commit": gate.meta.get("commit", ""),
            "branch": gate.meta.get("branch", ""),
        },
        "run": {
            "started_at": gate.started_at,
            "duration_s": gate.duration_s,
            "level": gate.level.value,
            "profile": gate.profile,
            "ci": gate.ci,
            "os": gate.meta.get("os", ""),
            "python_runtime": gate.meta.get("python_runtime", ""),
        },
        "python_target": {
            "version": gate.target.version,
            "source": gate.target.source,
            "executable": gate.target.executable,
            "strict": gate.target.strict,
        },
        "verdict": gate.verdict.value,
        "summary": {
            "checks": len(gate.results),
            "by_status": _count_status(gate),
            "findings_active": sum(1 for f in findings if not f.suppressed_by),
            "findings_suppressed": sum(1 for f in findings if f.suppressed_by),
            "omissions": [r.check_id for r in gate.omissions],
        },
        "tools": {r.tool: r.tool_version for r in gate.results if r.tool},
        "profiles": {
            name: {k: v for k, v in values.items() if k != "ruff_reglas"} for name, values in profiles.items()
        },
        "checks": [check_dict(r, profiles, gate.profile) for r in gate.results],
        "exceptions": gate.meta.get("exceptions", []),
    }


def _count_status(gate: GateResult) -> dict[str, int]:
    counts: dict[str, int] = {}
    for result in gate.results:
        counts[result.status.value] = counts.get(result.status.value, 0) + 1
    return counts


def write(gate: GateResult, out_dir: Path) -> Path:
    path = out_dir / "report.json"
    path.write_text(json.dumps(build(gate), indent=2, ensure_ascii=False, default=str), encoding="utf-8")
    return path

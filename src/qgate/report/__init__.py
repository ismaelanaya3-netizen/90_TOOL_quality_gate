"""Report writers. ``junit.xml`` and ``coverage.xml`` are produced by the tests check."""

from __future__ import annotations

from pathlib import Path

from qgate.models import GateResult
from qgate.report import html_report, json_report, junit, sarif


def write_all(gate: GateResult, out_dir: Path) -> list[Path]:
    return [
        json_report.write(gate, out_dir),
        sarif.write(gate, out_dir),
        junit.write(gate, out_dir),
        html_report.write(gate, out_dir),
    ]

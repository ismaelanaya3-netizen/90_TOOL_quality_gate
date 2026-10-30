from __future__ import annotations

from pathlib import Path

import pytest

from qgate.checks.base import Check, rank_letter
from qgate.config import ConfigError
from qgate.context import RunContext, detect_ci
from qgate.models import CheckResult, Level, Metric, Status, Verdict
from qgate.runner import _run_one, compute_verdict, run_gate, select_checks
from tests.conftest import make_ctx, write_project


class _Skipper(Check):
    id = "skipper"
    title = "Skipper"
    level = Level.FAST

    def execute(self, ctx: RunContext) -> CheckResult:
        return self.skipped("sin herramienta")


class _Boom(Check):
    id = "boom"
    title = "Boom"
    level = Level.FAST

    def execute(self, ctx: RunContext) -> CheckResult:
        raise RuntimeError("explotó")


def test_select_checks_by_level_and_only() -> None:
    fast = {c.id for c in select_checks(Level.FAST, None)}
    assert "lint" in fast
    assert "typing" not in fast
    full = {c.id for c in select_checks(Level.FULL, None)}
    assert {"api_props", "load_smoke", "dast_zap"} <= full
    assert [c.id for c in select_checks(Level.FAST, ["typing"])] == ["typing"]
    with pytest.raises(ConfigError, match="desconocidos"):
        select_checks(Level.FAST, ["nope"])


def test_ci_converts_mandatory_skips_into_failures(tmp_path: Path) -> None:
    write_project(tmp_path)
    local = _run_one(_Skipper(), make_ctx(tmp_path, ci=False))
    ci = _run_one(_Skipper(), make_ctx(tmp_path, ci=True))
    assert local.status is Status.SKIPPED
    assert ci.status is Status.FAIL
    assert "[CI]" in ci.reason


def test_optional_checks_never_fail_in_ci(tmp_path: Path) -> None:
    write_project(tmp_path, '[checks]\nopcionales = ["skipper"]\n')
    result = _run_one(_Skipper(), make_ctx(tmp_path, ci=True))
    assert result.status is Status.SKIPPED
    assert not result.mandatory


def test_unexpected_exception_becomes_error(tmp_path: Path) -> None:
    write_project(tmp_path)
    result = _run_one(_Boom(), make_ctx(tmp_path))
    assert result.status is Status.ERROR
    assert "explotó" in result.reason


def test_verdicts() -> None:
    ok = CheckResult("a", "A", Level.FAST, Status.PASS)
    warn = CheckResult("b", "B", Level.FAST, Status.WARN)
    skip = CheckResult("c", "C", Level.FAST, Status.SKIPPED)
    optional_skip = CheckResult("d", "D", Level.FAST, Status.SKIPPED, mandatory=False)
    fail = CheckResult("e", "E", Level.FAST, Status.FAIL)
    assert compute_verdict([ok, warn, optional_skip]) is Verdict.APPROVED
    assert compute_verdict([ok, skip]) is Verdict.APPROVED_WITH_OMISSIONS
    assert compute_verdict([ok, skip, fail]) is Verdict.REJECTED


def test_disabled_and_profile_not_required(tmp_path: Path) -> None:
    toml = (
        '[proyecto]\nsrc = ["app"]\n[[checks.desactivados]]\ncheck = "lint"\n'
        'justificacion = "Código heredado en migración, ver ticket DASH-12."\nresponsable = "Equipo"\n'
        "creada = 2026-10-01\nvence = 2099-01-01\n"
    )
    write_project(tmp_path, toml.replace("2099-01-01", "2027-01-01"), {"app/a.py": "x = 1\n"})
    gate = run_gate(tmp_path, level=Level.STANDARD, only=["lint", "typing"], profile="baseline", ci=True)
    by_id = {r.check_id: r for r in gate.results}
    assert by_id["lint"].status is Status.SKIPPED
    assert by_id["typing"].status is Status.SKIPPED
    assert not by_id["typing"].mandatory
    assert gate.verdict is Verdict.APPROVED_WITH_OMISSIONS  # justified deactivation is an omission
    with pytest.raises(ConfigError, match="Perfil desconocido"):
        run_gate(tmp_path, profile="nope")


def test_latest_copy_and_artifacts(tmp_path: Path) -> None:
    write_project(tmp_path, files={"app/a.py": "x = 1\n"})
    run_gate(tmp_path, level=Level.FAST, only=["file_size"], ci=False)
    gate = run_gate(tmp_path, level=Level.FAST, only=["file_size"], ci=False)
    latest = tmp_path / ".qgate" / "latest"
    for name in ("report.json", "report.html", "results.sarif", "qgate-junit.xml"):
        assert (latest / name).is_file()
    assert Path(gate.out_dir).parent == tmp_path / ".qgate"


def test_detect_ci() -> None:
    assert detect_ci({"TF_BUILD": "True"})
    assert detect_ci({"GITHUB_ACTIONS": "true"})
    assert detect_ci({"QGATE_CI": "1"})
    assert not detect_ci({"QGATE_CI": "0"})


def test_metric_helpers() -> None:
    cov = Metric("cobertura_total", "Cobertura", 91.0, "%", "min")
    assert cov.margin(70) == 21.0
    assert cov.violates(95)
    count = Metric("lint_hallazgos", "Lint", 2.0)
    assert count.margin(0) == -2.0
    assert not count.violates(None)
    assert Metric("x", "x", 1.0, direction="info").margin(0) is None
    assert rank_letter(3) == "C"
    assert rank_letter(9) == "F"

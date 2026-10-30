from __future__ import annotations

from pathlib import Path

import pytest

from qgate import pyversion
from qgate.checks.code_checks import TypingCheck
from qgate.checks.fast_checks import FormatCheck, LintCheck
from qgate.cli import main
from qgate.config import ConfigError, load_config
from qgate.models import Level, Status
from qgate.runner import run_gate
from tests.conftest import make_ctx, write_project


def test_precedence_flag_wins() -> None:
    assert pyversion.resolve("3.11", "3.10", {pyversion.ENV_VAR: "3.13"}) == ("3.11", pyversion.SOURCE_FLAG)


def test_precedence_env_over_file() -> None:
    assert pyversion.resolve(None, "3.10", {pyversion.ENV_VAR: "3.13"}) == ("3.13", pyversion.SOURCE_ENV)


def test_precedence_file_over_default() -> None:
    assert pyversion.resolve(None, "3.10", {}) == ("3.10", pyversion.SOURCE_FILE)


def test_precedence_default() -> None:
    assert pyversion.resolve(None, None, {}) == ("3.12", pyversion.SOURCE_DEFAULT)


@pytest.mark.parametrize("value", ["3", "tres", "3.x", "2.7", "3.12.1", "", "3.7"])
def test_invalid_values_raise_clear_spanish_error(value: str) -> None:
    with pytest.raises(pyversion.PythonVersionError, match=r"(inválida|no soportada)"):
        pyversion.validate(value, "prueba")


def test_invalid_value_in_toml_returns_config_exit_code(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    write_project(tmp_path, '[entorno]\npython_objetivo = "tres"\n')
    assert main(["run", "--path", str(tmp_path), "--level", "fast"]) == 2
    assert "Versión de Python inválida 'tres'" in capsys.readouterr().err


def test_helpers() -> None:
    assert pyversion.ruff_target("3.11") == "py311"
    assert pyversion.major_minor("3.12.7") == "3.12"


def test_version_reaches_ruff_and_mypy_commands(tmp_path: Path) -> None:
    write_project(tmp_path, '[proyecto]\nsrc = ["app"]\nexcluir = ["legacy/**"]\n')
    ctx = make_ctx(tmp_path, version="3.11")
    fmt = FormatCheck().build_command(ctx)
    lint = LintCheck().build_command(ctx)
    typing = TypingCheck().build_command(ctx)
    assert fmt[fmt.index("--target-version") + 1] == "py311"
    assert lint[lint.index("--target-version") + 1] == "py311"
    assert "legacy/**" in lint
    assert typing[typing.index("--python-version") + 1] == "3.11"
    assert "--strict" in typing
    assert typing[-1] == "app"


def test_python_executable_is_passed_to_mypy(tmp_path: Path) -> None:
    write_project(tmp_path, '[entorno]\npython_ejecutable = "C:/Python311/python.exe"\n')
    command = TypingCheck().build_command(make_ctx(tmp_path))
    assert command[command.index("--python-executable") + 1] == "C:/Python311/python.exe"


def _version_result(root: Path, ci: bool, flag: str | None = "3.11"):  # type: ignore[no-untyped-def]
    gate = run_gate(root, level=Level.FAST, only=["python_version"], ci=ci, python_flag=flag)
    return gate, gate.results[0]


def test_mismatch_warns_locally_and_fails_in_ci(tmp_path: Path) -> None:
    write_project(tmp_path, "[entorno]\nestricto_version = true\n", {"app/__init__.py": ""})
    gate, local = _version_result(tmp_path, ci=False)
    assert local.status is Status.WARN
    assert gate.target.source == pyversion.SOURCE_FLAG
    _, ci = _version_result(tmp_path, ci=True)
    assert ci.status is Status.FAIL
    assert "3.11" in ci.reason


def test_mismatch_only_warns_in_ci_when_not_strict(tmp_path: Path) -> None:
    write_project(tmp_path, "[entorno]\nestricto_version = false\n", {"app/__init__.py": ""})
    _, ci = _version_result(tmp_path, ci=True)
    assert ci.status is Status.WARN


def test_vermin_flags_syntax_newer_than_target(tmp_path: Path) -> None:
    write_project(tmp_path, '[proyecto]\nsrc = ["app"]\n', {"app/mod.py": "type Alias = int\n"})
    _, result = _version_result(tmp_path, ci=False, flag="3.10")
    assert result.status is Status.FAIL
    assert any(f.rule == "requires-newer-python" for f in result.findings)


def test_target_recorded_in_report(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import json

    write_project(tmp_path, '[entorno]\npython_objetivo = "3.11"\n', {"app/__init__.py": ""})
    monkeypatch.setenv(pyversion.ENV_VAR, "3.13")
    gate = run_gate(tmp_path, level=Level.FAST, only=["python_version"], ci=False)
    data = json.loads((Path(gate.out_dir) / "report.json").read_text(encoding="utf-8"))
    assert data["python_target"]["version"] == "3.13"
    assert data["python_target"]["source"] == pyversion.SOURCE_ENV
    assert "3.13" in (Path(gate.out_dir) / "report.html").read_text(encoding="utf-8")


def test_bad_strict_flag_type(tmp_path: Path) -> None:
    write_project(tmp_path, '[entorno]\nestricto_version = "si"\n')
    with pytest.raises(ConfigError):
        load_config(tmp_path)

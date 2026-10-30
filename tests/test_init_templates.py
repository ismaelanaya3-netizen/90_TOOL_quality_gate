from __future__ import annotations

import shutil
from pathlib import Path

import pytest
import yaml

from qgate.cli import main
from qgate.config import ConfigError, load_config
from qgate.init_project import TEMPLATES, init_project, read_template
from qgate.models import Level, Status
from qgate.pyproject_merge import merge_text
from qgate.runner import run_gate
from tests.conftest import EXAMPLES, ROOT


@pytest.fixture
def bare_demo(tmp_path: Path) -> Path:
    target = tmp_path / "dashboard"
    shutil.copytree(EXAMPLES / "demo_dashboard", target, ignore=shutil.ignore_patterns(".qgate", "__pycache__"))
    for name in ("qgate.toml", "qgate-exceptions.toml"):
        (target / name).unlink()
    # an existing project with partial tool configuration that must be preserved
    (target / "pyproject.toml").write_text(
        '[project]\nname = "dashboard"\n\n[tool.ruff]\nline-length = 120\n\n'
        '[tool.ruff.lint.per-file-ignores]\n"tests/**" = ["S101"]\n\n'
        '[tool.pytest.ini_options]\ntestpaths = ["tests"]\n',
        encoding="utf-8",
    )
    return target


def test_init_creates_files_and_merges(bare_demo: Path) -> None:
    original = (bare_demo / "pyproject.toml").read_text(encoding="utf-8")
    lines = init_project(bare_demo, "app.main:app", "app", "3.11", force=False)
    for dest in TEMPLATES.values():
        assert (bare_demo / dest).is_file(), dest
    cfg = load_config(bare_demo)
    assert cfg.python_target == "3.11"
    assert cfg.app_module == "app.main:app"
    pipeline = yaml.safe_load((bare_demo / "azure-pipelines.yml").read_text(encoding="utf-8"))
    version = next(p for p in pipeline["parameters"] if p["name"] == "pythonVersion")
    assert version["default"] == "3.11"
    merged = (bare_demo / "pyproject.toml").read_text(encoding="utf-8")
    assert merged.startswith(original.rstrip("\n"))  # existing content untouched
    assert (bare_demo / "pyproject.toml.bak").read_text(encoding="utf-8") == original
    assert "tool.pytest.ini_options" not in merged.split("Añadido por qgate")[1]  # already existed
    assert ".qgate/" in (bare_demo / ".gitignore").read_text(encoding="utf-8")
    assert any(line.startswith("+++") for line in lines)  # diff is shown


def test_init_is_idempotent_and_respects_existing(bare_demo: Path) -> None:
    init_project(bare_demo, "app.main:app", "app", None, force=False)
    (bare_demo / "qgate.toml").write_text("# mío\n", encoding="utf-8")
    lines = init_project(bare_demo, "app.main:app", "app", None, force=False)
    assert (bare_demo / "qgate.toml").read_text(encoding="utf-8") == "# mío\n"
    assert any("sin cambios" in line for line in lines)
    assert any("ya contiene .qgate/" in line for line in lines)
    init_project(bare_demo, "app.main:app", "app", None, force=True)
    assert (bare_demo / "qgate.toml.bak").read_text(encoding="utf-8") == "# mío\n"


def test_gate_runs_on_initialized_project(bare_demo: Path) -> None:
    assert main(["init", str(bare_demo), "--python", "3.12"]) == 0
    gate = run_gate(bare_demo, level=Level.FAST, ci=False)
    assert {r.check_id for r in gate.results} >= {"lint", "format", "secrets", "file_size"}
    assert all(r.status in {Status.PASS, Status.WARN} for r in gate.results)


def test_init_errors(tmp_path: Path) -> None:
    with pytest.raises(ConfigError):
        init_project(tmp_path / "missing", "a:b", "a", None, False)
    with pytest.raises(ConfigError):
        merge_text("[tool\n")


def test_merge_creates_pyproject_when_missing(tmp_path: Path) -> None:
    init_project(tmp_path, "app.main:app", "app", None, force=False)
    assert "[tool.mypy]" in (tmp_path / "pyproject.toml").read_text(encoding="utf-8")
    assert not (tmp_path / "pyproject.toml.bak").exists()


@pytest.mark.parametrize("path", ["azure-pipelines.yml", ".pre-commit-config.yaml", ".github/workflows/ci.yml"])
def test_repository_yaml_is_valid(path: str) -> None:
    data = yaml.safe_load((ROOT / path).read_text(encoding="utf-8"))
    assert isinstance(data, dict)


def test_pipeline_template_structure() -> None:
    data = yaml.safe_load(read_template("azure-pipelines.yml"))
    names = {p["name"] for p in data["parameters"]}
    assert {"poolName", "pythonVersion", "runFull"} <= names
    assert [s["stage"] for s in data["stages"]] == ["Validate", "DeepScan"]
    text = read_template("azure-pipelines.yml")
    for task in ("PublishTestResults@2", "PublishCodeCoverageResults@2", "CodeAnalysisLogs", "qgate-report", "Cache@2"):
        assert task in text
    assert "qgate run --level standard --ci" in text
    assert "qgate run --level full --ci" in text
    yaml.safe_load(read_template("pre-commit-config.yaml"))


def test_lock_template_matches_repository_lock() -> None:
    assert read_template("requirements-dev.lock") == (ROOT / "requirements-dev.lock").read_text(encoding="utf-8")

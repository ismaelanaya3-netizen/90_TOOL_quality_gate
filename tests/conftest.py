"""Shared fixtures for the kit's own test-suite."""

from __future__ import annotations

import os
import shutil
import sys
from collections.abc import Iterator
from pathlib import Path

import pytest

from qgate.config import load_config
from qgate.context import RunContext
from qgate.exceptions_registry import ExceptionRegistry
from qgate.models import GateResult, Level, TargetPython
from qgate.runner import run_gate

ROOT = Path(__file__).resolve().parents[1]
EXAMPLES = ROOT / "examples"
DATA = Path(__file__).parent / "data"


def copy_example(name: str, dest: Path) -> Path:
    target = dest / name
    shutil.copytree(EXAMPLES / name, target, ignore=shutil.ignore_patterns(".qgate", "__pycache__", "*.pyc"))
    return target


def make_ctx(root: Path, version: str = "3.12", ci: bool = False, profile: str = "strict") -> RunContext:
    cfg = load_config(root)
    out = root / ".qgate" / "test"
    out.mkdir(parents=True, exist_ok=True)
    return RunContext(
        cfg=cfg,
        profile_name=profile,
        level=Level.FULL,
        ci=ci,
        target=TargetPython(version, "test", sys.executable, cfg.strict_version),
        out_dir=out,
        registry=ExceptionRegistry(),
    )


def write_project(root: Path, toml: str = "", files: dict[str, str] | None = None) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    (root / "qgate.toml").write_text(toml, encoding="utf-8")
    (root / "ruff.toml").write_text("line-length = 120\n", encoding="utf-8")
    for rel, content in (files or {}).items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    return root


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    """The demo dashboard needs Python >= 3.11 (typing.Self, its pinned dependencies)."""
    if sys.version_info >= (3, 11):
        return
    skip = pytest.mark.skip(reason="demo_dashboard requiere Python >= 3.11")
    for item in items:
        if "demo_gate" in getattr(item, "fixturenames", ()) or item.get_closest_marker("demo"):
            item.add_marker(skip)


@pytest.fixture(autouse=True)
def _isolated_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in ("QGATE_CI", "TF_BUILD", "GITHUB_ACTIONS", "QGATE_PYTHON_OBJETIVO"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("QGATE_NO_COLOR", "1")


@pytest.fixture(scope="session")
def fixtures_gate(tmp_path_factory: pytest.TempPathFactory) -> Iterator[GateResult]:
    root = copy_example("vulnerable_fixtures", tmp_path_factory.mktemp("fixtures"))
    saved = {k: os.environ.pop(k, None) for k in ("QGATE_CI", "TF_BUILD", "GITHUB_ACTIONS")}
    try:
        yield run_gate(root, level=Level.STANDARD, ci=False)
    finally:
        os.environ.update({k: v for k, v in saved.items() if v is not None})


@pytest.fixture(scope="session")
def demo_gate(tmp_path_factory: pytest.TempPathFactory) -> Iterator[GateResult]:
    root = copy_example("demo_dashboard", tmp_path_factory.mktemp("demo"))
    os.environ["QGATE_CARGA_DURACION_S"] = "5"
    try:
        yield run_gate(root, level=Level.FULL, ci=False)
    finally:
        os.environ.pop("QGATE_CARGA_DURACION_S", None)

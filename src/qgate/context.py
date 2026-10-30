"""Run context shared by every check."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from qgate.config import Config
from qgate.exceptions_registry import ExceptionRegistry
from qgate.models import Level, TargetPython

CI_VARS = ("QGATE_CI", "TF_BUILD", "GITHUB_ACTIONS")


def detect_ci(env: dict[str, str] | None = None) -> bool:
    environ = dict(os.environ) if env is None else env
    return any(environ.get(name, "").strip().lower() in {"1", "true", "yes"} for name in CI_VARS)


@dataclass
class RunContext:
    cfg: Config
    profile_name: str
    level: Level
    ci: bool
    target: TargetPython
    out_dir: Path
    registry: ExceptionRegistry

    @property
    def root(self) -> Path:
        return self.cfg.root

    @property
    def profile(self) -> dict[str, Any]:
        return self.cfg.profiles[self.profile_name]

    def threshold(self, key: str) -> float | None:
        value = self.profile.get(key)
        if value is None or isinstance(value, bool):
            return None
        if isinstance(value, (int, float)):
            return float(value)
        return None

    def profile_value(self, key: str, default: Any = None) -> Any:
        return self.profile.get(key, default)

    @property
    def python(self) -> str:
        """Interpreter that runs the project code (tests, app, audits)."""
        return self.target.executable

    @property
    def excludes(self) -> list[str]:
        return self.cfg.all_excludes

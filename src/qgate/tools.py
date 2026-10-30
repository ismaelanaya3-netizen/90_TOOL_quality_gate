"""Single entry point for external processes.

Every command is a list of arguments executed with ``shell=False`` and a timeout,
so it behaves the same on Windows and Linux and cannot be subject to shell injection.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess  # nosec B404 - centralized, list-based execution only
import sys
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

DEFAULT_TIMEOUT = 900
# Tools must never phone home during a gate run (semgrep --version alone can block for minutes).
QUIET_ENV = {
    "PYTHONIOENCODING": "utf-8",
    "SEMGREP_ENABLE_VERSION_CHECK": "0",
    "SEMGREP_SEND_METRICS": "off",
    "PIP_DISABLE_PIP_VERSION_CHECK": "1",
}


@dataclass
class ToolOutput:
    returncode: int
    stdout: str
    stderr: str
    timed_out: bool = False
    missing: bool = False

    @property
    def ok(self) -> bool:
        return self.returncode == 0 and not self.timed_out and not self.missing


def run(
    args: Sequence[str],
    cwd: Path | None = None,
    timeout: float = DEFAULT_TIMEOUT,
    env: Mapping[str, str] | None = None,
) -> ToolOutput:
    """Run ``args`` (never through a shell) and capture text output."""
    full_env = {**os.environ, **QUIET_ENV, **(env or {})}
    try:
        proc = subprocess.run(  # noqa: S603  # nosec B603 - argument list, shell=False
            list(args),
            cwd=str(cwd) if cwd else None,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            env=full_env,
            check=False,
        )
    except FileNotFoundError as exc:
        return ToolOutput(127, "", str(exc), missing=True)
    except subprocess.TimeoutExpired as exc:
        out = exc.stdout if isinstance(exc.stdout, str) else ""
        return ToolOutput(124, out, f"Tiempo agotado tras {timeout} s", timed_out=True)
    return ToolOutput(proc.returncode, proc.stdout or "", proc.stderr or "")


def spawn(args: Sequence[str], cwd: Path, env: Mapping[str, str], log_path: Path) -> subprocess.Popen[bytes]:
    """Start a long-running background process (used to serve the app)."""
    with log_path.open("wb") as log:  # the child keeps its own handle
        return subprocess.Popen(  # noqa: S603  # nosec B603 - argument list, shell=False
            list(args), cwd=str(cwd), env={**os.environ, **QUIET_ENV, **env}, stdout=log, stderr=log
        )


def scripts_dir() -> Path:
    """Directory with console scripts of the running interpreter (bin or Scripts)."""
    return Path(sys.executable).parent


def find_executable(name: str, extra_dirs: Sequence[Path] = ()) -> str | None:
    """Locate an executable next to the interpreter, in ``extra_dirs`` or in PATH."""
    suffixes = [".exe", ".cmd", ".bat", ""] if os.name == "nt" else [""]
    for folder in [*extra_dirs, scripts_dir()]:
        for suffix in suffixes:
            candidate = folder / f"{name}{suffix}"
            if candidate.is_file():
                return str(candidate)
    return shutil.which(name)


def python_module_cmd(module: str, python: str | None = None) -> list[str]:
    return [python or sys.executable, "-m", module]


_VERSION_RE = re.compile(r"(\d+\.\d+(?:\.\d+)?)")


def version_of(args: Sequence[str]) -> str:
    """Return the first ``x.y.z`` found in the output of ``args`` (or ``""``)."""
    out = run(args, timeout=60)
    if out.missing or out.timed_out:
        return ""
    match = _VERSION_RE.search(out.stdout + " " + out.stderr)
    return match.group(1) if match else ""


def module_available(module: str, python: str | None = None) -> bool:
    code = f"import importlib.util,sys;sys.exit(0 if importlib.util.find_spec('{module}') else 1)"
    return run([python or sys.executable, "-c", code], timeout=60).returncode == 0

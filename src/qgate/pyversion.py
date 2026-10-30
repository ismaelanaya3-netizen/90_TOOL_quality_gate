"""Resolution of the target Python version (flag > env var > qgate.toml > default)."""

from __future__ import annotations

import os
import re
from collections.abc import Mapping

DEFAULT_PYTHON = "3.12"
ENV_VAR = "QGATE_PYTHON_OBJETIVO"
_VERSION_RE = re.compile(r"^3\.(\d{1,2})$")

SOURCE_FLAG = "flag --python"
SOURCE_ENV = f"variable de entorno {ENV_VAR}"
SOURCE_FILE = "qgate.toml [entorno].python_objetivo"
SOURCE_DEFAULT = "valor por defecto"


class PythonVersionError(ValueError):
    """Raised when a configured Python version is not valid."""


def validate(value: str, origin: str) -> str:
    text = str(value).strip()
    if not _VERSION_RE.match(text):
        msg = (
            f"Versión de Python inválida '{value}' (origen: {origin}). "
            'Use el formato major.minor, por ejemplo "3.12".'
        )
        raise PythonVersionError(msg)
    minor = int(text.split(".")[1])
    if minor < 8:
        msg = f"Versión de Python '{value}' no soportada (origen: {origin}). Mínimo 3.8."
        raise PythonVersionError(msg)
    return text


def resolve(
    flag: str | None,
    file_value: str | None,
    env: Mapping[str, str] | None = None,
) -> tuple[str, str]:
    """Return ``(version, source)`` following the documented precedence."""
    environ = os.environ if env is None else env
    if flag:
        return validate(flag, SOURCE_FLAG), SOURCE_FLAG
    env_value = environ.get(ENV_VAR, "").strip()
    if env_value:
        return validate(env_value, SOURCE_ENV), SOURCE_ENV
    if file_value:
        return validate(file_value, SOURCE_FILE), SOURCE_FILE
    return DEFAULT_PYTHON, SOURCE_DEFAULT


def ruff_target(version: str) -> str:
    """``3.12`` -> ``py312``."""
    return "py" + version.replace(".", "")


def major_minor(version_text: str) -> str:
    parts = version_text.strip().split(".")
    return ".".join(parts[:2])

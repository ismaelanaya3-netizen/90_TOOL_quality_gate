"""Loading of ``qgate.toml`` and profile definitions."""

from __future__ import annotations

import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

if sys.version_info >= (3, 11):
    import tomllib
else:  # pragma: no cover - exercised only on Python 3.10
    import tomli as tomllib

CONFIG_FILE = "qgate.toml"
EXCEPTIONS_FILE = "qgate-exceptions.toml"

STRICT_RUFF_RULES = [
    "E", "F", "W", "I", "N", "UP", "B", "S", "C90", "SIM",
    "RUF", "ASYNC", "PTH", "DTZ", "T20", "ERA",
]  # fmt: skip

DEFAULT_PROFILES: dict[str, dict[str, Any]] = {
    "strict": {
        "descripcion": "Perfil exigente del kit (superconjunto del pipeline corporativo).",
        "ruff_reglas": STRICT_RUFF_RULES,
        "formato_diferencias": 0,
        "lint_hallazgos": 0,
        "secretos": 0,
        "archivo_lineas_max": 1000,
        "archivo_lineas_aviso": 600,
        "complejidad_peor": 3,
        "complejidad_promedio": 1,
        "mypy_errores": 0,
        "pruebas_fallidas": 0,
        "cobertura_total": 85,
        "cobertura_critica": 95,
        "bandit_severidad_minima": "LOW",
        "bandit_hallazgos": 0,
        "semgrep_hallazgos": 0,
        "vulnerabilidades": 0,
        "dependencias_sin_fijar": 0,
        "licencias_prohibidas": 0,
        "fastapi_hallazgos": 0,
        "version_python_desalineada": 0,
        "sintaxis_incompatible": 0,
        "api_fallos": 0,
        "http_fallos": 0,
        "zap_alertas": 0,
        "carga_p95_ms": 800,
        "carga_errores_pct": 0,
    },
    "baseline": {
        "descripcion": "Lo que exigiría un pipeline corporativo típico.",
        "ruff_reglas": ["E4", "E7", "E9", "F"],
        "archivo_lineas_max": 2000,
        "archivo_lineas_aviso": None,
        "complejidad_peor": 4,
        "complejidad_promedio": 2,
        "mypy_errores": None,
        "cobertura_total": 70,
        "cobertura_critica": None,
        "bandit_severidad_minima": "HIGH",
        "semgrep_hallazgos": None,
        "dependencias_sin_fijar": None,
        "fastapi_hallazgos": None,
        "version_python_desalineada": None,
        "api_fallos": None,
        "http_fallos": None,
        "carga_p95_ms": 2000,
        "carga_errores_pct": 1,
    },
}

DEFAULT_EXCLUDES = [
    ".git/**", ".venv/**", "venv/**", "env/**", ".qgate/**", ".nox/**", ".tox/**",
    "**/__pycache__/**", "node_modules/**", "build/**", "dist/**", ".mypy_cache/**",
    ".ruff_cache/**", ".pytest_cache/**", "*.egg-info/**", "runtime/**",
]  # fmt: skip


class ConfigError(ValueError):
    """Invalid or unreadable configuration (message in Spanish)."""


def read_toml(path: Path) -> dict[str, Any]:
    try:
        with path.open("rb") as handle:
            return tomllib.load(handle)
    except tomllib.TOMLDecodeError as exc:
        msg = f"El archivo {path.name} no es TOML válido: {exc}"
        raise ConfigError(msg) from exc


def build_profiles(raw: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Merge built-in profiles with ``[perfiles.*]`` tables (supports ``hereda``)."""
    profiles = {name: dict(values) for name, values in DEFAULT_PROFILES.items()}
    # baseline inherits every key it does not redefine from strict
    profiles["baseline"] = {**profiles["strict"], **profiles["baseline"]}
    user = raw.get("perfiles", {})
    if not isinstance(user, dict):
        msg = "La sección [perfiles] debe ser una tabla."
        raise ConfigError(msg)
    for name, values in user.items():
        if not isinstance(values, dict):
            msg = f"El perfil '{name}' debe ser una tabla [perfiles.{name}]."
            raise ConfigError(msg)
        parent = str(values.get("hereda", name if name in profiles else "strict"))
        if parent not in profiles:
            msg = f"El perfil '{name}' hereda de '{parent}', que no existe."
            raise ConfigError(msg)
        merged = {**profiles[parent], **values}
        # TOML has no null: the string "no_exigido" disables a threshold
        profiles[name] = {k: (None if v == "no_exigido" else v) for k, v in merged.items()}
    return profiles


@dataclass
class Config:
    root: Path
    name: str
    src: list[str]
    tests: str
    app_module: str
    excludes: list[str]
    python_target: str | None
    python_executable: str
    strict_version: bool
    profile: str
    disabled: list[str]
    optional: list[str]
    profiles: dict[str, dict[str, Any]]
    raw: dict[str, Any] = field(default_factory=dict)
    found: bool = False

    def section(self, name: str) -> dict[str, Any]:
        value = self.raw.get(name, {})
        return value if isinstance(value, dict) else {}

    def option(self, section: str, key: str, default: Any) -> Any:
        return self.section(section).get(key, default)

    def str_list(self, section: str, key: str, default: list[str]) -> list[str]:
        value = self.option(section, key, default)
        if isinstance(value, str):
            return [value]
        if not isinstance(value, list):
            msg = f"[{section}].{key} debe ser una lista de textos."
            raise ConfigError(msg)
        return [str(item) for item in value]

    @property
    def all_excludes(self) -> list[str]:
        return [*DEFAULT_EXCLUDES, *self.excludes]


def _as_bool(value: Any, where: str) -> bool:
    if isinstance(value, bool):
        return value
    msg = f"{where} debe ser true o false."
    raise ConfigError(msg)


def load_config(root: Path) -> Config:
    root = root.resolve()
    path = root / CONFIG_FILE
    raw: dict[str, Any] = read_toml(path) if path.is_file() else {}
    proyecto = raw.get("proyecto", {})
    entorno = raw.get("entorno", {})
    checks = raw.get("checks", {})
    cfg = Config(
        root=root,
        name=str(proyecto.get("nombre", root.name)),
        src=[],
        tests=str(proyecto.get("pruebas", "tests")),
        app_module=str(proyecto.get("app_module", "")),
        excludes=[],
        python_target=(str(entorno["python_objetivo"]) if "python_objetivo" in entorno else None),
        python_executable=str(entorno.get("python_ejecutable", "")),
        strict_version=_as_bool(entorno.get("estricto_version", True), "[entorno].estricto_version"),
        profile=str(checks.get("perfil", "strict")),
        disabled=[],
        optional=[],
        profiles=build_profiles(raw),
        raw=raw,
        found=path.is_file(),
    )
    cfg.src = cfg.str_list("proyecto", "src", _guess_src(root))
    cfg.excludes = cfg.str_list("proyecto", "excluir", [])
    cfg.disabled = cfg.str_list("checks", "desactivados", [])
    cfg.optional = cfg.str_list("checks", "opcionales", [])
    if cfg.profile not in cfg.profiles:
        msg = f"El perfil por defecto '{cfg.profile}' no está definido."
        raise ConfigError(msg)
    return cfg


def _guess_src(root: Path) -> list[str]:
    for candidate in ("app", "src"):
        if (root / candidate).is_dir():
            return [candidate]
    return ["."]

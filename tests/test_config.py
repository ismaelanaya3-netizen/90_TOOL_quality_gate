from __future__ import annotations

from pathlib import Path

import pytest

from qgate.config import DEFAULT_PROFILES, ConfigError, build_profiles, load_config
from tests.conftest import write_project


def test_defaults_without_file(tmp_path: Path) -> None:
    (tmp_path / "app").mkdir()
    cfg = load_config(tmp_path)
    assert not cfg.found
    assert cfg.src == ["app"]
    assert cfg.profile == "strict"
    assert cfg.python_target is None


def test_guess_src_fallback(tmp_path: Path) -> None:
    assert load_config(tmp_path).src == ["."]
    (tmp_path / "src").mkdir()
    assert load_config(tmp_path).src == ["src"]


def test_baseline_inherits_strict_and_relaxes() -> None:
    profiles = build_profiles({})
    assert profiles["baseline"]["cobertura_total"] == 70
    assert profiles["baseline"]["mypy_errores"] is None
    assert profiles["baseline"]["secretos"] == DEFAULT_PROFILES["strict"]["secretos"]


def test_custom_profile_inherits_and_disables() -> None:
    raw = {"perfiles": {"epm_ti": {"hereda": "baseline", "cobertura_total": 80, "secretos": "no_exigido"}}}
    profiles = build_profiles(raw)
    assert profiles["epm_ti"]["cobertura_total"] == 80
    assert profiles["epm_ti"]["secretos"] is None
    assert profiles["epm_ti"]["complejidad_peor"] == 4


def test_override_builtin_profile() -> None:
    profiles = build_profiles({"perfiles": {"strict": {"archivo_lineas_max": 400}}})
    assert profiles["strict"]["archivo_lineas_max"] == 400
    assert profiles["strict"]["cobertura_total"] == 85


@pytest.mark.parametrize(
    "raw",
    [{"perfiles": []}, {"perfiles": {"x": 1}}, {"perfiles": {"x": {"hereda": "nope"}}}],
)
def test_invalid_profiles(raw: dict[str, object]) -> None:
    with pytest.raises(ConfigError):
        build_profiles(raw)


def test_invalid_toml_and_types(tmp_path: Path) -> None:
    write_project(tmp_path, "[proyecto\n")
    with pytest.raises(ConfigError, match="no es TOML válido"):
        load_config(tmp_path)
    write_project(tmp_path, "[proyecto]\nsrc = 3\n")
    with pytest.raises(ConfigError, match="lista"):
        load_config(tmp_path)
    write_project(tmp_path, '[checks]\nperfil = "inexistente"\n')
    with pytest.raises(ConfigError, match="no está definido"):
        load_config(tmp_path)


def test_options_and_lists(tmp_path: Path) -> None:
    write_project(tmp_path, '[proyecto]\nsrc = "app"\n[fastapi]\nruta_salud = "/ping"\n')
    cfg = load_config(tmp_path)
    assert cfg.src == ["app"]
    assert cfg.option("fastapi", "ruta_salud", "/health") == "/ping"
    assert cfg.section("missing") == {}
    assert ".venv/**" in cfg.all_excludes

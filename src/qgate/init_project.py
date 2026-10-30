"""``qgate init``: apply the kit to an existing project without breaking it."""

from __future__ import annotations

import shutil
from importlib import resources
from pathlib import Path

from qgate import pyversion
from qgate.config import ConfigError
from qgate.pyproject_merge import merge_file

# template name -> destination relative to the project
TEMPLATES: dict[str, str] = {
    "qgate.toml": "qgate.toml",
    "qgate-exceptions.toml": "qgate-exceptions.toml",
    "pre-commit-config.yaml": ".pre-commit-config.yaml",
    "azure-pipelines.yml": "azure-pipelines.yml",
    "noxfile.py.tmpl": "noxfile.py",
    "requirements-dev.lock": "requirements-dev.lock",
    "vscode-tasks.json": ".vscode/tasks.json",
}


def read_template(name: str) -> str:
    return resources.files("qgate").joinpath("templates").joinpath(name).read_text(encoding="utf-8")


def render(text: str, values: dict[str, str]) -> str:
    for key, value in values.items():
        text = text.replace(f"@@{key}@@", value)
    return text


def ensure_gitignore(root: Path) -> str:
    path = root / ".gitignore"
    current = path.read_text(encoding="utf-8") if path.is_file() else ""
    if any(line.strip() in {".qgate/", ".qgate", "/.qgate/"} for line in current.splitlines()):
        return ".gitignore: ya contiene .qgate/"
    prefix = "" if not current or current.endswith("\n") else "\n"
    path.write_text(f"{current}{prefix}# Quality Gate Kit\n.qgate/\n", encoding="utf-8")
    return ".gitignore: se añadió .qgate/"


def init_project(root: Path, app_module: str, src: str, python: str | None, force: bool) -> list[str]:
    root = root.resolve()
    if not root.is_dir():
        msg = f"La ruta {root} no existe o no es una carpeta."
        raise ConfigError(msg)
    version = pyversion.validate(python, "flag --python") if python else pyversion.DEFAULT_PYTHON
    values = {
        "NAME": root.name,
        "APP_MODULE": app_module,
        "SRC": src,
        "PYTHON": version,
    }
    lines = [f"Aplicando Quality Gate Kit en {root} (python_objetivo = {version})"]
    for template, dest_rel in TEMPLATES.items():
        dest = root / dest_rel
        if dest.exists() and not force:
            lines.append(f"Se conserva {dest_rel} (ya existe; use --force para reemplazar)")
            continue
        if dest.exists():
            shutil.copy2(dest, dest.with_name(dest.name + ".bak"))
            lines.append(f"Copia de seguridad: {dest_rel}.bak")
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(render(read_template(template), values), encoding="utf-8")
        lines.append(f"Creado {dest_rel}")
    lines.extend(merge_file(root / "pyproject.toml"))
    lines.append(ensure_gitignore(root))
    lines.append("Siguiente paso: qgate doctor && qgate run --level fast")
    return lines

"""Non-destructive merge of tool sections into ``pyproject.toml``."""

from __future__ import annotations

import difflib
import shutil
import sys
from pathlib import Path
from typing import Any

from qgate.config import ConfigError

if sys.version_info >= (3, 11):
    import tomllib
else:  # pragma: no cover - exercised only on Python 3.10
    import tomli as tomllib

# Tables added only when absent. Dotted header -> body.
SECTIONS: dict[str, str] = {
    "tool.ruff": "line-length = 120\n",
    "tool.ruff.lint.per-file-ignores": '"tests/**" = ["S101", "S105", "S106"]\n',
    "tool.mypy": "strict = true\n",
    "tool.pytest.ini_options": 'testpaths = ["tests"]\naddopts = "-ra"\n',
    "tool.coverage.run": "branch = true\n",
}


def _has_table(data: dict[str, Any], dotted: str) -> bool:
    node: Any = data
    for part in dotted.split("."):
        if not isinstance(node, dict) or part not in node:
            return False
        node = node[part]
    return True


def merge_text(original: str) -> tuple[str, list[str]]:
    """Return ``(new_text, added_tables)``. Existing tables are never modified."""
    try:
        data = tomllib.loads(original) if original.strip() else {}
    except tomllib.TOMLDecodeError as exc:
        msg = f"pyproject.toml no es TOML válido; no se modifica: {exc}"
        raise ConfigError(msg) from exc
    added = [name for name in SECTIONS if not _has_table(data, name)]
    if not added:
        return original, []
    blocks = [f"[{name}]\n{SECTIONS[name]}" for name in added]
    header = "\n# --- Añadido por qgate init (no modifica secciones existentes) ---\n"
    text = original.rstrip("\n") + "\n" + header + "\n".join(blocks)
    tomllib.loads(text)  # the result must still be valid TOML
    return text, added


def merge_file(path: Path) -> list[str]:
    """Merge into ``path``; returns human readable lines including a unified diff."""
    original = path.read_text(encoding="utf-8") if path.is_file() else ""
    text, added = merge_text(original)
    if not added:
        return ["pyproject.toml: sin cambios (todas las secciones ya existen)."]
    lines = [f"pyproject.toml: se añaden {', '.join(added)}"]
    if path.is_file():
        backup = path.with_name(path.name + ".bak")
        shutil.copy2(path, backup)
        lines.append(f"Copia de seguridad: {backup.name}")
    diff = difflib.unified_diff(
        original.splitlines(), text.splitlines(), "pyproject.toml (antes)", "pyproject.toml (después)", lineterm=""
    )
    lines.extend(diff)
    path.write_text(text, encoding="utf-8")
    return lines

"""Auditable registry of justified exceptions with mandatory expiry dates."""

from __future__ import annotations

import datetime as dt
from dataclasses import dataclass, field
from fnmatch import fnmatchcase
from pathlib import Path
from typing import Any

from qgate.config import EXCEPTIONS_FILE, ConfigError, read_toml
from qgate.models import Finding

MAX_DAYS = 180
SOON_DAYS = 30


@dataclass
class GateException:
    rule: str
    path: str
    justification: str
    owner: str
    created: dt.date
    expires: dt.date
    tool: str = ""
    used: int = 0

    @property
    def ident(self) -> str:
        scope = f"{self.tool}:" if self.tool else ""
        return f"{scope}{self.rule}@{self.path}"

    def state(self, today: dt.date) -> str:
        if self.expires < today:
            return "vencida"
        if (self.expires - today).days < SOON_DAYS:
            return "por_vencer"
        return "vigente"

    def matches(self, finding: Finding) -> bool:
        if self.tool and self.tool != finding.tool:
            return False
        if not fnmatchcase(finding.rule, self.rule):
            return False
        return fnmatchcase(finding.file, self.path) or self.path in {"*", "**"}

    def to_dict(self, today: dt.date) -> dict[str, Any]:
        return {
            "id": self.ident,
            "regla": self.rule,
            "herramienta": self.tool,
            "archivo": self.path,
            "justificacion": self.justification,
            "responsable": self.owner,
            "creada": self.created.isoformat(),
            "vence": self.expires.isoformat(),
            "estado": self.state(today),
            "usos": self.used,
        }


@dataclass
class ExceptionRegistry:
    items: list[GateException] = field(default_factory=list)
    today: dt.date = field(default_factory=lambda: dt.datetime.now(dt.timezone.utc).date())

    def apply(self, findings: list[Finding]) -> tuple[list[str], list[str]]:
        """Mark suppressed findings. Return ``(applied_ids, expired_messages)``."""
        applied: list[str] = []
        expired: list[str] = []
        for finding in findings:
            for item in self.items:
                if not item.matches(finding):
                    continue
                item.used += 1
                if item.state(self.today) == "vencida":
                    expired.append(
                        f"Excepción vencida {item.ident} (venció el {item.expires.isoformat()}); "
                        f"el hallazgo {finding.rule} en {finding.file}:{finding.line} vuelve a contar."
                    )
                    break
                finding.suppressed_by = item.ident
                if item.ident not in applied:
                    applied.append(item.ident)
                break
        return applied, expired


def _parse_date(value: Any, where: str) -> dt.date:
    if isinstance(value, dt.datetime):
        return value.date()
    if isinstance(value, dt.date):
        return value
    try:
        return dt.date.fromisoformat(str(value))
    except ValueError as exc:
        msg = f"{where}: fecha inválida '{value}' (use AAAA-MM-DD)."
        raise ConfigError(msg) from exc


def validate_record(entry: dict[str, Any], where: str, keys: tuple[str, ...]) -> tuple[dt.date, dt.date]:
    """Common audit rules: mandatory fields, ISO dates, max validity, real justification."""
    for key in keys:
        if not str(entry.get(key, "")).strip():
            msg = f"{where}: falta el campo obligatorio '{key}'."
            raise ConfigError(msg)
    created = _parse_date(entry["creada"], where)
    expires = _parse_date(entry["vence"], where)
    if expires < created:
        msg = f"{where}: 'vence' es anterior a 'creada'."
        raise ConfigError(msg)
    if (expires - created).days > MAX_DAYS:
        msg = f"{where}: la vigencia máxima es de {MAX_DAYS} días."
        raise ConfigError(msg)
    if len(str(entry["justificacion"]).strip()) < 15:
        msg = f"{where}: la justificación debe explicar el motivo (mínimo 15 caracteres)."
        raise ConfigError(msg)
    return created, expires


def parse_exception(entry: dict[str, Any], index: int) -> GateException:
    where = f"{EXCEPTIONS_FILE} excepción #{index}"
    created, expires = validate_record(entry, where, ("regla", "justificacion", "responsable", "creada", "vence"))
    return GateException(
        rule=str(entry["regla"]),
        path=str(entry.get("archivo", "**")),
        justification=str(entry["justificacion"]).strip(),
        owner=str(entry["responsable"]).strip(),
        created=created,
        expires=expires,
        tool=str(entry.get("herramienta", "")),
    )


def load_registry(root: Path, today: dt.date | None = None) -> ExceptionRegistry:
    path = root / EXCEPTIONS_FILE
    registry = ExceptionRegistry()
    if today is not None:
        registry.today = today
    if not path.is_file():
        return registry
    raw = read_toml(path)
    entries = raw.get("excepcion", [])
    if not isinstance(entries, list):
        msg = f"{EXCEPTIONS_FILE}: use tablas [[excepcion]]."
        raise ConfigError(msg)
    for index, entry in enumerate(entries, start=1):
        rules = entry.get("regla")
        # ``regla`` may list several ids sharing the same justification
        for rule in rules if isinstance(rules, list) else [rules]:
            registry.items.append(parse_exception({**entry, "regla": rule}, index))
    return registry


def render_list(registry: ExceptionRegistry) -> str:
    if not registry.items:
        return "No hay excepciones registradas."
    groups = {"vigente": "VIGENTES", "por_vencer": "POR VENCER (< 30 días)", "vencida": "VENCIDAS"}
    lines: list[str] = []
    for state, title in groups.items():
        items = [e for e in registry.items if e.state(registry.today) == state]
        lines.append(f"\n{title} ({len(items)})")
        for item in items:
            days = (item.expires - registry.today).days
            lines.append(
                f"  - {item.ident} | vence {item.expires.isoformat()} ({days} días) | "
                f"{item.owner} | {item.justification}"
            )
    return "\n".join(lines).lstrip("\n")

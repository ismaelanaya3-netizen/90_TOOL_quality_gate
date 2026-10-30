"""Justified deactivation of checks (``[[checks.desactivados]]``), same model as exceptions."""

from __future__ import annotations

import datetime as dt
from dataclasses import dataclass
from typing import Any

from qgate.config import CONFIG_FILE, ConfigError
from qgate.exceptions_registry import validate_record

KEYS = ("check", "justificacion", "responsable", "creada", "vence")


@dataclass
class Waiver:
    check: str
    justification: str = ""
    owner: str = ""
    created: dt.date | None = None
    expires: dt.date | None = None
    error: str = ""  # invalid or unjustified entry -> the check FAILs

    def expired(self, today: dt.date) -> bool:
        return self.expires is not None and self.expires < today

    def to_dict(self) -> dict[str, str]:
        return {
            "check": self.check,
            "justificacion": self.justification,
            "responsable": self.owner,
            "creada": self.created.isoformat() if self.created else "",
            "vence": self.expires.isoformat() if self.expires else "",
        }


def parse_waivers(entries: list[Any]) -> dict[str, Waiver]:
    """Map check id -> waiver. Invalid entries are kept with ``error`` set (never raise)."""
    waivers: dict[str, Waiver] = {}
    for index, entry in enumerate(entries, start=1):
        if isinstance(entry, str):
            waivers[entry] = Waiver(
                entry,
                error=(
                    f"Desactivado sin justificación: use [[checks.desactivados]] con check, justificacion, "
                    f"responsable, creada y vence en {CONFIG_FILE}."
                ),
            )
            continue
        if not isinstance(entry, dict) or not str(entry.get("check", "")).strip():
            msg = f"{CONFIG_FILE} [[checks.desactivados]] #{index}: falta 'check' (id del check a desactivar)."
            raise ConfigError(msg)
        check = str(entry["check"]).strip()
        try:
            created, expires = validate_record(entry, f"{CONFIG_FILE} [[checks.desactivados]] #{index}", KEYS)
        except ConfigError as exc:
            waivers[check] = Waiver(check, error=f"Desactivación inválida: {exc}")
            continue
        waivers[check] = Waiver(
            check,
            justification=str(entry["justificacion"]).strip(),
            owner=str(entry["responsable"]).strip(),
            created=created,
            expires=expires,
        )
    return waivers

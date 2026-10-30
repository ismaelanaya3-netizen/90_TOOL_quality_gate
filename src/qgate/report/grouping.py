"""Group duplicate findings (same file + line + CWE or equivalent rule) for the HTML view only.

report.json and SARIF keep every finding; per-check counts never change.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
# Rules that describe the same defect across tools, normalized to a bandit id or a qgate concept.
EQUIVALENT = {
    "qgate-sql-injection-string-building": "B608",
    "qgate-eval-exec": "B307",
    "qgate-subprocess-shell": "B602",
    "qgate-yaml-unsafe-load": "B506",
    "qgate-tls-verify-disabled": "B501",
    "qgate-unsafe-deserialization": "B301",
    "qgate-insecure-xml-parser": "B314",
    "qgate-hardcoded-credential": "B105",
    "qgate-debug-enabled": "fastapi-debug",
    "qgate-cors-wildcard": "cors-wildcard",
    "github-pat": "secret",
    "GitHub Token": "secret",
}
_RUFF_BANDIT = re.compile(r"^S(\d{3})$")  # ruff flake8-bandit S307 == bandit B307


def concept(finding: dict[str, Any]) -> str:
    rule = str(finding["rule"])
    if finding["tool"] in {"gitleaks", "detect-secrets"}:
        return "secret"
    match = _RUFF_BANDIT.match(rule)
    if finding["tool"] == "ruff" and match:
        rule = f"B{match.group(1)}"
    return EQUIVALENT.get(rule, rule)


@dataclass
class Group:
    file: str
    line: int
    items: list[dict[str, Any]] = field(default_factory=list)

    def accepts(self, finding: dict[str, Any]) -> bool:
        cwes = {i["cwe"] for i in self.items if i["cwe"]}
        concepts = {concept(i) for i in self.items}
        return bool(finding["cwe"] and finding["cwe"] in cwes) or concept(finding) in concepts

    @property
    def severity(self) -> str:
        return str(min((i["severity"] for i in self.items), key=SEVERITIES.index))

    @property
    def cwe(self) -> str:
        return str(next((i["cwe"] for i in self.items if i["cwe"]), ""))

    @property
    def tools(self) -> list[str]:
        return sorted({i["tool"] for i in self.items})

    @property
    def detected_by(self) -> str:
        return ", ".join(f"{i['tool']} ({i['rule']})" for i in sorted(self.items, key=lambda i: (i["tool"], i["rule"])))

    @property
    def suppressed(self) -> bool:
        return all(i["suppressed_by"] for i in self.items)

    @property
    def message(self) -> str:
        # the most severe finding carries the most explicit message
        return str(min(self.items, key=lambda i: SEVERITIES.index(i["severity"]))["message"])


def group_findings(findings: list[dict[str, Any]]) -> list[Group]:
    """Findings without a location are never merged (they are not the same occurrence)."""
    groups: list[Group] = []
    by_place: dict[tuple[str, int], list[Group]] = {}
    for finding in findings:
        place = (str(finding["file"]), int(finding["line"]))
        candidates = by_place.setdefault(place, []) if finding["file"] and finding["line"] else []
        target = next((g for g in candidates if g.accepts(finding)), None)
        if target is None:
            target = Group(place[0], place[1])
            groups.append(target)
            if finding["file"] and finding["line"]:
                candidates.append(target)
        target.items.append(finding)
    return sorted(groups, key=lambda g: (SEVERITIES.index(g.severity), g.file, g.line))

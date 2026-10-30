"""Group duplicate findings for the HTML view only.

Code findings merge when they are the same defect: same file, an equivalent rule (or a compatible
CWE on the same line) and lines at most ``LINE_TOLERANCE`` apart (multi-line statements).
Dependency findings merge only on file + package + rule id: never by line or CWE.
report.json and SARIF keep every finding; per-check counts never change.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
LINE_TOLERANCE = 2
CREDENTIAL = "hardcoded-credential"
# Rules that describe the same defect across tools, normalized to a bandit id or a qgate concept.
EQUIVALENT = {
    "qgate-sql-injection-string-building": "B608",
    "qgate-eval-exec": "B307",
    "qgate-subprocess-shell": "B602",
    "qgate-yaml-unsafe-load": "B506",
    "qgate-tls-verify-disabled": "B501",
    "qgate-unsafe-deserialization": "B301",
    "qgate-insecure-xml-parser": "B314",
    "qgate-debug-enabled": "fastapi-debug",
    "qgate-cors-wildcard": "cors-wildcard",
    "qgate-hardcoded-credential": CREDENTIAL,
    "B105": CREDENTIAL,
    "B106": CREDENTIAL,
    "B107": CREDENTIAL,
}
SECRET_TOOLS = {"gitleaks", "detect-secrets"}
SPANISH_TOOLS = {"qgate", "qgate-fastapi", "qgate-http"}
# CWE precedence by family: within a family the first entry is the most specific and wins as the
# group CWE; CWEs of the same family are compatible. e.g. eval is CWE-95 (eval injection), more
# specific than CWE-78; unsafe YAML/pickle is CWE-502, more specific than CWE-20. For credentials
# CWE-798 wins: bandit labels every literal as a password (CWE-259) even when it is a token.
CWE_FAMILIES: list[list[str]] = [
    ["CWE-95", "CWE-94", "CWE-78", "CWE-77"],
    ["CWE-89", "CWE-943"],
    ["CWE-502", "CWE-20"],
    ["CWE-611", "CWE-776", "CWE-20"],
    ["CWE-798", "CWE-259", "CWE-321", "CWE-522"],
    ["CWE-295", "CWE-297"],
    ["CWE-918"],
    ["CWE-22", "CWE-23"],
    ["CWE-942", "CWE-346"],
    ["CWE-489", "CWE-215"],
    ["CWE-1395", "CWE-1104", "CWE-937"],
]
_RUFF_BANDIT = re.compile(r"^S(\d{3})$")  # ruff flake8-bandit S307 == bandit B307


def concept(finding: dict[str, Any]) -> str:
    rule = str(finding["rule"])
    if finding["tool"] in SECRET_TOOLS:
        return CREDENTIAL
    match = _RUFF_BANDIT.match(rule)
    if finding["tool"] == "ruff" and match:
        rule = f"B{match.group(1)}"
    return EQUIVALENT.get(rule, rule)


def cwe_rank(cwe: str) -> int:
    """Position inside its family (0 = most specific); unknown CWEs rank last."""
    return min((family.index(cwe) for family in CWE_FAMILIES if cwe in family), default=len(CWE_FAMILIES))


def cwe_compatible(a: str, b: str) -> bool:
    """Empty, equal or in the same precedence family."""
    return not a or not b or a == b or any(a in family and b in family for family in CWE_FAMILIES)


def is_spanish(finding: dict[str, Any]) -> bool:
    """Messages written by qgate itself (local rules) are in Spanish."""
    return finding["tool"] in SPANISH_TOOLS or (
        finding["tool"] == "semgrep" and str(finding["rule"]).startswith("qgate-")
    )


@dataclass
class Group:
    file: str
    items: list[dict[str, Any]] = field(default_factory=list)
    package: str = ""

    @property
    def lines(self) -> list[int]:
        return sorted({int(i["line"]) for i in self.items})

    @property
    def line(self) -> int:
        return self.lines[0]

    @property
    def place(self) -> str:
        if not self.file:
            return ""
        first, last = self.lines[0], self.lines[-1]
        if not first:
            return self.file
        return f"{self.file}:{first}" if first == last else f"{self.file}:{first}-{last}"

    def _cwes(self) -> list[str]:
        ordered: list[str] = []
        for item in self.items:
            if item["cwe"] and item["cwe"] not in ordered:
                ordered.append(str(item["cwe"]))
        return ordered

    @property
    def cwe(self) -> str:
        cwes = self._cwes()
        return min(cwes, key=lambda c: (cwe_rank(c), cwes.index(c))) if cwes else ""

    @property
    def other_cwes(self) -> list[str]:
        return [c for c in self._cwes() if c != self.cwe]

    def accepts(self, finding: dict[str, Any]) -> bool:
        if self.package or finding.get("package"):
            same_rule = concept(finding) in {concept(i) for i in self.items}
            return self.package == finding.get("package") and self.file == finding["file"] and same_rule
        line = int(finding["line"])
        if not finding["file"] or not line or finding["file"] != self.file:
            return False
        concepts = {concept(i) for i in self.items}
        cwes = self._cwes()
        if line in self.lines and (
            concept(finding) in concepts or (finding["cwe"] and any(cwe_compatible(finding["cwe"], c) for c in cwes))
        ):
            return True
        near = any(abs(line - other) <= LINE_TOLERANCE for other in self.lines)
        return near and concept(finding) in concepts and all(cwe_compatible(finding["cwe"], c) for c in cwes)

    @property
    def severity(self) -> str:
        return str(min((i["severity"] for i in self.items), key=SEVERITIES.index))

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
        """Spanish message from qgate's local rules first, then the most severe finding."""
        best = min(self.items, key=lambda i: (not is_spanish(i), SEVERITIES.index(i["severity"])))
        return str(best["message"])


def group_findings(findings: list[dict[str, Any]]) -> list[Group]:
    """Findings without a location are never merged (they are not the same occurrence)."""
    groups: list[Group] = []
    by_file: dict[str, list[Group]] = {}
    for finding in findings:
        located = bool(finding["file"]) and (bool(finding["line"]) or bool(finding.get("package")))
        candidates = by_file.setdefault(str(finding["file"]), []) if located else []
        target = next((g for g in candidates if g.accepts(finding)), None)
        if target is None:
            target = Group(str(finding["file"]), package=str(finding.get("package", "")))
            groups.append(target)
            if located:
                candidates.append(target)
        target.items.append(finding)
    return sorted(groups, key=lambda g: (SEVERITIES.index(g.severity), g.file, g.line, g.package))

"""Mask secret values before anything is printed or written (console, JSON, HTML, SARIF, JUnit)."""

from __future__ import annotations

import re
from collections.abc import Iterable

from qgate.models import CheckResult, Finding

VISIBLE = 4
SECRET_TOOLS = {"gitleaks", "detect-secrets"}
# rules whose message quotes the hard-coded value
SECRET_RULES = {
    ("bandit", "B105"),
    ("bandit", "B106"),
    ("bandit", "B107"),
    ("ruff", "S105"),
    ("ruff", "S106"),
    ("ruff", "S107"),
}
_QUOTED = re.compile(r"""(['"])(.+?)\1""")


def mask(value: str) -> str:
    """``ghp_abcdef`` -> ``ghp_***``."""
    return value[:VISIBLE] + "***"


def is_secret_finding(finding: Finding) -> bool:
    return finding.tool in SECRET_TOOLS or (finding.tool, finding.rule) in SECRET_RULES


def _scrub(text: str, secrets: Iterable[str]) -> str:
    for value in sorted(secrets, key=len, reverse=True):
        if len(value) > VISIBLE and value in text:
            text = text.replace(value, mask(value))
    return text


def redact_finding(finding: Finding, secrets: set[str]) -> None:
    if is_secret_finding(finding):
        for match in _QUOTED.finditer(finding.message):
            secrets.add(match.group(2))
        finding.message = _QUOTED.sub(lambda m: m.group(1) + mask(m.group(2)) + m.group(1), finding.message)
    finding.message = _scrub(finding.message, secrets)


def redact_results(results: Iterable[CheckResult], secrets: set[str]) -> None:
    """Two passes: collect/mask quoted values of secret findings, then scrub every text field."""
    results = list(results)
    for result in results:
        for finding in result.findings:
            redact_finding(finding, secrets)
    for result in results:
        for finding in result.findings:
            finding.message = _scrub(finding.message, secrets)
        result.reason = _scrub(result.reason, secrets)
        result.notes = [_scrub(note, secrets) for note in result.notes]

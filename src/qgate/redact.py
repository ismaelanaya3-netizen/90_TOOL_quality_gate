"""Mask secret values before anything is printed or written (console, JSON, HTML, SARIF, JUnit).

Only the literal value is masked; variable or argument names are kept, e.g.
``GITHUB_TOKEN = "ghp_***"`` or ``Possible hardcoded password assigned to: "pwd"`` (ruff quotes the
name, not the value, so nothing is masked there).
"""

from __future__ import annotations

import re
from collections.abc import Iterable

from qgate.models import CheckResult, Finding

VISIBLE = 4
SECRET_TOOLS = {"gitleaks", "detect-secrets"}
# rules whose message may quote the hard-coded value
SECRET_RULES = {
    ("bandit", "B105"),
    ("bandit", "B106"),
    ("bandit", "B107"),
    ("ruff", "S105"),
    ("ruff", "S106"),
    ("ruff", "S107"),
}
# where a value appears: bandit "password: 'x'", qgate/gitleaks "valor: 'x'", a source statement
# "NAME = 'x'" / "NAME: str = 'x'" / "name='x'" (keyword argument). Group "v" is the literal.
_VALUE_PATTERNS = [
    re.compile(r"""(?:password|valor):\s*(?P<q>['"])(?P<v>.+?)(?P=q)"""),
    re.compile(r"""\b[A-Za-z_]\w*\s*(?::\s*[\w\[\], .|]+?)?\s*=\s*(?P<q>['"])(?P<v>.+?)(?P=q)"""),
]


def mask(value: str) -> str:
    """``ghp_abcdef`` -> ``ghp_***``."""
    return value[:VISIBLE] + "***"


def is_secret_finding(finding: Finding) -> bool:
    return finding.tool in SECRET_TOOLS or (finding.tool, finding.rule) in SECRET_RULES


def _mask_values(text: str, secrets: set[str]) -> str:
    for pattern in _VALUE_PATTERNS:

        def repl(match: re.Match[str]) -> str:
            value = match.group("v")
            if value.endswith("***"):  # already masked
                return match.group(0)
            secrets.add(value)
            start, end = match.span("v")
            whole = match.group(0)
            offset = match.start()
            return whole[: start - offset] + mask(value) + whole[end - offset :]

        text = pattern.sub(repl, text)
    return text


def _scrub(text: str, secrets: Iterable[str]) -> str:
    for value in sorted(secrets, key=len, reverse=True):
        if len(value) > VISIBLE and value in text:
            text = text.replace(value, mask(value))
    return text


def redact_finding(finding: Finding, secrets: set[str]) -> None:
    if is_secret_finding(finding):
        finding.message = _mask_values(finding.message, secrets)
    finding.message = _scrub(finding.message, secrets)


def redact_results(results: Iterable[CheckResult], secrets: set[str]) -> None:
    """Two passes: mask values of secret findings, then scrub every text field for those values."""
    results = list(results)
    for result in results:
        for finding in result.findings:
            redact_finding(finding, secrets)
    for result in results:
        for finding in result.findings:
            finding.message = _scrub(finding.message, secrets)
        result.reason = _scrub(result.reason, secrets)
        result.notes = [_scrub(note, secrets) for note in result.notes]

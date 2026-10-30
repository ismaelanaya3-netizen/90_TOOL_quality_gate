"""Core data model shared by checks, runner and reports."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Severity(str, Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

    @property
    def rank(self) -> int:
        return list(Severity).index(self)

    @classmethod
    def parse(cls, value: str) -> Severity:
        normalized = value.strip().upper()
        aliases = {"ERROR": "HIGH", "WARNING": "MEDIUM", "NOTE": "LOW", "UNDEFINED": "LOW"}
        return cls(aliases.get(normalized, normalized))


class Status(str, Enum):
    PASS = "PASS"  # noqa: S105  # nosec B105 - status name, not a credential
    FAIL = "FAIL"
    WARN = "WARN"
    SKIPPED = "SKIPPED"
    ERROR = "ERROR"
    INFO = "INFO"  # nothing to verify: informative, never blocks


class Level(str, Enum):
    FAST = "fast"
    STANDARD = "standard"
    FULL = "full"

    @property
    def order(self) -> int:
        return list(Level).index(self)


class Verdict(str, Enum):
    APPROVED = "APROBADO"
    APPROVED_WITH_OMISSIONS = "APROBADO CON OMISIONES"
    REJECTED = "RECHAZADO"


@dataclass
class Finding:
    tool: str
    rule: str
    severity: Severity
    message: str
    file: str = ""
    line: int = 0
    cwe: str = ""
    suppressed_by: str = ""
    package: str = ""  # dependency findings: normalized package name (grouping key with the rule id)

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool": self.tool,
            "rule": self.rule,
            "severity": self.severity.value,
            "message": self.message,
            "file": self.file,
            "line": self.line,
            "cwe": self.cwe,
            "suppressed_by": self.suppressed_by,
            "package": self.package,
        }


@dataclass
class Metric:
    """A measured value compared against profile thresholds.

    ``direction`` is ``"max"`` when lower is better (counts, latency) and ``"min"``
    when higher is better (coverage). ``display`` optionally renders ranks (A..F).
    """

    key: str
    label: str
    value: float
    unit: str = ""
    direction: str = "max"
    display: str = ""

    def violates(self, threshold: float | None) -> bool:
        if threshold is None or self.direction == "info":
            return False
        if self.direction == "max":
            return self.value > threshold
        return self.value < threshold

    def margin(self, threshold: float | None) -> float | None:
        if threshold is None or self.direction == "info":
            return None
        diff = threshold - self.value if self.direction == "max" else self.value - threshold
        return round(diff, 2)


@dataclass
class CheckResult:
    check_id: str
    title: str
    level: Level
    status: Status
    tool: str = ""
    tool_version: str = ""
    duration_s: float = 0.0
    reason: str = ""
    mandatory: bool = True
    findings: list[Finding] = field(default_factory=list)
    metrics: list[Metric] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    applied_exceptions: list[str] = field(default_factory=list)
    expired_exceptions: list[str] = field(default_factory=list)
    artifacts: list[str] = field(default_factory=list)
    # justified [[checks.desactivados]] entry that skipped this check (empty if none)
    waiver: dict[str, str] = field(default_factory=dict)

    @property
    def active_findings(self) -> list[Finding]:
        return [f for f in self.findings if not f.suppressed_by]


@dataclass
class TargetPython:
    version: str
    source: str
    executable: str
    strict: bool


@dataclass
class GateResult:
    verdict: Verdict
    results: list[CheckResult]
    profile: str
    level: Level
    ci: bool
    target: TargetPython
    started_at: str
    duration_s: float
    out_dir: str
    meta: dict[str, Any] = field(default_factory=dict)

    @property
    def omissions(self) -> list[CheckResult]:
        return [r for r in self.results if r.status is Status.SKIPPED and (r.mandatory or r.waiver)]

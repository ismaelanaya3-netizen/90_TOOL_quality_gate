"""Common interface for every check."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import ClassVar

from qgate.context import RunContext
from qgate.models import CheckResult, Level, Metric, Status

RANKS = "ABCDEF"


def rank_letter(value: float) -> str:
    index = max(1, min(len(RANKS), round(value))) - 1
    return RANKS[index]


class Check(ABC):
    """A gate control. Subclasses implement :meth:`execute`."""

    id: ClassVar[str]
    title: ClassVar[str]
    level: ClassVar[Level]
    tool: ClassVar[str] = ""
    # profile key whose ``None`` value means "not required by this profile"
    gate_key: ClassVar[str] = ""

    @abstractmethod
    def execute(self, ctx: RunContext) -> CheckResult:
        """Run the control and return a finalized result."""

    def new(self, status: Status = Status.PASS, reason: str = "") -> CheckResult:
        return CheckResult(
            check_id=self.id,
            title=self.title,
            level=self.level,
            status=status,
            tool=self.tool,
            reason=reason,
        )

    def skipped(self, reason: str, mandatory: bool = True) -> CheckResult:
        result = self.new(Status.SKIPPED, reason)
        result.mandatory = mandatory
        return result

    def error(self, reason: str) -> CheckResult:
        return self.new(Status.ERROR, reason)

    def suppress(self, ctx: RunContext, result: CheckResult) -> None:
        """Apply the exception registry to ``result.findings``."""
        applied, expired = ctx.registry.apply(result.findings)
        result.applied_exceptions.extend(applied)
        result.expired_exceptions.extend(expired)

    def finalize(self, ctx: RunContext, result: CheckResult, warn: str = "") -> CheckResult:
        """Evaluate metrics against the active profile and set the final status."""
        problems: list[str] = []
        for metric in result.metrics:
            limit = ctx.threshold(metric.key)
            if metric.violates(limit):
                op = "≤" if metric.direction == "max" else "≥"
                shown = metric.display or _fmt(metric.value)
                wanted = rank_letter(limit) if metric.display and limit is not None else _fmt(limit)
                problems.append(f"{metric.label}: {shown}{metric.unit} (exigido {op} {wanted})")
        problems.extend(result.expired_exceptions)
        if problems:
            result.status = Status.FAIL
            result.reason = "; ".join(problems)
        elif result.status is Status.FAIL:
            pass
        elif warn:
            result.status = Status.WARN
            result.reason = warn
        else:
            result.status = Status.PASS
        return result

    def count_metric(self, key: str, label: str, result: CheckResult) -> Metric:
        return Metric(key=key, label=label, value=float(len(result.active_findings)))


def _fmt(value: float | None) -> str:
    if value is None:
        return "-"
    return str(int(value)) if float(value).is_integer() else f"{value:.2f}"


def pct(value: float) -> float:
    return round(value, 2)


def metric_rank(key: str, label: str, value: float) -> Metric:
    return Metric(key=key, label=label, value=float(value), display=rank_letter(value))


__all__ = ["Check", "Metric", "metric_rank", "pct", "rank_letter"]

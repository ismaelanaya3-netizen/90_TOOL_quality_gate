"""Ordered catalog of checks. To add a check, implement ``Check`` and list it here."""

from __future__ import annotations

from qgate.checks.base import Check
from qgate.checks.code_checks import BanditCheck, ComplexityCheck, TypingCheck
from qgate.checks.deps_checks import DepsAuditCheck, DepsPinnedCheck, LicensesCheck, SbomCheck
from qgate.checks.fast_checks import FileSizeCheck, FormatCheck, LintCheck, PythonVersionCheck
from qgate.checks.fastapi_config import FastApiConfigCheck
from qgate.checks.full_checks import ApiPropertiesCheck, HttpBehaviorCheck, LoadSmokeCheck, ZapBaselineCheck
from qgate.checks.secrets import SecretsCheck
from qgate.checks.semgrep_check import SemgrepCheck
from qgate.checks.tests_cov import TestsCheck

CHECK_CLASSES: list[type[Check]] = [
    PythonVersionCheck,
    FormatCheck,
    LintCheck,
    SecretsCheck,
    FileSizeCheck,
    ComplexityCheck,
    TypingCheck,
    TestsCheck,
    BanditCheck,
    SemgrepCheck,
    DepsAuditCheck,
    DepsPinnedCheck,
    LicensesCheck,
    SbomCheck,
    FastApiConfigCheck,
    ApiPropertiesCheck,
    HttpBehaviorCheck,
    ZapBaselineCheck,
    LoadSmokeCheck,
]


def all_checks() -> list[Check]:
    return [cls() for cls in CHECK_CLASSES]

"""Gate orchestration: selection, timing, CI conversion and verdict."""

from __future__ import annotations

import datetime as dt
import platform
import shutil
import sys
import time
from collections.abc import Callable, Sequence
from pathlib import Path

from qgate import __version__, pyversion, tools
from qgate.checks.base import Check
from qgate.checks.registry import all_checks
from qgate.config import ConfigError, load_config
from qgate.context import RunContext, detect_ci
from qgate.exceptions_registry import load_registry
from qgate.models import CheckResult, GateResult, Level, Status, TargetPython, Verdict
from qgate.redact import redact_results
from qgate.waivers import Waiver, parse_waivers

Progress = Callable[[str, CheckResult | None], None]


def resolve_target(flag: str | None, cfg_target: str | None, executable: str, strict: bool) -> TargetPython:
    version, source = pyversion.resolve(flag, cfg_target)
    return TargetPython(version=version, source=source, executable=executable or sys.executable, strict=strict)


def select_checks(level: Level, only: Sequence[str] | None) -> list[Check]:
    checks = [c for c in all_checks() if c.level.order <= level.order]
    if only:
        known = {c.id for c in all_checks()}
        unknown = [name for name in only if name not in known]
        if unknown:
            msg = f"Checks desconocidos: {', '.join(unknown)}. Disponibles: {', '.join(sorted(known))}"
            raise ConfigError(msg)
        checks = [c for c in all_checks() if c.id in only]
    return checks


def _waived(check: Check, ctx: RunContext, waivers: dict[str, Waiver]) -> CheckResult | None:
    """Result for a deactivated check, or ``None`` when it must run (not listed or expired)."""
    waiver = waivers.get(check.id)
    if waiver is None:
        return None
    if waiver.error:
        result = check.new(Status.FAIL, waiver.error)
        result.waiver = waiver.to_dict()
        return result
    if waiver.expired(ctx.registry.today):
        return None
    result = check.skipped(
        f"Desactivado hasta {waiver.to_dict()['vence']} por {waiver.owner}: {waiver.justification}", mandatory=False
    )
    result.waiver = waiver.to_dict()
    return result


def _run_one(check: Check, ctx: RunContext, waivers: dict[str, Waiver] | None = None) -> CheckResult:
    cfg = ctx.cfg
    waivers = parse_waivers(cfg.disabled) if waivers is None else waivers
    waived = _waived(check, ctx, waivers)
    if waived is not None:
        return waived
    if check.gate_key and ctx.threshold(check.gate_key) is None:
        return check.skipped(f"No exigido por el perfil '{ctx.profile_name}'", mandatory=False)
    start = time.perf_counter()
    try:
        result = check.execute(ctx)
    except Exception as exc:
        result = check.error(f"Error inesperado: {type(exc).__name__}: {exc}")
    result.duration_s = round(time.perf_counter() - start, 2)
    if check.id in waivers:  # expired deactivation: the check ran again
        result.notes.append(f"La desactivación venció el {waivers[check.id].to_dict()['vence']}; el check se ejecutó.")
    if check.id in cfg.optional:
        result.mandatory = False
    if ctx.ci and result.status is Status.SKIPPED and result.mandatory:
        result.status = Status.FAIL
        result.reason = f"[CI] Un check obligatorio no puede omitirse: {result.reason}"
    redact_results([result], ctx.secrets)
    return result


def compute_verdict(results: Sequence[CheckResult]) -> Verdict:
    if any(r.status in {Status.FAIL, Status.ERROR} for r in results):
        return Verdict.REJECTED
    if any(r.status is Status.SKIPPED and (r.mandatory or r.waiver) for r in results):
        return Verdict.APPROVED_WITH_OMISSIONS
    return Verdict.APPROVED


def git_meta(root: Path) -> dict[str, str]:
    commit = tools.run(["git", "rev-parse", "HEAD"], cwd=root, timeout=30)
    branch = tools.run(["git", "rev-parse", "--abbrev-ref", "HEAD"], cwd=root, timeout=30)
    return {
        "commit": commit.stdout.strip() if commit.ok else "",
        "branch": branch.stdout.strip() if branch.ok else "",
    }


def run_gate(
    root: Path,
    level: Level = Level.STANDARD,
    profile: str | None = None,
    only: Sequence[str] | None = None,
    ci: bool | None = None,
    python_flag: str | None = None,
    today: dt.date | None = None,
    progress: Progress | None = None,
) -> GateResult:
    cfg = load_config(root)
    profile_name = profile or cfg.profile
    if profile_name not in cfg.profiles:
        msg = f"Perfil desconocido '{profile_name}'. Disponibles: {', '.join(cfg.profiles)}"
        raise ConfigError(msg)
    target = resolve_target(python_flag, cfg.python_target, cfg.python_executable, cfg.strict_version)
    now = dt.datetime.now().astimezone()
    out_base = cfg.root / ".qgate"
    out_dir = out_base / now.strftime("%Y%m%d-%H%M%S-%f")
    out_dir.mkdir(parents=True, exist_ok=True)
    ctx = RunContext(
        cfg=cfg,
        profile_name=profile_name,
        level=level,
        ci=detect_ci() if ci is None else ci,
        target=target,
        out_dir=out_dir,
        registry=load_registry(cfg.root, today),
    )
    if progress:
        progress(f"Python objetivo: {target.version} (origen: {target.source})", None)
    started = time.perf_counter()
    results: list[CheckResult] = []
    waivers = parse_waivers(cfg.disabled)
    for check in select_checks(level, only):
        if progress:
            progress(f"→ {check.id}: {check.title}", None)
        result = _run_one(check, ctx, waivers)
        results.append(result)
        if progress:
            progress("", result)
    redact_results(results, ctx.secrets)  # secrets learned by later checks also mask earlier text
    gate = GateResult(
        verdict=compute_verdict(results),
        results=results,
        profile=profile_name,
        level=level,
        ci=ctx.ci,
        target=target,
        started_at=now.isoformat(timespec="seconds"),
        duration_s=round(time.perf_counter() - started, 2),
        out_dir=str(out_dir),
        meta={
            "project": cfg.name,
            "root": str(cfg.root),
            "os": platform.platform(),
            "python_runtime": platform.python_version(),
            "qgate_version": __version__,
            **git_meta(cfg.root),
            "profiles": cfg.profiles,
            "exceptions": [e.to_dict(ctx.registry.today) for e in ctx.registry.items],
        },
    )
    from qgate.report import write_all  # local import keeps report optional for checks

    write_all(gate, out_dir)
    latest = out_base / "latest"
    if latest.exists():
        shutil.rmtree(latest)
    shutil.copytree(out_dir, latest)
    return gate

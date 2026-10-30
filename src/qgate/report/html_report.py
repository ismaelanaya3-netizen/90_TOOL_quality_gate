"""Self-contained HTML report (no CDN), light/dark mode, printable as audit evidence."""

from __future__ import annotations

from html import escape
from pathlib import Path
from typing import Any

from qgate.models import GateResult
from qgate.report import json_report
from qgate.report.grouping import SEVERITIES, group_findings

_CSS = """
:root{--bg:#f7f8fa;--fg:#1d2330;--card:#fff;--muted:#5d6675;--line:#d9dde4;
--pass:#1a7f37;--fail:#c62828;--warn:#9a6700;--skip:#0b6e99;--err:#8e24aa}
@media (prefers-color-scheme:dark){:root:not([data-theme=light]){--bg:#11151c;--fg:#e6e9ef;
--card:#1a2029;--muted:#9aa3b2;--line:#2c3440;--pass:#3fb950;--fail:#f85149;--warn:#d29922;
--skip:#58a6ff;--err:#d2a8ff}}
:root[data-theme=dark]{--bg:#11151c;--fg:#e6e9ef;--card:#1a2029;--muted:#9aa3b2;--line:#2c3440;
--pass:#3fb950;--fail:#f85149;--warn:#d29922;--skip:#58a6ff;--err:#d2a8ff}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);
font:14px/1.45 "Segoe UI",system-ui,-apple-system,sans-serif}
main{max-width:1200px;margin:0 auto;padding:16px}
h1{font-size:22px;margin:0 0 4px}
h2{font-size:17px;margin:28px 0 8px;border-bottom:1px solid var(--line);padding-bottom:4px}
.card{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:14px;margin:10px 0}
.verdict{font-size:30px;font-weight:700;padding:18px;border-radius:8px;text-align:center;color:#fff}
.v-APROBADO{background:var(--pass)}.v-RECHAZADO{background:var(--fail)}.v-OMISIONES{background:var(--warn)}
.meta{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:6px 18px;color:var(--muted)}
.meta b{color:var(--fg)}table{width:100%;border-collapse:collapse;font-size:13px}
th,td{border-bottom:1px solid var(--line);padding:6px 8px;text-align:left;vertical-align:top}
th{background:var(--bg)}.wrap{overflow-x:auto}
.s{font-weight:700}.s-PASS{color:var(--pass)}.s-FAIL{color:var(--fail)}.s-WARN{color:var(--warn)}
.s-SKIPPED{color:var(--skip)}.s-ERROR{color:var(--err)}.s-INFO{color:var(--muted)}.pos{color:var(--pass)}.neg{color:var(--fail)}
.sev{font-weight:600}.toolbar{display:flex;gap:10px;flex-wrap:wrap;align-items:center;margin:6px 0}
select,button{font:inherit;padding:4px 8px;border:1px solid var(--line);border-radius:6px;
background:var(--card);color:var(--fg)}
.muted{color:var(--muted)}.supp{opacity:.6}
@media print{.toolbar,#theme{display:none}body{background:#fff;color:#000}.card{break-inside:avoid}
tr{break-inside:avoid}.verdict{-webkit-print-color-adjust:exact;print-color-adjust:exact}}
"""

_JS = """
(function(){var r=document.documentElement,b=document.getElementById('theme');
b.addEventListener('click',function(){var d=r.getAttribute('data-theme');
var dark=d?d==='dark':matchMedia('(prefers-color-scheme: dark)').matches;
r.setAttribute('data-theme',dark?'light':'dark');});
var fs=document.getElementById('fsev'),ft=document.getElementById('ftool'),fx=document.getElementById('fsup');
function apply(){var rows=document.querySelectorAll('#findings tbody tr'),n=0;
rows.forEach(function(tr){var ok=(!fs.value||tr.dataset.sev===fs.value)
&&(!ft.value||tr.dataset.tools.indexOf(' '+ft.value+' ')>=0)
&&(fx.value!=='active'||tr.dataset.sup==='0');tr.style.display=ok?'':'none';if(ok)n++;});
document.getElementById('fcount').textContent=n+' grupos visibles';}
[fs,ft,fx].forEach(function(e){e.addEventListener('change',apply);});apply();})();
"""


def _e(value: Any) -> str:
    return escape(str(value), quote=True)


def _fmt(value: Any) -> str:
    if value is None:
        return "—"
    if isinstance(value, float) and value.is_integer():
        return str(int(value))
    return _e(value)


def _margins(data: dict[str, Any]) -> str:
    profiles = list(data["profiles"])
    head = "".join(f"<th>Umbral {_e(p)}</th><th>Margen vs {_e(p)}</th>" for p in profiles)
    rows = []
    for check in data["checks"]:
        for m in check["metrics"]:
            if m["direction"] == "info":
                continue
            value = m["display"] or _fmt(m["value"])
            cells = []
            for p in profiles:
                limit, margin = m["thresholds"].get(p), m["margins"].get(p)
                shown = _fmt(limit) if not m["display"] or limit is None else "ABCDEF"[max(0, min(5, round(limit) - 1))]
                css = "" if margin is None else ("pos" if margin >= 0 else "neg")
                sign = "" if margin is None or margin < 0 else "+"
                unit = " pts" if m["unit"] == "%" else ""
                cells.append(
                    f"<td>{shown}</td><td class='{css}'>{sign}{_fmt(margin)}{unit if margin is not None else ''}</td>"
                )
            rows.append(
                f"<tr><td>{_e(check['id'])}</td><td>{_e(m['label'])}</td>"
                f"<td><b>{value}{_e(m['unit'])}</b></td>{''.join(cells)}</tr>"
            )
    return (
        "<div class='wrap'><table><thead><tr><th>Check</th><th>Métrica</th><th>Valor</th>"
        f"{head}</tr></thead><tbody>{''.join(rows)}</tbody></table></div>"
    )


def _checks(data: dict[str, Any]) -> str:
    rows = []
    for c in data["checks"]:
        active = sum(1 for f in c["findings"] if not f["suppressed_by"])
        notes = "<br>".join(_e(n) for n in c["notes"])
        rows.append(
            f"<tr><td>{_e(c['id'])}<div class='muted'>{_e(c['title'])}</div></td><td>{_e(c['level'])}</td>"
            f"<td class='s s-{_e(c['status'])}'>{_e(c['status'])}</td><td>{active}</td>"
            f"<td>{_e(c['tool'])} {_e(c['tool_version'])}</td><td>{c['duration_s']:.1f} s</td>"
            f"<td>{_e(c['reason'])}<div class='muted'>{notes}</div></td></tr>"
        )
    return (
        "<div class='wrap'><table><thead><tr><th>Check</th><th>Nivel</th><th>Estado</th><th>Hallazgos</th>"
        f"<th>Herramienta</th><th>Tiempo</th><th>Detalle</th></tr></thead><tbody>{''.join(rows)}</tbody></table></div>"
    )


def _findings(data: dict[str, Any]) -> str:
    items = [f for c in data["checks"] for f in c["findings"]]
    groups = group_findings(items)
    tools = sorted({f["tool"] for f in items})
    rows = []
    for g in groups:
        sup = "<div class='muted'>Con excepción vigente</div>" if g.suppressed else ""
        place = f"{_e(g.file)}:{_e(g.line)}" if g.file else "—"
        rows.append(
            f"<tr data-sev='{_e(g.severity)}' data-tools=' {_e(' '.join(g.tools))} ' data-sup='{int(g.suppressed)}'"
            f"{' class=supp' if g.suppressed else ''}><td class='sev'>{_e(g.severity)}</td><td>{place}</td>"
            f"<td>{_e(g.cwe)}</td><td>{_e(g.message)}{sup}</td>"
            f"<td>Detectado por: {_e(g.detected_by)}</td></tr>"
        )
    sev_opts = "".join(f"<option>{s}</option>" for s in SEVERITIES)
    tool_opts = "".join(f"<option>{_e(t)}</option>" for t in tools)
    summary = (
        f"<p class='muted'>{len(items)} hallazgos agrupados en {len(groups)} por archivo + línea + CWE/regla "
        "equivalente. La lista completa está en report.json y results.sarif.</p>"
    )
    return (
        summary + "<div class='toolbar'><label>Severidad <select id='fsev'><option value=''>Todas</option>"
        f"{sev_opts}</select></label><label>Herramienta <select id='ftool'><option value=''>Todas</option>{tool_opts}"
        "</select></label><label>Mostrar <select id='fsup'><option value='all'>Todos</option>"
        "<option value='active'>Solo activos</option></select></label><span id='fcount' class='muted'></span></div>"
        "<div class='wrap'><table id='findings'><thead><tr><th>Severidad</th><th>Ubicación</th><th>CWE</th>"
        f"<th>Mensaje</th><th>Herramientas</th></tr></thead><tbody>{''.join(rows)}</tbody></table></div>"
    )


def _exceptions(data: dict[str, Any]) -> str:
    if not data["exceptions"]:
        return "<p class='muted'>No hay excepciones registradas.</p>"
    rows = "".join(
        f"<tr><td>{_e(x['id'])}</td><td>{_e(x['estado'])}</td><td>{_e(x['usos'])}</td><td>{_e(x['responsable'])}</td>"
        f"<td>{_e(x['creada'])}</td><td>{_e(x['vence'])}</td><td>{_e(x['justificacion'])}</td></tr>"
        for x in data["exceptions"]
    )
    return (
        "<div class='wrap'><table><thead><tr><th>Excepción</th><th>Estado</th><th>Usos</th><th>Responsable</th>"
        f"<th>Creada</th><th>Vence</th><th>Justificación</th></tr></thead><tbody>{rows}</tbody></table></div>"
    )


def _omission(check: dict[str, Any]) -> str:
    waiver = check.get("waiver") or {}
    if not waiver:
        return f"<li><b>{_e(check['id'])}</b>: {_e(check['reason'])}</li>"
    return (
        f"<li><b>{_e(check['id'])}</b> desactivado — {_e(waiver['justificacion'])} "
        f"<span class='muted'>(responsable: {_e(waiver['responsable'])}; creada {_e(waiver['creada'])}; "
        f"vence {_e(waiver['vence'])})</span></li>"
    )


def render(gate: GateResult) -> str:
    data = json_report.build(gate)
    verdict = data["verdict"]
    css_verdict = "OMISIONES" if "OMISIONES" in verdict else verdict
    omissions = data["summary"]["omissions"]
    omitted = (
        "<ul>" + "".join(_omission(c) for c in data["checks"] if c["id"] in omissions) + "</ul>"
        if omissions else "<p class='muted'>Sin omisiones.</p>"
    )  # fmt: skip
    run, proj, target = data["run"], data["project"], data["python_target"]
    meta = "".join(
        f"<div>{label}: <b>{_e(value)}</b></div>"
        for label, value in [
            ("Proyecto", proj["name"]), ("Commit", proj["commit"][:12] or "—"), ("Rama", proj["branch"] or "—"),
            ("Fecha", run["started_at"]), ("Perfil", run["profile"]), ("Nivel", run["level"]),
            ("CI", "sí" if run["ci"] else "no"), ("SO", run["os"]), ("qgate", data["tool"]["version"]),
            ("Python objetivo", f"{target['version']} ({target['source']})"),
            ("Intérprete", target["executable"]), ("Duración", f"{run['duration_s']} s"),
        ]
    )  # fmt: skip
    return f"""<!doctype html>
<html lang="es"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Informe Quality Gate</title><style>{_CSS}</style></head><body><main>
<div class="toolbar" style="justify-content:space-between"><h1>Informe Quality Gate — {_e(proj["name"])}</h1>
<button id="theme" type="button">Claro / oscuro</button></div>
<div class="verdict v-{_e(css_verdict)}">{_e(verdict)}</div>
<div class="card meta">{meta}</div>
<h2>Checks</h2>{_checks(data)}
<h2>Márgenes frente a los perfiles</h2>{_margins(data)}
<h2>Omisiones</h2>{omitted}
<h2>Hallazgos</h2>{_findings(data)}
<h2>Excepciones registradas</h2>{_exceptions(data)}
<p class="muted">Generado por qgate {_e(data["tool"]["version"])} · esquema report.json {_e(data["schema_version"])}</p>
</main><script>{_JS}</script></body></html>
"""


def write(gate: GateResult, out_dir: Path) -> Path:
    path = out_dir / "report.html"
    path.write_text(render(gate), encoding="utf-8")
    return path

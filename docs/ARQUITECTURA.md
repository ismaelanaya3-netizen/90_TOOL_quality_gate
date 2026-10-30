# Arquitectura

## Flujo

```
cli.py ── run ──► runner.run_gate()
                   ├─ config.load_config()           qgate.toml + perfiles (strict, baseline, …)
                   ├─ runner.resolve_target()         flag > QGATE_PYTHON_OBJETIVO > toml > 3.12
                   ├─ exceptions_registry.load_registry()
                   ├─ RunContext(cfg, perfil, nivel, ci, target, out_dir, registry)
                   ├─ por cada Check del nivel: check.execute(ctx) → CheckResult
                   │     ├─ tools.run([...])          único punto de subprocess (sin shell)
                   │     ├─ suppress()                aplica excepciones (vencidas → FAIL)
                   │     └─ finalize()                métricas vs umbrales del perfil
                   ├─ CI: SKIPPED obligatorio → FAIL
                   ├─ compute_verdict()               APROBADO / CON OMISIONES / RECHAZADO
                   └─ report.write_all()              json, html, sarif, junit → .qgate/<ts>/ y latest/
```

Módulos principales:

| Módulo | Responsabilidad |
|---|---|
| `models.py` | `Severity`, `Status`, `Level`, `Verdict`, `Finding`, `Metric`, `CheckResult`, `GateResult` |
| `config.py` | Lectura de `qgate.toml`, perfiles por defecto, herencia (`hereda`) |
| `pyversion.py` | Validación y precedencia de `python_objetivo` |
| `tools.py` | Ejecución de procesos con lista de argumentos, timeout y entorno silencioso |
| `fsutil.py` / `net.py` | Recorrido de archivos con globs POSIX; red vía urllib (respeta proxy) |
| `checks/` | Un archivo por familia; `registry.py` define el orden del catálogo |
| `report/` | Escritores de informes; `html_report` no usa CDN ni recursos externos |
| `init_project.py` / `pyproject_merge.py` | `qgate init` no destructivo |

## Agregar un check nuevo

1. Cree la clase en `src/qgate/checks/` (un archivo nuevo o el de su familia):

```python
from qgate.checks.base import Check
from qgate.context import RunContext
from qgate.fsutil import iter_files, rel_posix
from qgate.models import CheckResult, Finding, Level, Severity


class TodoCheck(Check):
    """Ejemplo: prohíbe comentarios TODO en el código de la app."""

    id = "todos"
    title = "Comentarios TODO pendientes"
    level = Level.FAST
    tool = "qgate"
    gate_key = "todos_pendientes"  # umbral en los perfiles (None = no exigido)

    def execute(self, ctx: RunContext) -> CheckResult:
        result = self.new()
        for path in iter_files(ctx.root, ctx.cfg.src, [".py"], ctx.excludes):
            for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
                if "TODO" in line:
                    result.findings.append(
                        Finding("qgate", "todo", Severity.LOW, line.strip(), rel_posix(path, ctx.root), number)
                    )
        self.suppress(ctx, result)  # aplica qgate-exceptions.toml
        result.metrics.append(self.count_metric(self.gate_key, "TODO pendientes", result))
        return self.finalize(ctx, result)  # PASS/FAIL según el perfil activo
```

2. Agregue la clase a `CHECK_CLASSES` en `checks/registry.py`.
3. Agregue el umbral `"todos_pendientes": 0` en `DEFAULT_PROFILES["strict"]` (y, si aplica, un
   valor más laxo en `baseline`).
4. Si llama a una herramienta externa, use siempre `tools.run([...])` y devuelva
   `self.skipped("motivo")` cuando no esté disponible, para que la degradación sea controlada.
5. Escriba pruebas: una de detección (con un fixture en `examples/vulnerable_fixtures`) y una de
   paso (el demo debe seguir aprobando).

Reglas: ningún archivo supera 400 líneas, `mypy --strict` y `ruff` limpios (el kit se verifica a sí
mismo con `qgate run --level standard`).

## Esquema de `report.json` (`schema_version` = `"1.0"`)

```jsonc
{
  "schema_version": "1.0",
  "tool": {"name": "qgate", "version": "0.1.0"},
  "project": {"name": "...", "root": "...", "commit": "sha", "branch": "main"},
  "run": {
    "started_at": "2026-10-30T04:15:54-05:00",    // ISO 8601 con zona horaria
    "duration_s": 42.1, "level": "standard", "profile": "strict", "ci": false,
    "os": "Windows-10-...", "python_runtime": "3.12.3"
  },
  "python_target": {"version": "3.12", "source": "qgate.toml [entorno].python_objetivo",
                    "executable": "C:\\...\\python.exe", "strict": true},
  "verdict": "APROBADO | APROBADO CON OMISIONES | RECHAZADO",
  "summary": {"checks": 15, "by_status": {"PASS": 14, "SKIPPED": 1},
              "findings_active": 0, "findings_suppressed": 2, "omissions": ["dast_zap"]},
  "tools": {"ruff": "0.17.3", "mypy": "2.4.1", "...": "..."},
  "profiles": {"strict": {"cobertura_total": 85, "...": "..."}, "baseline": {"...": "..."}},
  "checks": [{
    "id": "tests", "title": "...", "level": "standard", "status": "PASS", "mandatory": true,
    "tool": "pytest", "tool_version": "9.2.0", "duration_s": 4.2, "reason": "", "notes": ["..."],
    "metrics": [{
      "key": "cobertura_total", "label": "Cobertura total", "value": 91.0, "display": "",
      "unit": "%", "direction": "min",                  // min: mayor es mejor; max: menor es mejor
      "thresholds": {"strict": 85, "baseline": 70},
      "margins": {"strict": 6.0, "baseline": 21.0},
      "passes_active_profile": true
    }],
    "findings": [{"tool": "bandit", "rule": "B608", "severity": "MEDIUM", "message": "...",
                  "file": "app/db.py", "line": 12, "cwe": "CWE-89", "suppressed_by": ""}],
    "applied_exceptions": ["bandit:B608@app/reports/*.py"],
    "expired_exceptions": []
  }],
  "exceptions": [{"id": "...", "regla": "...", "herramienta": "...", "archivo": "...",
                  "justificacion": "...", "responsable": "...", "creada": "2026-10-30",
                  "vence": "2027-01-28", "estado": "vigente | por_vencer | vencida", "usos": 1}]
}
```

Compatibilidad: los campos nuevos se agregan sin cambiar `schema_version` menor; un cambio que
rompa consumidores incrementa la versión mayor.

## SARIF

Un único *run* con `tool.driver.name = "qgate"`; los `ruleId` son `herramienta/regla`
(`bandit/B608`, `semgrep/qgate-eval-exec`). Los hallazgos con excepción vigente se emiten con
`suppressions` (`kind: external`) para que Azure/GitHub los muestren como aceptados.

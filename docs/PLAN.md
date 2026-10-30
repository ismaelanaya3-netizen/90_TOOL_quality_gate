# Plan de construcción — Quality Gate Kit (`qgate`) v0.1.0

## Árbol de archivos final

```
90_TOOL_quality_gate/
├── src/qgate/
│   ├── __init__.py / __main__.py
│   ├── cli.py                  # argparse: init, run, report, doctor, exceptions list
│   ├── config.py               # carga qgate.toml, perfiles, defaults
│   ├── pyversion.py            # resolución de python_objetivo (flag > env > toml > 3.12)
│   ├── context.py              # RunContext: config + perfil + excepciones + carpeta de salida
│   ├── models.py               # Severity, Status, Level, Finding, Metric, CheckResult, GateResult
│   ├── tools.py                # ÚNICO punto de subprocess (listas de argumentos, sin shell)
│   ├── fsutil.py               # recorrido de archivos con exclusiones (pathlib, glob POSIX)
│   ├── net.py                  # conectividad y descargas (urllib, respeta HTTP(S)_PROXY)
│   ├── runner.py               # selección de checks, tiempos, veredicto, conversión CI
│   ├── exceptions_registry.py  # qgate-exceptions.toml con vencimientos
│   ├── doctor.py               # diagnóstico del entorno
│   ├── init_project.py         # aplica el kit a un proyecto
│   ├── pyproject_merge.py      # merge no destructivo de pyproject.toml
│   ├── checks/
│   │   ├── base.py             # interfaz Check + evaluación de métricas
│   │   ├── registry.py         # catálogo ordenado
│   │   ├── formatting.py lint.py secrets.py gitleaks_bin.py file_size.py python_version.py
│   │   ├── complexity.py typing_check.py tests_cov.py bandit_check.py semgrep_check.py
│   │   ├── deps_audit.py deps_pinned.py licenses.py sbom.py fastapi_config.py
│   │   └── app_server.py api_props.py http_behavior.py dast_zap.py load_smoke.py
│   ├── report/                 # console.py json_report.py html_report.py sarif.py junit.py
│   ├── rules/semgrep/          # reglas Semgrep locales versionadas
│   └── templates/              # archivos que `qgate init` copia al proyecto
├── examples/demo_dashboard/    # FastAPI limpia que pasa strict
├── examples/vulnerable_fixtures/  # fallas intencionales (nunca importado)
├── tests/                      # pytest del kit
├── docs/  install.ps1  install.sh  pyproject.toml  requirements-dev.lock
├── .pre-commit-config.yaml  .gitleaks.toml  qgate.toml  qgate-exceptions.toml
├── .github/workflows/ci.yml  azure-pipelines.yml
```

## Decisiones de diseño

1. **Sin dependencias de runtime** (solo stdlib; `tomli` en Python 3.10). Las herramientas
   (ruff, mypy, bandit, …) se instalan desde `requirements-dev.lock` y se invocan como
   `python -m <herramienta>` cuando es posible: funciona igual en Windows y Linux.
2. **Un único punto de `subprocess`** (`tools.py`), siempre con lista de argumentos,
   `shell=False` y timeout. Facilita auditoría (una sola supresión justificada).
3. **Métricas + perfiles**: cada check emite métricas (`Metric`) con dirección `max`/`min`.
   El perfil activo (por defecto `strict`) decide PASS/FAIL; el informe calcula el margen
   contra todos los perfiles (baseline, strict, y cualquier perfil adicional como `epm_ti`).
4. **Excepciones aplicadas dentro del check** antes de calcular métricas: los hallazgos
   suprimidos quedan visibles en el informe; una excepción vencida reactiva el hallazgo y
   fuerza FAIL.
5. **Degradación controlada**: un check que no puede correr devuelve `SKIPPED` con motivo.
   Local → "APROBADO CON OMISIONES". CI (`--ci`, `QGATE_CI=1`, `TF_BUILD`, `GITHUB_ACTIONS`)
   → SKIPPED obligatorio = FAIL.
6. **Checks `full`** levantan la app con uvicorn en puerto efímero (127.0.0.1) con las
   variables de entorno de producción definidas en `qgate.toml`. El esquema OpenAPI se
   extrae importando la app (así los docs pueden seguir deshabilitados).
7. **Plantillas con marcadores `@@CLAVE@@`** (no `$`), para no chocar con la sintaxis de
   Azure Pipelines.
8. **gitleaks** fijado a v8.21.2 con SHA-256 embebidos en el kit (no se confía en el archivo
   de checksums descargado del mismo origen).
9. **Informe HTML autocontenido** (CSS/JS inline, sin CDN), con modo claro/oscuro e
   impresión a PDF.

## Orden de construcción (commits)

1. Esqueleto, modelos, config, pyversion, CLI con `doctor`.
2. Checks `fast` + pruebas.
3. Checks `standard` + pruebas.
4. Informes JSON/HTML/SARIF/JUnit.
5. Excepciones y perfiles con márgenes.
6. `init` + plantillas.
7. Checks `full`.
8. Ejemplos + `test_detection.py`.
9. CI (Azure + GitHub) + scripts de instalación.
10. Documentación + resumen de entrega.

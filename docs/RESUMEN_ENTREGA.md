# Resumen de entrega — Quality Gate Kit v0.1.0

Rama: `claude/quality-gate-kit` · Fecha: 2026-10-30 · Entorno de construcción: Linux, Python 3.12.3.

## Lo construido

- **Paquete `qgate`** (`src/qgate`, 34 módulos, el más grande de 268 líneas; sin dependencias de
  runtime): CLI `init`, `run`, `report`, `doctor`, `exceptions list`.
- **19 checks** en tres niveles: los 18 del catálogo más `python_version`. Todos devuelven un
  resultado normalizado: estado, hallazgos con CWE, métricas, versión de la herramienta y tiempo.
- **Perfiles** `strict` (por defecto) y `baseline`, con herencia (`hereda`) para crear `epm_ti`, y
  **márgenes** por métrica en el informe.
- **Python objetivo configurable** con precedencia flag > variable de entorno > `qgate.toml` > 3.12.
  Se propaga a ruff, mypy, vermin, pytest y la app levantada, y queda registrado en los informes.
- **Registro de excepciones** auditable con vencimiento obligatorio (≤ 180 días).
- **Informes**: `report.json` (schema 1.0), `report.html` autocontenido (claro/oscuro, imprimible),
  `results.sarif` 2.1.0, `qgate-junit.xml`, `junit.xml`, `coverage.xml`, `sbom.cdx.json`.
- **Reglas Semgrep locales** versionadas (`src/qgate/rules/semgrep`, 15 reglas).
- **Ejemplos**: `demo_dashboard` (FastAPI + SQLAlchemy + Jinja, 31 pruebas, cobertura 100 %) y
  `vulnerable_fixtures` (11 fallas sembradas).
- **CI**: plantilla `azure-pipelines.yml` (Validate + DeepScan) y `.github/workflows/ci.yml`
  (matriz ubuntu/windows × 3.10/3.12).
- **Instalación**: `install.ps1` (Windows, sin administrador, con proxy) e `install.sh`.
- **Documentación** en español: README, GUIA_ADOPCION, ALINEACION_TI, ARQUITECTURA,
  LIMITACIONES_ENTORNO, CHANGELOG.

## Criterios de aceptación

| # | Criterio | Resultado | Evidencia |
|---|---|---|---|
| 1 | `pytest` del kit 100 % verde, cobertura ≥ 85 % | ✅ | `python -m pytest --cov=qgate --cov-branch` → **112 passed**, cobertura total **92 %** (críticos: `exceptions_registry`, `pyversion`, `tools` al 100 %) |
| 2 | `qgate run --level standard` sobre el kit → APROBADO | ✅ | `qgate run --level standard --ci` → **VEREDICTO: APROBADO**, rc=0. 13 PASS; `python_version` WARN (intérprete 3.12 frente a objetivo 3.10, `estricto_version=false` en una librería multiversión); `fastapi_config` desactivado (el kit no es una app) |
| 3 | `qgate run --level full` sobre `demo_dashboard` → APROBADO (u omisiones de entorno) | ✅ | **APROBADO CON OMISIONES**, rc=0. 18 PASS; solo `dast_zap` SKIPPED (no hay daemon Docker). Carga: 3714 peticiones, 20 usuarios, 30 s, 0 % de errores |
| 4 | `vulnerable_fixtures` → FALLA y `test_detection.py` confirma cada hallazgo | ✅ | **RECHAZADO**, rc=1. `test_detection.py`: 22 pruebas verdes (18 pares falla/check, más secreto, ubicación y dependencias) |
| 5 | `qgate init` sobre una copia de `demo_dashboard` sin configuración | ✅ | Crea 7 archivos, añade solo `tool.mypy`, `tool.pytest.ini_options` y `tool.coverage.run` (conserva `tool.ruff`), muestra el diff, deja `pyproject.toml.bak` y agrega `.qgate/` a `.gitignore`. Después, `qgate run --level standard` → **APROBADO** (incluido pip-audit con resolución transitiva) |
| 6 | Precedencia de `python_objetivo`, propagación y desalineación | ✅ | `tests/test_pyversion.py` (20 pruebas): los 4 niveles de precedencia; valores inválidos (`"3"`, `"tres"`…) dan un error claro en español y salida 2; `--target-version py311` y `--python-version 3.11` en los comandos; origen registrado en JSON y HTML; WARN en local y FAIL con `--ci` |
| 7 | Excepción vencida → FAIL; vigente suprime y aparece en el informe | ✅ | `tests/test_exceptions.py`. Uso real: el kit tiene 5 CVE de dependencias de semgrep suprimidas con vencimiento 2027-01-28 (aparecen como "Supr." en el resumen) |
| 8 | HTML offline, SARIF válido, YAML válido | ✅ | Chromium headless: 0 peticiones externas, 0 errores JS y el filtro por severidad funciona. SARIF validado con `jsonschema` contra el esquema oficial 2.1.0 (`tests/data`). `azure-pipelines.yml`, `.pre-commit-config.yaml` y `ci.yml` se validan con `yaml.safe_load` en las pruebas |
| 9 | Ningún .py del kit > 400 líneas; `mypy --strict` y `ruff` limpios | ✅ | Máximo 268 líneas (`checks/full_checks.py`); el gate del kit fija `archivo_lineas_max = 400`. `mypy --strict --python-version 3.10 src/qgate` → sin errores; ruff con las 16 familias de reglas → limpio |
| 10 | Sin `shell=True`, sin separadores de ruta fijos, sin bash en la funcionalidad | ✅ | Un único punto de `subprocess` (`tools.py`) con listas de argumentos. Las rutas usan `pathlib`; los `replace("\\", "/")` solo normalizan la salida de las herramientas para los informes. Los scripts de instalación son opcionales; el CLI no los usa |

## Lo que no se pudo verificar en el sandbox

Detalle en [LIMITACIONES_ENTORNO.md](LIMITACIONES_ENTORNO.md):

- **OWASP ZAP**: no hay daemon Docker. El check queda SKIPPED con instrucciones; en CI falla a
  propósito. Se ejecutará en el job ubuntu de GitHub y en la etapa DeepScan de Azure.
- **Windows real**: no hay Windows ni PowerShell. El código evita dependencias de plataforma y la
  matriz de GitHub incluye `windows-latest`, pero `install.ps1` y semgrep nativo en Windows quedan
  por confirmar en su servidor.
- **OSV y el registro de Semgrep están bloqueados por el proxy**: pip-audit usa el servicio PyPI
  (sí funciona) y semgrep corre solo con las reglas locales.
- **Python 3.10 con el lock**: varias herramientas fijadas exigen 3.11 o más. El kit funciona en
  3.10, y el job 3.10 de CI instala `.[tools]` con resolución.
- **Workflow de GitHub**: quedó escrito y validado como YAML, pero no se ejecutó (corre al hacer
  push o abrir un PR).

## Primeros 3 pasos en su servidor Windows

1. **Instalar y diagnosticar** en la carpeta `release\` de un dashboard real:

```powershell
powershell -ExecutionPolicy Bypass -File C:\herramientas\qgate\install.ps1 -ProjectPath C:\apps\mi_dashboard\release -PythonVersion 3.12
```

2. **Aplicar el kit y revisar `qgate.toml`**: confirme `src`, `app_module`, `[cobertura].criticos` y
   `[fastapi].entorno_produccion`.

```powershell
.\.venv\Scripts\qgate.exe init . --app-module app.main:app --src app --python 3.12
```

3. **Primera medición gradual** y abrir el informe; empiece por `fast`
   (ver [GUIA_ADOPCION.md](GUIA_ADOPCION.md)):

```powershell
.\.venv\Scripts\qgate.exe run --level fast; .\.venv\Scripts\qgate.exe report --open
```

## Sugerencias para la v0.2

- **Perfil `epm_ti`**: cuando TI responda el cuestionario de `ALINEACION_TI.md`, versionarlo en una
  plantilla compartida (`qgate init --perfil epm_ti`). Añadir un comando `qgate compare` que muestre
  la brecha entre `strict` y `epm_ti` por métrica.
- **Integración con el generador de dashboards**: que el generador llame a `qgate init` al crear
  cada proyecto, con `qgate.toml` precargado (módulos críticos, `entorno_produccion`) y una prueba
  base que deje el proyecto nuevo en "APROBADO" desde el primer commit.
- **Monitoreo continuo de CVE**: un pipeline programado (cron diario en Azure) que ejecute
  `qgate run --only deps_audit,licenses,sbom --ci` sobre `main` de cada dashboard y cree un *work
  item* o envíe un aviso cuando aparezca una vulnerabilidad nueva. También conviene archivar los
  `sbom.cdx.json` en Dependency-Track para cruzarlos con nuevas CVE sin volver a ejecutar el gate.
- Generar automáticamente el lock para varias versiones de Python (`requirements-dev-py3XX.lock`).
- Check de **accesibilidad y JS** del frontend (eslint/axe) y reglas Semgrep para plantillas Jinja.

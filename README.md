# Quality Gate Kit (`qgate`)

Kit reutilizable que replica **localmente** los controles de calidad, pruebas y seguridad de un
pipeline de Azure DevOps, con **umbrales más estrictos**. Si un dashboard pasa `qgate`, llega al
pipeline corporativo con una brecha casi nula y lo supera con margen.

- Pensado para dashboards **Python + FastAPI** (Jinja/HTML/JS), SQL Server (pyodbc/SQLAlchemy) y
  servicios SOAP/REST internos, desplegados en **servidores Windows** (`release/` + `runtime/`).
- Sin dependencias de runtime (solo la biblioteca estándar; `tomli` en Python 3.10). Las
  herramientas se instalan con versiones **exactas** desde `requirements-dev.lock`.
- Informes de evidencia para auditoría: HTML autocontenido, JSON versionado, SARIF 2.1.0, JUnit,
  cobertura y SBOM CycloneDX.

## Instalación

### Windows (PowerShell, sin administrador)

```powershell
git clone https://github.com/ismaelanaya3-netizen/90_TOOL_quality_gate C:\herramientas\qgate
powershell -ExecutionPolicy Bypass -File C:\herramientas\qgate\install.ps1 -ProjectPath C:\apps\mi_dashboard -PythonVersion 3.12
```

`install.ps1` crea `.venv`, instala las herramientas del lock y el kit, descarga gitleaks a
`.qgate\bin` verificando su SHA-256, instala los hooks de pre-commit y ejecuta `qgate doctor`.
Respeta `HTTP_PROXY`/`HTTPS_PROXY`.

### Linux

```bash
git clone https://github.com/ismaelanaya3-netizen/90_TOOL_quality_gate ~/qgate
~/qgate/install.sh /ruta/mi_dashboard 3.12
```

### Solo el paquete

```bash
pip install git+https://github.com/ismaelanaya3-netizen/90_TOOL_quality_gate
pip install -r requirements-dev.lock   # herramientas con versiones exactas
```

También funciona desde una carpeta copiada: `python -m pip install C:\ruta\90_TOOL_quality_gate`
o, sin instalar, `set PYTHONPATH=C:\ruta\90_TOOL_quality_gate\src` y `python -m qgate ...`.

## Uso rápido (5 comandos)

```bash
qgate init . --app-module app.main:app --src app --python 3.12
```

```bash
qgate doctor
```

```bash
qgate run --level fast
```

```bash
qgate run --level standard
```

```bash
qgate report --open
```

Otros: `qgate run --level full` (levanta la app: API, HTTP, DAST, carga), `qgate run --ci`
(omisiones = fallo), `qgate run --only lint,bandit`, `qgate run --profile baseline`,
`qgate run --python 3.11`, `qgate exceptions list`.

Código de salida: `0` aprobado (con o sin omisiones), `1` rechazado, `2` error de configuración.

## Checks

| # | Check (`id`) | Herramienta | Nivel | Criterio strict |
|---|---|---|---|---|
| 0 | `python_version` | intérprete + vermin | fast | intérprete = `python_objetivo` (WARN local / FAIL CI); 0 sintaxis incompatible |
| 1 | `format` | `ruff format --check` | fast | 0 diferencias |
| 2 | `lint` | `ruff` E,F,W,I,N,UP,B,S,C90,SIM,RUF,ASYNC,PTH,DTZ,T20,ERA | fast | 0 hallazgos |
| 3 | `secrets` | gitleaks 8.21.2 (descarga verificada) → detect-secrets | fast | 0 hallazgos |
| 4 | `file_size` | propio | fast | .py ≤ 1000 líneas; aviso desde 600 |
| 5 | `complexity` | radon | standard | ninguna función peor que C; promedio A |
| 6 | `typing` | `mypy --strict` | standard | 0 errores |
| 7 | `tests` | pytest + pytest-cov | standard | 100 % pasan; cobertura ≥ 85 %; críticos ≥ 95 % |
| 8 | `bandit` | bandit | standard | 0 hallazgos (bajas solo con excepción registrada) |
| 9 | `semgrep` | semgrep, reglas locales versionadas (+ `p/python`, `p/owasp-top-ten` con red) | standard | 0 ERROR/WARNING |
| 10 | `deps_audit` | pip-audit | standard | 0 vulnerabilidades sin excepción |
| 11 | `deps_pinned` | propio | standard | todo con `==` |
| 12 | `licenses` | pip-licenses | standard | sin GPL/AGPL en runtime |
| 13 | `sbom` | cyclonedx-py | standard | genera `sbom.cdx.json` |
| 14 | `fastapi_config` | propio (AST + inspección en modo producción) | standard | sin docs, CORS `*`, debug; headers y TrustedHost |
| 15 | `api_props` | schemathesis | full | 0 errores 5xx, respuestas conformes |
| 16 | `http_behavior` | propio (http.client) | full | headers, métodos, 404 sin trazas, límite de tamaño, Host |
| 17 | `dast_zap` | OWASP ZAP baseline (Docker) | full | 0 alertas High/Medium |
| 18 | `load_smoke` | locust headless 30 s × 20 usuarios | full | p95 < 800 ms, 0 % errores |

Estados: `PASS`, `FAIL`, `WARN`, `ERROR`, `SKIPPED` e `INFO`. `INFO` significa "sin elementos que
verificar" (por ejemplo, `licenses` sin dependencias de runtime o los checks de app en un proyecto
sin FastAPI) y no bloquea. Si un check no puede ejecutarse (sin red, sin Docker, sin herramienta)
queda **SKIPPED** con su motivo: en local el veredicto es **APROBADO CON OMISIONES**; en CI (`--ci`,
`QGATE_CI=1`, `TF_BUILD`, `GITHUB_ACTIONS`) un check obligatorio omitido es **FAIL**.

### Desactivar un check

Solo con justificación auditable, igual que una excepción. Queda listado en "Omisiones" y el
veredicto pasa a APROBADO CON OMISIONES. Sin justificación → FAIL; vencido → el check se ejecuta.

```toml
[[checks.desactivados]]
check = "dast_zap"
justificacion = "Los agentes Windows no tienen Docker; ZAP corre en la etapa DeepScan Linux."
responsable = "Nombre Apellido"
creada = 2026-10-30
vence = 2027-01-28
```

## Python objetivo configurable

```toml
[entorno]
python_objetivo = "3.12"     # major.minor
python_ejecutable = ""       # opcional: C:\Python312\python.exe o .venv\Scripts\python.exe
estricto_version = true      # desalineación: FAIL en CI, WARN en local
```

Precedencia: `--python` > `QGATE_PYTHON_OBJETIVO` > `qgate.toml` > `3.12`. La versión efectiva y su
origen se imprimen al inicio y quedan en `report.json`/`report.html`. Se propaga a
`ruff --target-version`, `mypy --python-version` (y `--python-executable`), vermin, pytest,
pip-licenses y la app levantada en los checks full.

## Interpretar el informe (`.qgate/latest/`)

| Archivo | Uso |
|---|---|
| `report.html` | Evidencia para auditoría: veredicto, checks, **márgenes** vs baseline/strict, hallazgos agrupados (archivo + línea + CWE, "Detectado por: …") y filtrables, excepciones y omisiones. Abre offline; imprimible a PDF. |
| `report.json` | Esquema estable (`schema_version`), ver `docs/ARQUITECTURA.md`. |
| `results.sarif` | SARIF 2.1.0 consolidado (Azure *Scans* tab / GitHub code scanning). |
| `junit.xml`, `coverage.xml` | Para `PublishTestResults@2` y `PublishCodeCoverageResults@2`. |
| `qgate-junit.xml` | Un caso de prueba por check (pestaña Tests de Azure). |
| `sbom.cdx.json` | SBOM CycloneDX. |

**Margen**: para cada métrica se muestra el valor, el umbral de cada perfil y la distancia. Por
ejemplo, cobertura 91 % frente a 70 % baseline → **+21 pts**; positivo = se supera lo exigido.

Los secretos se enmascaran en todas las salidas (4 primeros caracteres + `***`).

## Excepciones

`qgate-exceptions.toml` registra excepciones auditables (regla, archivo, justificación,
responsable, creada, vence ≤ 180 días). Una excepción vencida reactiva el hallazgo y hace fallar
el gate. `qgate exceptions list` muestra vigentes, por vencer (< 30 días) y vencidas.

## Documentación

- [docs/GUIA_ADOPCION.md](docs/GUIA_ADOPCION.md) — aplicar el kit a un dashboard existente.
- [docs/ALINEACION_TI.md](docs/ALINEACION_TI.md) — preguntas para TI y perfil `epm_ti`.
- [docs/ARQUITECTURA.md](docs/ARQUITECTURA.md) — diseño, nuevo check, esquema de `report.json`.
- [docs/LIMITACIONES_ENTORNO.md](docs/LIMITACIONES_ENTORNO.md) — qué verificar en Windows.
- [CHANGELOG.md](CHANGELOG.md)

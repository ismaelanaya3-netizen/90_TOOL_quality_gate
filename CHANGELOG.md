# Changelog

Formato basado en [Keep a Changelog](https://keepachangelog.com/es-ES/1.1.0/) y versionado semántico.

## [0.1.2] - 2026-10-30

### Corregido
- **Agrupación de dependencias (bug)**: las vulnerabilidades de pip-audit se fusionaban en una sola
  fila del HTML porque todas compartían archivo, línea 1 y CWE-1395. Ahora los hallazgos de
  dependencias (pip-audit, `deps_pinned`, `licenses`) se agrupan solo por archivo + paquete + id
  (CVE o regla), nunca por línea ni CWE. Nuevo campo `package` en cada hallazgo de `report.json`.
- **pip-audit reporta la línea real** del paquete en el requirements/lock (siguiendo `-r`), y
  `licenses` también. Las dependencias transitivas no declaradas usan la línea 0 y lo indican en el
  mensaje.
- **Enmascarado solo del valor**: en v0.1.1 el mensaje de ruff S105–S107 quedaba con el *nombre*
  de la variable enmascarado (`"GITH***"`), porque ruff cita el nombre y no el valor. Ahora solo se
  enmascaran literales (`password: '…'`, `valor: '…'`, `NOMBRE = '…'`). Bandit B105–B107 muestran
  la sentencia de origen para conservar el nombre: `GITHUB_TOKEN = "ghp_***"`.

### Cambiado (informe HTML)
- **CWE del grupo según una tabla de precedencia** por familias (`CWE_FAMILIES` en
  `report/grouping.py`): CWE-95 sobre CWE-78, CWE-502 sobre CWE-20, CWE-798 sobre CWE-259… Los
  demás CWE del grupo se listan como "también: …".
- **Mensaje del grupo en español**: se prefiere el de las reglas locales de qgate (semgrep `qgate-*`,
  checks propios) sobre el de bandit/ruff.
- **Agrupación tolerante**: misma regla equivalente + mismo archivo + CWE compatible y líneas a
  ≤ 2 de distancia forman un solo grupo (sentencias multilínea, p. ej. `db.py:7-8`). El grupo
  muestra el rango de líneas.
- gitleaks, detect-secrets, bandit B105–B107, ruff S105–S107 y semgrep `qgate-hardcoded-credential`
  comparten el concepto "credencial fija" y se agrupan en una sola fila.

## [0.1.1] - 2026-10-30

### Cambiado
- **Desactivar un check exige justificación** con el mismo modelo que `qgate-exceptions.toml`:
  `[[checks.desactivados]]` con `check`, `justificacion`, `responsable`, `creada` y `vence`
  (≤ 180 días). Un check desactivado aparece en "Omisiones" y el veredicto pasa a
  **APROBADO CON OMISIONES**; no se convierte en FAIL con `--ci` porque está autorizado. Si no
  hay justificación (incluido el formato anterior `desactivados = ["id"]`) o el registro es
  inválido, el check da **FAIL**. Si la desactivación venció, el check se vuelve a ejecutar.
- **Nuevo estado `INFO`** ("Sin elementos que verificar") en lugar de PASS cuando un check no
  tiene nada que revisar: `licenses` sin dependencias de runtime, `fastapi_config` en proyectos
  que no importan FastAPI/Starlette (detección por import AST, ya no por texto) y los checks
  `full` sin `app_module`. INFO no bloquea, no es una omisión y aparece en JUnit como `system-out`.
- **Informe HTML**: los hallazgos se agrupan por archivo + línea + CWE o regla equivalente (ruff
  `S###` = bandit `B###`; reglas `qgate-*` de semgrep mapeadas a su equivalente bandit) y
  muestran "Detectado por: …". `report.json` y `results.sarif` conservan la lista completa y los
  conteos por check no cambian.
- El kit ya no usa `desactivados`: sus checks de app no aplicables dan INFO.
- Se documenta en el `qgate.toml` del kit por qué usa `estricto_version = false` (librería
  multiversión) y el motivo del WARN en CI lo dice explícitamente. Con `estricto_version = true`
  y `--ci`, la desalineación sigue siendo FAIL (ambos casos probados).

### Seguridad
- **Enmascarado de secretos en todas las salidas** (consola, `report.json`, `report.html`,
  `results.sarif`, `qgate-junit.xml`): los valores reportados por gitleaks, detect-secrets,
  bandit B105/B106/B107 y ruff S105–S107 se muestran como los 4 primeros caracteres + `***`, y
  cualquier repetición del valor en otros mensajes o notas también se enmascara. En 0.1.0 el
  mensaje de bandit B105 exponía el token completo del fixture en 4 archivos de `.qgate/`.
- El informe crudo de gitleaks se escribe en una carpeta temporal fuera de `.qgate/` y se borra;
  en `.qgate/` solo queda `gitleaks-report.json` enmascarado.

## [0.1.0] - 2026-10-30

### Añadido
- CLI `qgate` con `init`, `run`, `report`, `doctor` y `exceptions list` (mensajes en español).
- 19 checks en tres niveles (`fast`, `standard`, `full`) con estados PASS/FAIL/WARN/SKIPPED/ERROR,
  degradación controlada (APROBADO CON OMISIONES en local, FAIL en CI).
- `python_objetivo` configurable (flag > `QGATE_PYTHON_OBJETIVO` > `qgate.toml` > 3.12), propagado a
  ruff, mypy, vermin, pytest, pip-licenses y a la app levantada; check `python_version`.
- Perfiles `strict` (por defecto) y `baseline`, herencia de perfiles (`hereda`) y márgenes por métrica.
- Registro auditable de excepciones con vencimiento obligatorio (≤ 180 días).
- Reglas Semgrep locales versionadas (SQL injection, eval/exec, shell, deserialización, YAML,
  SSRF, path traversal, CORS, debug, cookies, TLS, XML/XXE, Jinja autoescape, credenciales, hashes).
- Informes `report.json` (schema 1.0), `report.html` autocontenido, `results.sarif` 2.1.0,
  `qgate-junit.xml`, `junit.xml`, `coverage.xml` y `sbom.cdx.json`.
- gitleaks 8.21.2 con descarga verificada por SHA-256 y fallback a detect-secrets.
- `qgate init` con merge no destructivo de `pyproject.toml` y plantillas (Azure Pipelines,
  pre-commit, nox, VS Code, lock de herramientas).
- `examples/demo_dashboard` (aprueba strict) y `examples/vulnerable_fixtures` (debe fallar).
- Scripts `install.ps1` / `install.sh`, workflow de GitHub y plantilla de Azure DevOps.

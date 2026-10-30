# Changelog

Formato basado en [Keep a Changelog](https://keepachangelog.com/es-ES/1.1.0/) y versionado semántico.

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

# Limitaciones del entorno de construcción

El kit se construyó y probó en un contenedor Linux (Python 3.12.3) con salida a internet
restringida por un proxy. Esto es lo que **no** se pudo verificar ahí y cómo verificarlo en Windows.

| Aspecto | Situación en el sandbox | Comportamiento del kit | Cómo verificar en Windows |
|---|---|---|---|
| Docker / OWASP ZAP | Cliente Docker presente, **sin daemon** | `dast_zap` → SKIPPED con instrucciones (FAIL en CI) | En un agente con Docker: `qgate run --level full`. Sin Docker: instalar ZAP y `zap.bat -cmd -quickurl http://127.0.0.1:<puerto> -quickout zap.json` con la app levantada |
| API de OSV (`api.osv.dev`) | **Bloqueada** (403 en el proxy) | `deps_audit` usa por defecto el servicio `pypi` de pip-audit (sí accesible); `servicio = "osv"` quedaría SKIPPED | `qgate doctor` muestra la conectividad a OSV |
| Registro de Semgrep (`semgrep.dev`) | **Bloqueado** | Solo reglas locales versionadas; nota en el informe | Con red: se añaden `p/python` y `p/owasp-top-ten` automáticamente |
| `semgrep --version` | Intentaba consultar actualizaciones y bloqueaba ~100 s | El kit ejecuta todas las herramientas con `SEMGREP_ENABLE_VERSION_CHECK=0` y métricas desactivadas | — |
| PowerShell (`install.ps1`) | No hay `pwsh` en el contenedor | Script escrito para Windows PowerShell 5.1+ sin admin | Ejecutar `powershell -ExecutionPolicy Bypass -File install.ps1 -ProjectPath <ruta>` |
| Rutas y ejecutables Windows | No ejecutable en Linux | Código solo con `pathlib`, `subprocess` con listas, búsqueda de `.exe` en `Scripts\` | Workflow de GitHub con `windows-latest` (matriz 3.10/3.12) |
| gitleaks para Windows | Descargado y verificado solo el de Linux | SHA-256 de `windows_x64.zip` embebido desde el archivo oficial de checksums | `install.ps1` o la primera ejecución de `qgate run` lo descarga y verifica |
| Semgrep nativo en Windows | No probado | Existe wheel `win_amd64` para 1.183.0 | Si falla, `semgrep` queda SKIPPED (FAIL en CI); alternativa: ejecutar el gate en WSL o en el agente Linux |
| Python 3.10 con el lock | El lock exige Python ≥ 3.11 (varias herramientas ya no soportan 3.10) | El kit en sí funciona en 3.10; el job 3.10 de CI instala `.[tools]` resuelto | `pip install -e .[tools]` en un venv 3.10 |
| `demo_dashboard` en 3.10 | Requiere ≥ 3.11 (`typing.Self`, dependencias fijadas) | Las pruebas del kit que lo usan se omiten en 3.10 | — |
| Agente self-hosted de Azure | No disponible | Plantilla con `poolName`; `UsePythonVersion` requiere la versión en el *tool cache* del agente | Registrar el agente y ejecutar la etapa Validate |
| Extensión *SARIF SAST Scans Tab* | No disponible | `results.sarif` valida contra el esquema oficial 2.1.0 (prueba automatizada) y se publica como artefacto `CodeAnalysisLogs` | Instalar la extensión en la organización de Azure DevOps |

## Hallazgos reales durante la construcción

- **Vulnerabilidades en herramientas**: pip-audit encontró CVE en `mcp==1.29.0` y
  `opentelemetry-api==1.37.0`, ambos fijados exactamente por `semgrep 1.183.0`. No se pueden
  actualizar sin romper semgrep; se registraron como **excepciones con vencimiento**
  (`qgate-exceptions.toml`, vence 2027-01-28). Al vencer, el gate del kit fallará a propósito.
- **Demo bajo carga**: el smoke de locust detectó que SQLite en memoria con una única conexión
  compartida provocaba errores 500 y la caída de uvicorn bajo concurrencia; se serializó el acceso
  solo para SQLite (SQL Server usa su pool).
- **schemathesis** detectó un 404 HTML documentado con tipo de contenido JSON; corregido.

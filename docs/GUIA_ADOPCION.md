# Guía de adopción en un dashboard existente

Esta guía aplica el kit a un dashboard FastAPI desplegado en Windows con la estructura típica:

```
C:\apps\mi_dashboard\
├── release\          # código versionado que se despliega (repositorio git)
│   ├── app\
│   ├── tests\
│   └── requirements.txt
└── runtime\          # logs, caché, archivos generados en el servidor (NO versionar)
```

## 1. Instalar en el equipo de desarrollo

```powershell
git clone https://github.com/ismaelanaya3-netizen/90_TOOL_quality_gate C:\herramientas\qgate
cd C:\apps\mi_dashboard\release
powershell -ExecutionPolicy Bypass -File C:\herramientas\qgate\install.ps1 -ProjectPath . -PythonVersion 3.12
.\.venv\Scripts\Activate.ps1
```

## 2. Aplicar el kit

```powershell
qgate init . --app-module app.main:app --src app --python 3.12
```

`init` **no rompe nada**:

- Copia `qgate.toml`, `qgate-exceptions.toml`, `.pre-commit-config.yaml`, `azure-pipelines.yml`,
  `noxfile.py`, `requirements-dev.lock` y `.vscode/tasks.json` **solo si no existen** (`--force`
  los reemplaza dejando `.bak`).
- Añade a `pyproject.toml` únicamente las secciones que faltan (`[tool.ruff]`, `[tool.mypy]`,
  `[tool.pytest.ini_options]`, `[tool.coverage.run]`…), muestra el diff y crea
  `pyproject.toml.bak`.
- Agrega `.qgate/` a `.gitignore`.

Revise `qgate.toml`: `src`, `app_module`, `[cobertura].criticos` (auth, seguridad, acceso a BD),
`[fastapi].entorno_produccion` (variables con las que la app arranca en modo producción) y
`[proyecto].excluir` (por defecto `release/**` y `runtime/**` si el repositorio está un nivel
arriba).

## 3. Estrategia gradual para los primeros cientos de hallazgos

Un dashboard existente puede arrojar cientos de hallazgos la primera vez. No los silencie en bloque:

1. **Semana 1 — `fast`**: `qgate run --level fast`.
   - `ruff format .` resuelve el formato de una vez (commit aparte, solo formato).
   - `ruff check --fix .` corrige automáticamente buena parte del lint.
   - Los secretos se corrigen **siempre** (rotar la credencial y moverla a variables de entorno).
   - Active el hook de pre-commit: desde ahora nada empeora.
2. **Semanas 2–3 — `standard`**: tipado, pruebas, SAST y dependencias.
   - Empiece por `bandit`/`semgrep` ALTAS (SQL concatenado, `verify=False`, XML sin `defusedxml`).
   - Fije dependencias: `pip freeze > requirements.txt` dentro del venv del proyecto.
   - mypy: agregue tipos módulo por módulo empezando por los críticos.
   - Cobertura: pruebas primero en `auth`, seguridad y acceso a BD (umbral 95 %).
3. **Semana 4 — `full`**: levante la app con `qgate run --level full` y corrija headers, límites de
   tamaño y errores 5xx que encuentre schemathesis.

Mientras avanza puede usar `qgate run --profile baseline` para medir contra lo que exigiría el
pipeline corporativo típico, sin bajar nunca el perfil por defecto del repositorio.

### Uso responsable de excepciones

- Solo para hallazgos **revisados** que son falsos positivos o riesgos aceptados.
- Siempre con justificación concreta, responsable y vencimiento (máximo 180 días).
- Prefiera el alcance más pequeño: `regla` exacta y `archivo` concreto, nunca `"*"`.
- Revise `qgate exceptions list` en cada sprint; las que vencen hacen fallar el gate a propósito.

```toml
[[excepcion]]
regla = "B608"
herramienta = "bandit"
archivo = "app/reports/export.py"
justificacion = "Nombre de columna tomado de una lista blanca fija (ALLOWED_COLUMNS); valores parametrizados."
responsable = "Ismael Anaya"
creada = 2026-10-30
vence = 2027-01-28
```

## 4. VS Code

`qgate init` crea `.vscode/tasks.json` con las tareas *qgate: fast*, *qgate: standard* (tarea de
prueba por defecto, `Ctrl+Shift+P → Run Test Task`), *qgate: full*, *qgate: abrir informe* y
*qgate: doctor*. Seleccione el intérprete `.venv\Scripts\python.exe` para que las tareas usen el
entorno del proyecto. Extensiones recomendadas: Ruff, Mypy Type Checker y SonarLint (ver
`ALINEACION_TI.md`).

## 5. Pipeline

`azure-pipelines.yml` queda listo: etapa **Validate** en cada PR y **DeepScan** en `main` o manual.
Ajuste `poolName` si usará un agente self-hosted en un servidor interno. El pipeline verifica que
`pythonVersion` coincide con `python_objetivo` antes de ejecutar nada.

## 6. Despliegue (`release/` + `runtime/`)

`qgate` es una herramienta de desarrollo y CI: **no** se instala en el servidor de producción. En
el servidor solo se despliega `release/` con su `requirements.txt` fijado. Si el servidor
ejecuta la app con uvicorn, use `--no-server-header` y configure en IIS/proxy el límite de tamaño
de petición equivalente a `[http].tam_max_request_kb`.

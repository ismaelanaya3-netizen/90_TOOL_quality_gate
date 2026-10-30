# Alineación con TI

El kit es un **superconjunto exigente** porque aún no se conocen las herramientas y umbrales
exactos del pipeline corporativo. Este documento lista qué preguntar a TI y cómo trasladar las
respuestas a un perfil `epm_ti` sin tocar el código del kit.

## Preguntas para TI

### Plantillas y pipelines
1. ¿Existe una plantilla corporativa de Azure Pipelines (`extends:`/`template:`) que debamos usar?
   ¿Permite pasos propios antes/después?
2. ¿Qué pool de agentes usaremos (Microsoft-hosted o self-hosted)? ¿Windows o Linux? ¿Tienen
   salida a internet (PyPI, GitHub, OSV) o pasan por proxy/feeds internos (Azure Artifacts)?
3. ¿Los agentes tienen Docker? (necesario para ZAP baseline) ¿Hay un ZAP corporativo?

### Herramientas de análisis
4. ¿Usan **SonarQube/SonarCloud**? ¿Qué *Quality Profile* y *Quality Gate* aplican a Python
   (cobertura sobre código nuevo, duplicación, *Security Hotspots*, *Maintainability Rating*)?
5. ¿Usan **Checkmarx**, **Fortify**, **Veracode** o **GitHub Advanced Security for Azure DevOps**?
6. ¿**Microsoft Defender for Cloud / DevOps** escanea los repos (secretos, IaC, dependencias)?
   ¿Con qué severidad bloquea?
7. ¿Qué herramienta de **SCA** usan (Dependabot, Mend/WhiteSource, Snyk, OWASP Dependency-Check)?
   ¿Qué política de licencias rige (lista negra/blanca)?

### Umbrales y políticas
8. Cobertura mínima global y sobre código nuevo. ¿Se mide con `coverage.xml` (Cobertura)?
9. Severidad que bloquea en SAST y SCA (¿Critical/High? ¿Medium?). ¿Plazos de remediación (SLA)?
10. **Branch policies**: revisores mínimos, build de validación obligatorio, resolución de
    comentarios, *work item* vinculado, estrategia de merge.
11. **Política de desarrollo seguro** (SDLC): ¿hay requisitos documentados (OWASP ASVS, CIS,
    políticas internas de headers, TLS, gestión de secretos, registro de excepciones)?
12. ¿Cómo debe documentarse una excepción o riesgo aceptado (formato, aprobador, vigencia)?
13. ¿Qué evidencia piden para auditoría (PDF, artefactos del pipeline, retención)?

## Crear el perfil `epm_ti`

Los perfiles se definen en `qgate.toml` sin modificar el kit. `hereda` toma todos los umbrales de
otro perfil y solo se redefinen los que cambian. `"no_exigido"` desactiva un umbral (el check se
muestra como no obligatorio para ese perfil).

```toml
[perfiles.epm_ti]
descripcion = "Reglas reales del pipeline de TI (actualizado 2026-11-15, fuente: correo de TI)"
hereda = "baseline"
cobertura_total = 80            # Sonar: 80 % sobre código nuevo
bandit_severidad_minima = "MEDIUM"
semgrep_hallazgos = 0           # equivalente a Checkmarx High/Medium
mypy_errores = "no_exigido"
ruff_reglas = ["E", "F", "W", "S", "B"]
```

Uso:

```bash
qgate run --profile epm_ti
```

El gate por defecto sigue siendo `strict`, y el informe muestra los umbrales y márgenes de **todos**
los perfiles definidos (strict, baseline y epm_ti), de modo que el informe demuestra cuánto se
supera lo que exige TI. Si TI confirma un umbral **más exigente** que `strict`, súbalo también en
`[perfiles.strict]` para que el margen nunca sea negativo.

Claves disponibles (ver `src/qgate/config.py`, `DEFAULT_PROFILES`): `ruff_reglas`,
`formato_diferencias`, `lint_hallazgos`, `secretos`, `archivo_lineas_max`, `archivo_lineas_aviso`,
`complejidad_peor` (1=A … 6=F), `complejidad_promedio`, `mypy_errores`, `pruebas_fallidas`,
`cobertura_total`, `cobertura_critica`, `bandit_severidad_minima`, `bandit_hallazgos`,
`semgrep_hallazgos`, `vulnerabilidades`, `dependencias_sin_fijar`, `licencias_prohibidas`,
`fastapi_hallazgos`, `version_python_desalineada`, `sintaxis_incompatible`, `api_fallos`,
`http_fallos`, `zap_alertas`, `carga_p95_ms`, `carga_errores_pct`.

## SonarQube: SonarLint en *connected mode*

Si TI usa SonarQube, el control más cercano al pipeline es ver **las mismas reglas** en el editor:

1. Instale la extensión **SonarLint** (SonarQube for IDE) en VS Code.
2. Pida a TI la URL del servidor y un *user token* con permiso de lectura del proyecto.
3. En VS Code: *SonarLint → Add SonarQube Connection*, pegue URL y token.
4. *Bind* del workspace al proyecto de SonarQube (`sonarlint.connectedMode.project` en
   `.vscode/settings.json` con `projectKey`).
5. SonarLint descargará el *Quality Profile* corporativo y marcará los mismos *issues* y
   *Security Hotspots* que verá el pipeline.

Para alinear la cobertura con Sonar, publique `coverage.xml` de `.qgate/latest` en la propiedad
`sonar.python.coverage.reportPaths` y el informe de bandit/ruff como *external issues* si TI lo
permite. `results.sarif` también puede importarse en SonarQube ≥ 10.3 (*external issues SARIF*).

## Checkmarx / Defender / GHAS

- Los hallazgos de `semgrep` (reglas `qgate-*`) cubren las familias que estos motores suelen
  reportar en Python: inyección SQL, comandos, deserialización, XXE, SSRF, path traversal, TLS.
- `results.sarif` sigue SARIF 2.1.0 con CWE en `properties.tags`, compatible con la pestaña
  *Scans* de Azure DevOps y con GitHub Advanced Security.
- Si TI usa Defender for DevOps, el *Microsoft Security DevOps* task también consume SARIF.

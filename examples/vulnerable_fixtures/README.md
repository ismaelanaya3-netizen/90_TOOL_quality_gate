# ⚠️ FIXTURES DELIBERADAMENTE INSEGUROS — NO USAR

Esta carpeta contiene código **intencionalmente vulnerable** para verificar que el Quality Gate
detecta cada falla (`tests/test_detection.py`). Nunca es importada por el kit ni debe desplegarse.

| Falla | Archivo | Check que debe detectarla |
|---|---|---|
| SQL concatenado con f-string | `vulnapp/db.py` | semgrep, bandit (B608) |
| `eval` | `vulnapp/unsafe.py` | bandit (B307), semgrep, ruff (S307) |
| `subprocess` con `shell=True` | `vulnapp/unsafe.py` | bandit (B602), semgrep |
| `yaml.load` inseguro | `vulnapp/unsafe.py` | bandit (B506), semgrep |
| `requests` con `verify=False` | `vulnapp/unsafe.py` | bandit (B501), semgrep |
| CORS `*` | `vulnapp/main.py` | fastapi_config, semgrep |
| `debug=True` | `vulnapp/main.py` | fastapi_config, semgrep |
| Token falso con formato real | `vulnapp/settings_fake.py` | secrets (gitleaks / detect-secrets) |
| Archivo de 1100 líneas | `vulnapp/huge_module.py` | file_size |
| Función de complejidad alta | `vulnapp/complex_logic.py` | complexity |
| Dependencia sin fijar | `requirements.txt` | deps_pinned |

El token de `settings_fake.py` es **inequívocamente falso** (contiene `FAKE`/`EXAMPLE`).
El repositorio del kit excluye esta carpeta de su escaneo de secretos mediante
`[secretos].excluir` en `qgate.toml` y el allowlist de `.gitleaks.toml`.

from __future__ import annotations

import datetime as dt
from pathlib import Path

import pytest

from qgate.cli import main
from qgate.config import ConfigError
from qgate.exceptions_registry import load_registry, parse_exception, render_list
from qgate.models import Finding, Level, Severity, Status
from qgate.runner import run_gate
from tests.conftest import write_project

TODAY = dt.date(2026, 10, 30)
VALID = {
    "regla": "B608",
    "archivo": "app/*.py",
    "justificacion": "Columnas tomadas de una lista blanca fija.",
    "responsable": "Equipo Datos",
    "creada": "2026-10-01",
    "vence": "2027-01-15",
}


def _exc_file(root: Path, vence: str, regla: str = "file-too-long") -> None:
    (root / "qgate-exceptions.toml").write_text(
        f"""[[excepcion]]
regla = "{regla}"
herramienta = "qgate"
archivo = "app/big.py"
justificacion = "Módulo generado automáticamente; se dividirá en la v2."
responsable = "Ismael Anaya"
creada = 2026-09-01
vence = {vence}
""",
        encoding="utf-8",
    )


def _big_project(root: Path) -> Path:
    body = "\n".join(f"x{i} = {i}" for i in range(1200)) + "\n"
    return write_project(root, '[proyecto]\nsrc = ["app"]\n', {"app/big.py": body})


@pytest.mark.parametrize(
    ("change", "message"),
    [
        ({"responsable": ""}, "responsable"),
        ({"vence": "2028-01-01"}, "180"),
        ({"vence": "2026-09-01"}, "anterior"),
        ({"justificacion": "porque sí"}, "justificación"),
        ({"creada": "ayer"}, "fecha inválida"),
    ],
)
def test_validation(change: dict[str, str], message: str) -> None:
    with pytest.raises(ConfigError, match=message):
        parse_exception({**VALID, **change}, 1)


def test_states_and_matching() -> None:
    item = parse_exception(VALID, 1)
    assert item.state(TODAY) == "vigente"
    assert item.state(dt.date(2027, 1, 1)) == "por_vencer"
    assert item.state(dt.date(2027, 2, 1)) == "vencida"
    assert item.matches(Finding("bandit", "B608", Severity.MEDIUM, "sql", "app/repo.py", 3))
    assert not item.matches(Finding("bandit", "B608", Severity.MEDIUM, "sql", "lib/repo.py", 3))


def test_active_exception_suppresses_and_is_reported(tmp_path: Path) -> None:
    root = _big_project(tmp_path)
    _exc_file(root, "2027-02-01")
    gate = run_gate(root, level=Level.FAST, only=["file_size"], ci=False, today=TODAY)
    result = gate.results[0]
    assert result.status is Status.PASS
    assert result.applied_exceptions == ["qgate:file-too-long@app/big.py"]
    assert result.findings[0].suppressed_by
    html = (Path(gate.out_dir) / "report.html").read_text(encoding="utf-8")
    assert "qgate:file-too-long@app/big.py" in html


def test_expired_exception_fails(tmp_path: Path) -> None:
    root = _big_project(tmp_path)
    _exc_file(root, "2026-10-01")
    gate = run_gate(root, level=Level.FAST, only=["file_size"], ci=False, today=TODAY)
    result = gate.results[0]
    assert result.status is Status.FAIL
    assert "Excepción vencida" in result.reason
    assert not result.findings[0].suppressed_by


def test_list_rules_and_render(tmp_path: Path) -> None:
    (tmp_path / "qgate-exceptions.toml").write_text(
        """[[excepcion]]
regla = ["CVE-1", "CVE-2"]
justificacion = "Dependencia de desarrollo sin corrección publicada."
responsable = "Seguridad"
creada = 2026-10-01
vence = 2026-11-10
""",
        encoding="utf-8",
    )
    registry = load_registry(tmp_path, TODAY)
    assert [e.rule for e in registry.items] == ["CVE-1", "CVE-2"]
    text = render_list(registry)
    assert "POR VENCER (< 30 días) (2)" in text
    assert render_list(load_registry(tmp_path / "nada")) == "No hay excepciones registradas."


def test_cli_exceptions_list_exit_codes(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    _exc_file(tmp_path, "2026-10-01")
    assert main(["exceptions", "list", "--path", str(tmp_path)]) == 1
    assert "VENCIDAS (1)" in capsys.readouterr().out
    (tmp_path / "qgate-exceptions.toml").write_text("excepcion = 3\n", encoding="utf-8")
    assert main(["exceptions", "list", "--path", str(tmp_path)]) == 2


def test_registry_apply_details() -> None:
    from qgate.exceptions_registry import ExceptionRegistry

    scoped = parse_exception({**VALID, "herramienta": "bandit", "archivo": "**"}, 1)
    other_rule = parse_exception({**VALID, "regla": "B101"}, 2)
    registry = ExceptionRegistry([other_rule, scoped], today=TODAY)
    findings = [
        Finding("bandit", "B608", Severity.MEDIUM, "sql", "lib/a.py", 1),
        Finding("bandit", "B608", Severity.MEDIUM, "sql", "lib/b.py", 2),
        Finding("semgrep", "B608", Severity.MEDIUM, "sql", "lib/c.py", 3),
    ]
    applied, expired = registry.apply(findings)
    assert applied == ["bandit:B608@**"]
    assert expired == []
    assert [bool(f.suppressed_by) for f in findings] == [True, True, False]
    assert scoped.used == 2
    data = scoped.to_dict(TODAY)
    assert data["estado"] == "vigente"
    assert data["usos"] == 2


def test_dates_accept_toml_datetimes() -> None:
    item = parse_exception({**VALID, "creada": dt.datetime(2026, 10, 1, 8, 0), "vence": dt.date(2026, 12, 1)}, 1)
    assert item.created == dt.date(2026, 10, 1)

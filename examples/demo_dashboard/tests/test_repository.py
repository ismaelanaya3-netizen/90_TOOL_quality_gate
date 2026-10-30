from __future__ import annotations

import datetime as dt

import pytest

from app import db
from app.db import create_db_engine, init_schema, seed_demo_data
from app.repository import MeasurementRepository
from app.routes import polyline


def _repo(seed: bool = True) -> MeasurementRepository:
    engine = create_db_engine("sqlite+pysqlite:///:memory:")
    init_schema(engine)
    if seed:
        assert seed_demo_data(engine, days=3) == 3 * 24 * 3
    return MeasurementRepository(engine)


def test_series_is_bounded_and_ordered() -> None:
    points = _repo().series("RIO-03", dt.date(2026, 1, 2), dt.date(2026, 1, 2))
    assert len(points) == 24
    assert points == sorted(points, key=lambda p: p.ts)


def test_parameters_are_not_interpreted_as_sql() -> None:
    repo = _repo()
    assert repo.series("MED-01' OR '1'='1", dt.date(2026, 1, 1), dt.date(2026, 1, 3)) == []
    assert repo.count("MED-01' OR '1'='1") == 0
    assert repo.count("MED-01") == 72


def test_latest_day_and_empty_database() -> None:
    assert _repo().latest_day("MED-01") == dt.date(2026, 1, 3)
    empty = _repo(seed=False)
    assert empty.latest_day("MED-01") is None
    assert empty.stations() == []


def test_sql_server_engine_options(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, object] = {}

    def fake_create_engine(url: str, **kwargs: object) -> object:
        captured.update(url=url, **kwargs)
        return object()

    monkeypatch.setattr(db, "create_engine", fake_create_engine)
    db.create_db_engine("mssql+pyodbc://@SERVIDOR/BD?driver=ODBC+Driver+18+for+SQL+Server")
    assert captured["pool_pre_ping"] is True
    assert str(captured["url"]).startswith("mssql+pyodbc://")


def test_polyline_handles_flat_and_empty_series() -> None:
    assert polyline([]) == ""
    points = _repo().series("MED-01", dt.date(2026, 1, 1), dt.date(2026, 1, 1))
    assert len(polyline(points).split()) == 24


def test_concurrent_reads_are_serialized_for_sqlite() -> None:
    from concurrent.futures import ThreadPoolExecutor

    repo = _repo()
    with ThreadPoolExecutor(max_workers=8) as pool:
        counts = list(pool.map(lambda _: repo.count("MED-02"), range(64)))
    assert set(counts) == {72}


def test_other_dialects_use_the_pool_without_lock() -> None:
    from types import SimpleNamespace
    from typing import Any, cast

    real = create_db_engine("sqlite+pysqlite:///:memory:")
    init_schema(real)
    fake = SimpleNamespace(dialect=SimpleNamespace(name="mssql"), connect=real.connect)
    repo = MeasurementRepository(cast(Any, fake))
    assert repo.stations() == []

"""Data access with parameterized queries only (portable to SQL Server)."""

from __future__ import annotations

import datetime as dt
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass

from sqlalchemy import Connection, Engine, func, select, text

from app.db import measurements

MAX_POINTS = 5000


@dataclass(frozen=True)
class Point:
    ts: dt.datetime
    value: float


class MeasurementRepository:
    def __init__(self, engine: Engine) -> None:
        self._engine = engine
        # In-memory SQLite shares a single connection (StaticPool): serialize access.
        # SQL Server uses a real connection pool and needs no lock.
        self._lock = threading.Lock() if engine.dialect.name == "sqlite" else None

    @contextmanager
    def _connect(self) -> Iterator[Connection]:
        if self._lock is None:
            with self._engine.connect() as conn:
                yield conn
            return
        with self._lock, self._engine.connect() as conn:
            yield conn

    def stations(self) -> list[str]:
        stmt = select(measurements.c.station).distinct().order_by(measurements.c.station)
        with self._connect() as conn:
            return [str(row[0]) for row in conn.execute(stmt)]

    def count(self, station: str) -> int:
        # Raw SQL is allowed only with bound parameters (":station"), never string building.
        stmt = text("SELECT COUNT(*) FROM measurements WHERE station = :station")
        with self._connect() as conn:
            return int(conn.execute(stmt, {"station": station}).scalar_one())

    def latest_day(self, station: str) -> dt.date | None:
        stmt = select(func.max(measurements.c.ts)).where(measurements.c.station == station)
        with self._connect() as conn:
            value = conn.execute(stmt).scalar_one_or_none()
        return value.date() if isinstance(value, dt.datetime) else None

    def series(self, station: str, start: dt.date, end: dt.date) -> list[Point]:
        """Points in ``[start, end]`` (whole days), ordered by time."""
        lower = dt.datetime.combine(start, dt.time.min)
        upper = dt.datetime.combine(end + dt.timedelta(days=1), dt.time.min)
        stmt = (
            select(measurements.c.ts, measurements.c.value)
            .where(measurements.c.station == station, measurements.c.ts >= lower, measurements.c.ts < upper)
            .order_by(measurements.c.ts)
            .limit(MAX_POINTS)
        )
        with self._connect() as conn:
            return [Point(ts=row.ts, value=float(row.value)) for row in conn.execute(stmt)]

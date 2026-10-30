"""Database engine and schema. Works with SQLite (tests) and SQL Server (pyodbc)."""

from __future__ import annotations

import datetime as dt
import math

from sqlalchemy import Column, DateTime, Engine, Float, Integer, MetaData, String, Table, create_engine, insert
from sqlalchemy.pool import StaticPool

metadata = MetaData()

measurements = Table(
    "measurements",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("station", String(20), nullable=False, index=True),
    Column("ts", DateTime, nullable=False, index=True),
    Column("value", Float, nullable=False),
)

DEMO_STATIONS = ("MED-01", "MED-02", "RIO-03")
DEMO_START = dt.datetime(2026, 1, 1, tzinfo=dt.UTC).replace(tzinfo=None)  # stored as naive UTC


def create_db_engine(url: str) -> Engine:
    """Create the engine; in-memory SQLite shares one connection across threads."""
    if url.startswith("sqlite"):
        return create_engine(url, connect_args={"check_same_thread": False}, poolclass=StaticPool)
    return create_engine(url, pool_pre_ping=True, pool_recycle=1800)


def init_schema(engine: Engine) -> None:
    metadata.create_all(engine)


def seed_demo_data(engine: Engine, days: int = 90) -> int:
    """Insert deterministic hourly data for the demo stations. Returns inserted rows."""
    rows = []
    for index, station in enumerate(DEMO_STATIONS):
        for hour in range(days * 24):
            value = 20 + 5 * math.sin(hour / 24 * 2 * math.pi) + index * 3 + (hour % 7) * 0.1
            rows.append({"station": station, "ts": DEMO_START + dt.timedelta(hours=hour), "value": round(value, 2)})
    with engine.begin() as conn:
        conn.execute(insert(measurements), rows)
    return len(rows)

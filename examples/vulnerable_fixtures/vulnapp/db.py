"""INTENTIONALLY VULNERABLE: SQL built with f-strings (SQL injection)."""

from typing import Any


def find_station(cursor: Any, name: str) -> Any:
    query = f"SELECT * FROM stations WHERE name = '{name}'"
    cursor.execute(query)
    return cursor.fetchall()


def find_values(conn: Any, station: str) -> Any:
    return conn.execute(f"SELECT value FROM measurements WHERE station = '{station}'")

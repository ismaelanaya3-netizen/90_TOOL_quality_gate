from __future__ import annotations

from fastapi.testclient import TestClient

from app.main import create_app
from app.settings import Settings


def test_health(client: TestClient) -> None:
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_stations(client: TestClient) -> None:
    assert client.get("/api/stations").json() == ["MED-01", "MED-02", "RIO-03"]


def test_series_ok(client: TestClient) -> None:
    response = client.get("/api/series", params={"station": "MED-01", "start": "2026-01-01", "end": "2026-01-02"})
    body = response.json()
    assert response.status_code == 200
    assert body["count"] == 48
    assert body["points"][0]["ts"].startswith("2026-01-01T00:00")


def test_series_unknown_station(client: TestClient) -> None:
    response = client.get("/api/series", params={"station": "XYZ-99", "start": "2026-01-01", "end": "2026-01-02"})
    assert response.status_code == 404


def test_series_rejects_inverted_range(client: TestClient) -> None:
    response = client.get("/api/series", params={"station": "MED-01", "start": "2026-01-05", "end": "2026-01-01"})
    assert response.status_code == 422


def test_series_rejects_long_range(client: TestClient) -> None:
    response = client.get("/api/series", params={"station": "MED-01", "start": "2026-01-01", "end": "2026-03-01"})
    assert response.status_code == 422


def test_series_rejects_bad_station_code(client: TestClient) -> None:
    response = client.get("/api/series", params={"station": "x'; DROP", "start": "2026-01-01", "end": "2026-01-02"})
    assert response.status_code == 422


def test_dashboard_renders_chart(client: TestClient) -> None:
    response = client.get("/", params={"station": "MED-02"})
    assert response.status_code == 200
    assert "<polyline" in response.text
    assert "MED-02" in response.text


def test_dashboard_default_station(client: TestClient) -> None:
    assert "MED-01" in client.get("/").text


def test_dashboard_unknown_station(client: TestClient) -> None:
    assert client.get("/", params={"station": "ABC-12"}).status_code == 404


def test_dashboard_without_data() -> None:
    with TestClient(create_app(Settings(env="test", seed_demo=False))) as client:
        response = client.get("/")
    assert response.status_code == 200
    assert "No hay datos" in response.text


def test_docs_disabled_in_production() -> None:
    app = create_app(Settings(env="production"))
    assert app.docs_url is None
    assert app.openapi_url is None
    assert app.redoc_url is None
    with TestClient(app) as client:
        assert client.get("/docs").status_code == 404
        assert client.get("/openapi.json").status_code == 404


def test_docs_enabled_outside_production(client: TestClient) -> None:
    assert client.get("/openapi.json").status_code == 200

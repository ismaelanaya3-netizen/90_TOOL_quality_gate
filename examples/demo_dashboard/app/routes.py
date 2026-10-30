"""HTTP routes: health, JSON API and the HTML dashboard."""

from __future__ import annotations

import datetime as dt
from pathlib import Path
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from app.repository import MeasurementRepository, Point
from app.schemas import ErrorOut, HealthOut, PointOut, SeriesOut, SeriesQuery, StationCode

router = APIRouter()
templates = Jinja2Templates(directory=Path(__file__).parent / "templates")
CHART_W, CHART_H = 640, 220


def get_repository(request: Request) -> MeasurementRepository:
    repository: MeasurementRepository = request.app.state.repository
    return repository


Repo = Annotated[MeasurementRepository, Depends(get_repository)]


@router.get("/health", response_model=HealthOut)
def health() -> HealthOut:
    return HealthOut(status="ok")


@router.get("/api/stations", response_model=list[str])
def stations(repo: Repo) -> list[str]:
    return repo.stations()


@router.get("/api/series", response_model=SeriesOut, responses={404: {"model": ErrorOut}})
def series(query: Annotated[SeriesQuery, Query()], repo: Repo) -> SeriesOut:
    if query.station not in repo.stations():
        raise HTTPException(status_code=404, detail="Estación no encontrada")
    points = repo.series(query.station, query.start, query.end)
    return SeriesOut(
        station=query.station,
        start=query.start,
        end=query.end,
        count=len(points),
        points=[PointOut(ts=p.ts, value=p.value) for p in points],
    )


def polyline(points: list[Point]) -> str:
    """SVG polyline coordinates scaled to the chart box (rendered server side, no JS)."""
    if not points:
        return ""
    low = min(p.value for p in points)
    span = (max(p.value for p in points) - low) or 1.0
    step = CHART_W / max(len(points) - 1, 1)
    return " ".join(f"{i * step:.1f},{CHART_H - (p.value - low) / span * CHART_H:.1f}" for i, p in enumerate(points))


@router.get("/", response_class=HTMLResponse, responses={404: {"description": "Estación no encontrada (HTML)"}})
def dashboard(request: Request, repo: Repo, station: Annotated[StationCode | None, Query()] = None) -> HTMLResponse:
    available = repo.stations()
    selected = station or (available[0] if available else None)
    if selected is not None and selected not in available:
        missing: dict[str, object] = {"stations": available, "selected": None, "count": 0}
        return templates.TemplateResponse(request, "dashboard.html", missing, status_code=404)
    last = repo.latest_day(selected) if selected else None
    points = repo.series(selected, last - dt.timedelta(days=6), last) if selected and last else []
    context: dict[str, object] = {
        "stations": available,
        "selected": selected,
        "points": polyline(points),
        "count": len(points),
        "width": CHART_W,
        "height": CHART_H,
        "last_value": points[-1].value if points else None,
    }
    return templates.TemplateResponse(request, "dashboard.html", context)

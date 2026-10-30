"""Request/response models with strict validation."""

from __future__ import annotations

import datetime as dt
from typing import Annotated, Self

from pydantic import BaseModel, ConfigDict, Field, model_validator

MAX_RANGE_DAYS = 31
StationCode = Annotated[str, Field(pattern=r"^[A-Z]{3}-\d{2}$", description="Código de estación, p. ej. MED-01")]


class SeriesQuery(BaseModel):
    model_config = ConfigDict(extra="forbid")

    station: StationCode
    start: Annotated[dt.date, Field(ge=dt.date(2000, 1, 1), le=dt.date(2100, 12, 31))]
    end: Annotated[dt.date, Field(ge=dt.date(2000, 1, 1), le=dt.date(2100, 12, 31))]

    @model_validator(mode="after")
    def check_range(self) -> Self:
        if self.end < self.start:
            msg = "end debe ser posterior o igual a start"
            raise ValueError(msg)
        if (self.end - self.start).days > MAX_RANGE_DAYS:
            msg = f"el rango máximo es de {MAX_RANGE_DAYS} días"
            raise ValueError(msg)
        return self


class PointOut(BaseModel):
    ts: dt.datetime
    value: float


class SeriesOut(BaseModel):
    station: str
    start: dt.date
    end: dt.date
    count: int
    points: list[PointOut]


class HealthOut(BaseModel):
    status: str


class ErrorOut(BaseModel):
    detail: str

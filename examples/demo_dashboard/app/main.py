"""Application factory with secure defaults."""

from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from starlette.middleware.trustedhost import TrustedHostMiddleware

from app.db import create_db_engine, init_schema, seed_demo_data
from app.repository import MeasurementRepository
from app.routes import router
from app.security import BodySizeLimitMiddleware, SecurityHeadersMiddleware
from app.settings import Settings


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or Settings()
    # Interactive docs and the OpenAPI schema are never published in production.
    docs_url = None if settings.is_production else "/docs"
    openapi_url = None if settings.is_production else "/openapi.json"
    app = FastAPI(title="Demo Dashboard", version="0.1.0", docs_url=docs_url, redoc_url=None, openapi_url=openapi_url)

    engine = create_db_engine(settings.database_url)
    init_schema(engine)
    if settings.seed_demo:
        seed_demo_data(engine)
    app.state.repository = MeasurementRepository(engine)

    # Last added = outermost: security headers wrap every response, including 400/413 errors.
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=settings.allowed_hosts)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_methods=["GET"],
        allow_headers=["Accept"],
        allow_credentials=False,
    )
    app.add_middleware(BodySizeLimitMiddleware, max_bytes=settings.max_body_kb * 1024)
    app.add_middleware(SecurityHeadersMiddleware)

    app.include_router(router)
    app.mount("/static", StaticFiles(directory=Path(__file__).parent / "static"), name="static")
    return app


app = create_app()

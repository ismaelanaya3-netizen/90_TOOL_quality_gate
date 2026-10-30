"""Application settings loaded from environment variables (no secrets in code)."""

from __future__ import annotations

from typing import Literal

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Values come from ``APP_*`` variables, e.g. ``APP_DATABASE_URL``.

    SQL Server example: ``mssql+pyodbc://@SERVIDOR/BD?driver=ODBC+Driver+18+for+SQL+Server&trusted_connection=yes``
    """

    model_config = SettingsConfigDict(env_prefix="APP_", extra="ignore")

    env: Literal["development", "test", "production"] = "development"
    database_url: str = "sqlite+pysqlite:///:memory:"
    allowed_hosts: list[str] = ["127.0.0.1", "localhost", "testserver"]
    cors_origins: list[str] = ["http://localhost:8000"]
    max_body_kb: int = 1024
    seed_demo: bool = True

    @property
    def is_production(self) -> bool:
        return self.env == "production"

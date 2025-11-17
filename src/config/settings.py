from __future__ import annotations

import os
from functools import lru_cache
from typing import Optional

from pydantic import Field, HttpUrl, validator
from pydantic_settings import BaseSettings
from dotenv import load_dotenv


load_dotenv()


class Settings(BaseSettings):
    prisma_api_url: Optional[HttpUrl] = Field(
        default=None,
        env="PRISMA_API_URL",
        description="Base Prisma Cloud API URL, typically https://<tenant>/api",
    )
    prisma_access_key: Optional[str] = Field(default=None, env="PRISMA_ACCESS_KEY")
    prisma_secret_key: Optional[str] = Field(default=None, env="PRISMA_SECRET_KEY")
    prisma_firewall_ip: Optional[str] = Field(default=None, env="PRISMA_FIREWALL_IP")
    prisma_username: Optional[str] = Field(default=None, env="PRISMA_USERNAME")
    prisma_password: Optional[str] = Field(default=None, env="PRISMA_PASSWORD")

    grok_api_key: Optional[str] = Field(default=None, env="GROK_API_KEY")
    openai_api_key: Optional[str] = Field(default=None, env="OPENAI_API_KEY")

    timeout_seconds: int = Field(default=30, env="PRISMA_TIMEOUT_SECONDS")

    class Config:
        env_file = os.getenv("ENV_FILE", ".env")
        case_sensitive = False

    @validator("prisma_access_key", "prisma_secret_key", pre=True)
    def empty_string_to_none(cls, v: Optional[str]) -> Optional[str]:  # noqa: D401
        if v == "":
            return None
        return v


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return cached application settings."""

    return Settings()


def require_prisma_credentials(settings: Optional[Settings] = None) -> Settings:
    """Ensure required Prisma credentials are present, raise ValueError otherwise."""

    settings = settings or get_settings()
    missing = [
        name
        for name, value in {
            "PRISMA_API_URL": settings.prisma_api_url,
            "PRISMA_ACCESS_KEY": settings.prisma_access_key,
            "PRISMA_SECRET_KEY": settings.prisma_secret_key,
        }.items()
        if not value
    ]
    if missing:
        raise ValueError(
            "Missing required Prisma Cloud credentials: " + ", ".join(missing)
        )
    return settings

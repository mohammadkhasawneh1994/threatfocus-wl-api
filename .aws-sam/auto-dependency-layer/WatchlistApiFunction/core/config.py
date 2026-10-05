import os
from layers.app.python.pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    ENVIRONMENT: str = "production"
    LOG_LEVEL: str = "INFO"
    AWS_REGION: str = "us-east-1"
    TABLE_NAME: str = "ThreatFocusWatchlists"
    EVENT_BUS_NAME: str = "ThreatFocusEventBus"
    JWT_ALGORITHM: str = "RS256"
    JWT_AUDIENCE: str = "threatfocus-api"

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )


settings = Settings()
"""Server configuration loaded from environment or .env file."""

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    API_KEY: str = "CHANGE_ME_LONG_RANDOM_STRING_HERE"
    DB_PATH: str = "soc_lite.db"
    HOST: str = "127.0.0.1"
    PORT: int = 8000
    RETENTION_DAYS: int = 14
    WS_BATCH_MS: int = 500
    LOG_LEVEL: str = "INFO"

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )


settings = Settings()

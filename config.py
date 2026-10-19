import os
from functools import lru_cache
from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    # Paths
    models_dir: str = "models"
    data_dir: str = "datasets"

    # API Config
    api_host: str = "127.0.0.1"
    api_port: int = 8000
    rate_limit: str = "30/minute"

    # Database
    db_url: str = "sqlite:///./phishguard.db"

    # Logging
    log_level: str = "INFO"

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"

@lru_cache()
def get_settings():
    return Settings()
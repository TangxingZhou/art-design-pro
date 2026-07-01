import os
import typing
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    VERSION: str = "0.1.0"
    APP_TITLE: str = "Backend Example"
    PROJECT_NAME: str = "Backend Example"
    APP_DESCRIPTION: str = "Example for backend"

    CORS_ORIGINS: typing.List = ["*"]
    CORS_ALLOW_CREDENTIALS: bool = True
    CORS_ALLOW_METHODS: typing.List = ["*"]
    CORS_ALLOW_HEADERS: typing.List = ["*"]

    DEBUG: bool = True

    PROJECT_ROOT: str = os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir))
    BASE_DIR: str = os.path.abspath(os.path.join(PROJECT_ROOT, os.pardir))
    LOGS_ROOT: str = os.path.join(BASE_DIR, "logs")
    SECRET_KEY: str = "85e6545531e0551b09c9f11f470d7db10979a4b0c1ea9a4605652ef5772dd143"  # openssl rand -hex 32
    JWT_ALGORITHM: str = "HS256"
    JWT_ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 24 * 7  # 7 day
    TORTOISE_ORM: dict = {
        "connections": {
            # SQLite configuration
            "sqlite": {
                "engine": "tortoise.backends.sqlite",
                "credentials": {"file_path": f"{BASE_DIR}/db.sqlite3"},  # Path to SQLite database file
            },
            # PostgreSQL configuration
            # Install with: tortoise-orm[asyncpg]
            "postgres": {
                "engine": "tortoise.backends.asyncpg",
                "credentials": {
                    "host": "127.0.0.1",
                    "port": 5432,
                    "user": "postgres",
                    "password": "test123",
                    "database": "example",
                },
            },
        },
        "apps": {
            "models": {
                "models": ["models", "aerich.models"],
                "default_connection": "postgres",
            },
        },
        "use_tz": False,  # Whether to use timezone-aware datetimes
        "timezone": "Etc/GMT",  # Timezone setting
    }
    DATETIME_FORMAT: str = "%Y-%m-%d %H:%M:%S"


settings = Settings()

from contextlib import asynccontextmanager
from fastapi import FastAPI
from tortoise import Tortoise

from core.exceptions import SettingNotFound
from core.init_app import (
    init_data,
    make_middlewares,
    register_exceptions,
    register_routers,
)

try:
    from config import settings
except ImportError:
    raise SettingNotFound("Can not import settings")


@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_data(app)
    yield
    await Tortoise.close_connections()


def create_app() -> FastAPI:
    _app = FastAPI(
        title=settings.APP_TITLE,
        description=settings.APP_DESCRIPTION,
        version=settings.VERSION,
        openapi_url="/openapi.json",
        middleware=make_middlewares(),
        lifespan=lifespan,
    )
    register_exceptions(_app)
    register_routers(_app, prefix="/api")
    return _app


app = create_app()

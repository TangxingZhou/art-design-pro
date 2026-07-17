from __future__ import annotations

import asyncio
import json
import logging
import mimetypes
import os
from contextlib import asynccontextmanager

import anyio.to_thread
from fastapi import (
    FastAPI,
    HTTPException,
    applications,
)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.openapi.docs import get_swagger_ui_html
from fastapi.staticfiles import StaticFiles
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.middleware.sessions import SessionMiddleware
from starlette_compress import CompressMiddleware
from starsessions import (
    SessionAutoloadMiddleware,
)
from starsessions import (
    SessionMiddleware as StarSessionsMiddleware,
)
from starsessions.stores.redis import RedisStore

from config import settings
from constants import DATA_DIR, STATIC_DIR, FRONTEND_BUILD_DIR
from utils.events import (
    EVENTS,
    migrate_legacy_webhook_config,
    publish_event,
)
from models.config import Config
from utils.socket.main import (
    periodic_session_pool_cleanup,
    periodic_usage_pool_cleanup,
)
from utils.socket.main import (
    app as socket_app,
)
from utils.tasks import (
    redis_task_command_listener,
)
from utils.asgi_middleware import (
    AuthTokenMiddleware,
    CommitSessionMiddleware,
    WebsocketUpgradeGuardMiddleware,
)
from utils.audit import AuditLevel, AuditLoggingMiddleware
from utils.auth import (
    create_admin_user,
)
from utils.oauth import OAuthManager
from utils.redis import get_redis_client
from utils.security_headers import SecurityHeadersMiddleware
from routers import api_router


ENABLE_STAR_SESSIONS_MIDDLEWARE = False

log = logging.getLogger(__name__)


class SPAStaticFiles(StaticFiles):
    async def get_response(self, path: str, scope):
        try:
            return await super().get_response(path, scope)
        except (HTTPException, StarletteHTTPException) as ex:
            if ex.status_code == 404:
                if path.endswith('.js'):
                    # Return 404 for javascript files
                    raise ex
                else:
                    return await super().get_response('index.html', scope)
            else:
                raise ex


class CORSStaticFiles(StaticFiles):
    async def get_response(self, path: str, scope):
        response = await super().get_response(path, scope)
        response.headers['Access-Control-Allow-Origin'] = '*'
        return response


@asynccontextmanager
async def lifespan(app: FastAPI):
    from config import get_settings
    get_settings()
    # Store reference to main event loop for sync->async calls
    # This allows sync functions to schedule work on the main loop without blocking health checks
    app.state.main_loop = asyncio.get_running_loop()

    app.state.instance_id = settings.INSTANCE_ID

    if settings.SYSTEM.RESET_CONFIG_ON_START:
        await Config.clear()

    # await import_legacy_config_json()
    # if os.path.exists(f'{DATA_DIR}/config.json'):
    #     with open(f'{DATA_DIR}/config.json', 'r') as _f:
    #         await Config.upsert(json.load(_f))
    await Config.repair_flattened_dict_configs()
    await Config.seed_defaults(settings.SYSTEM.DEFAULT_CONFIG)
    # await initialize_runtime_config()
    await migrate_legacy_webhook_config()
    await publish_event(app, EVENTS.SYSTEM_STARTUP_STARTED, source='system')

    # Create admin account if specified and no users exist
    if settings.SYSTEM.AUTH.ADMIN_EMAIL and settings.SYSTEM.AUTH.ADMIN_PASSWORD:
        if await create_admin_user(
            f'{settings.SYSTEM.AUTH.ADMIN_EMAIL}',
            settings.SYSTEM.AUTH.ADMIN_PASSWORD.get_secret_value(),
            settings.SYSTEM.AUTH.ADMIN_NAME
        ):
            # Disable signup since we now have an admin
            await Config.upsert({'ui.enable_signup': False})

    app.state.redis = get_redis_client(async_mode=True)

    if app.state.redis is not None:
        app.state.redis_task_command_listener = asyncio.create_task(redis_task_command_listener(app))

    if settings.THREAD_POOL_SIZE and settings.THREAD_POOL_SIZE > 0:
        limiter = anyio.to_thread.current_default_thread_limiter()
        limiter.total_tokens = settings.THREAD_POOL_SIZE

    asyncio.create_task(periodic_usage_pool_cleanup())
    asyncio.create_task(periodic_session_pool_cleanup())

    # Mark application as ready to accept traffic from a startup perspective.
    app.state.startup_complete = True
    await publish_event(app, EVENTS.SYSTEM_STARTUP_COMPLETED, source='system')

    yield

    await publish_event(app, EVENTS.SYSTEM_SHUTDOWN_STARTED, source='system')

    # Shutdown: clean up shared resources
    from utils.session_pool import close_session

    await close_session()

    if hasattr(app.state, 'redis_task_command_listener'):
        app.state.redis_task_command_listener.cancel()

    await publish_event(app, EVENTS.SYSTEM_SHUTDOWN_COMPLETED, source='system')


app = FastAPI(
    title=settings.APP_TITLE,
    description=settings.APP_DESCRIPTION,
    version=settings.VERSION,
    docs_url='/docs' if settings.ENV == 'dev' else None,
    openapi_url='/openapi.json' if settings.ENV == 'dev' else None,
    redoc_url=None,
    root_path=settings.API_ROOT_PATH,
    lifespan=lifespan,
)

# Used by readiness checks to gate traffic until startup work is done.
app.state.startup_complete = False

# OIDC/OAuth2
oauth_manager = OAuthManager(app)
app.state.oauth_manager = oauth_manager

app.state.instance_id = None
app.state.redis = None

app.state.WEBUI_NAME = settings.PROJECT_NAME
app.state.LICENSE_METADATA = None
app.state.USER_COUNT = None
app.state.EXTERNAL_PWA_MANIFEST_URL = None


# Add the middleware to the app
app.add_middleware(CompressMiddleware)
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(CommitSessionMiddleware)
app.add_middleware(AuthTokenMiddleware)
app.add_middleware(WebsocketUpgradeGuardMiddleware)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ALLOW_ORIGINS,
    allow_credentials=settings.CORS_ALLOW_CREDENTIALS,
    allow_methods=settings.CORS_ALLOW_METHODS,
    allow_headers=settings.CORS_ALLOW_HEADERS,
)

try:
    audit_level = AuditLevel(settings.SYSTEM.AUDIT.LOG_LEVEL)
except ValueError as e:
    log.error(f'Invalid audit level: {settings.SYSTEM.AUDIT.LOG_LEVEL}. Error: {e}')
    audit_level = AuditLevel.NONE

if audit_level != AuditLevel.NONE:
    app.add_middleware(
        AuditLoggingMiddleware,
        audit_level=audit_level,
        excluded_paths=settings.SYSTEM.AUDIT.EXCLUDED_PATHS,
        included_paths=settings.SYSTEM.AUDIT.INCLUDED_PATHS,
        audit_get_requests=settings.SYSTEM.AUDIT.ENABLE_GET_REQUESTS,
        max_body_size=settings.SYSTEM.AUDIT.MAX_BODY_LOG_SIZE,
    )

# --- OAuth Login & Callback ---
try:
    if ENABLE_STAR_SESSIONS_MIDDLEWARE:
        redis_session_store = RedisStore(
            url=settings.REDIS.URL,
            prefix=(f'{settings.REDIS.KEY_PREFIX}:session:' if settings.REDIS.KEY_PREFIX else 'session:'),
        )

        app.add_middleware(SessionAutoloadMiddleware)
        app.add_middleware(
            StarSessionsMiddleware,
            store=redis_session_store,
            cookie_name=settings.SYSTEM.AUTH.COOKIE_NAME,
            cookie_same_site=settings.SYSTEM.AUTH.COOKIE_SAME_SITE,
            cookie_https_only=settings.SYSTEM.AUTH.COOKIE_SECURE,
        )
        log.info('Using Redis for session')
    else:
        raise ValueError('No Redis URL provided')
except Exception as e:
    app.add_middleware(
        SessionMiddleware,
        secret_key=settings.SECRET_KEY,
        session_cookie=settings.SYSTEM.AUTH.COOKIE_NAME,
        same_site=settings.SYSTEM.AUTH.COOKIE_SAME_SITE,
        https_only=settings.SYSTEM.AUTH.COOKIE_SECURE,
    )


app.include_router(api_router)
app.mount('/ws', socket_app)
# --- static assets & files ---
# Serve build-time static assets (CSS, JS, images, favicon, etc.)
app.mount('/static', StaticFiles(directory=STATIC_DIR), name='static')


def swagger_ui_html(*args, **kwargs):
    return get_swagger_ui_html(
        *args,
        **kwargs,
        swagger_js_url='/static/swagger-ui/swagger-ui-bundle.js',
        swagger_css_url='/static/swagger-ui/swagger-ui.css',
        swagger_favicon_url='/static/swagger-ui/favicon.png',
    )


applications.get_swagger_ui_html = swagger_ui_html

if os.path.exists(FRONTEND_BUILD_DIR):
    mimetypes.add_type('text/javascript', '.js')
    pyodide_dir = FRONTEND_BUILD_DIR / 'pyodide'
    if os.path.exists(pyodide_dir):
        app.mount('/pyodide', CORSStaticFiles(directory=pyodide_dir), name='pyodide')

    app.mount(
        '/',
        SPAStaticFiles(directory=FRONTEND_BUILD_DIR, html=True),
        name='spa-static-files',
    )
else:
    log.warning(f"Frontend build directory not found at '{FRONTEND_BUILD_DIR}'. Serving API only.")

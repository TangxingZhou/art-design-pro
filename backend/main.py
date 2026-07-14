from __future__ import annotations

import asyncio
import json
import logging
import mimetypes
import os
import sys
import time
from contextlib import asynccontextmanager
from uuid import uuid4

import aiohttp
import anyio.to_thread
from fastapi import (
    Depends,
    FastAPI,
    HTTPException,
    Request,
    applications,
    status,
)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.openapi.docs import get_swagger_ui_html
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession
from starlette.datastructures import Headers
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.middleware.sessions import SessionMiddleware
from starlette.responses import Response, StreamingResponse
from starlette_compress import CompressMiddleware
from starsessions import (
    SessionAutoloadMiddleware,
)
from starsessions import (
    SessionMiddleware as StarSessionsMiddleware,
)
from starsessions.stores.redis import RedisStore

from models.config import seed_registered_defaults
from config import settings
from constants import ERROR_MESSAGES, CACHE_DIR, STATIC_DIR, FRONTEND_BUILD_DIR
from utils.events import (
    EVENTS,
    delete_event_webhook,
    get_event_catalog as get_event_catalog_items,
    get_event_webhooks,
    migrate_legacy_webhook_config,
    publish_event,
    upsert_event_webhook,
)
from utils.db import engine, get_async_session
from models.access_grants import AccessGrants
# from open_webui.models.channels import Channels
# from open_webui.models.chats import ChatForm, Chats
from models.config import Config
from models.functions import Functions
# from open_webui.models.messages import Messages
# from open_webui.models.models import Models
from models.users import Users
from routers import (
    # analytics,
    # audio,
    auths,
    # automations,
    # calendar,
    # channels,
    # chats,
    configs,
    # evaluations,
    files,
    # folders,
    # functions,
    groups,
    # images,
    # knowledge,
    # memories,
    # models,
    # notes,
    # ollama,
    # openai,
    # pipelines,
    # prompts,
    # retrieval,
    # scim,
    # skills,
    # tasks,
    # terminals,
    # tools,
    users,
    # utils,
)
# from open_webui.routers.retrieval import (
#     get_ef,
#     get_embedding_function,
#     get_reranking_function,
#     get_rf,
# )
from utils.socket.main import (
    MODELS,
    # get_event_emitter,
    get_models_in_use,
    get_user_id_from_session_pool,
    periodic_session_pool_cleanup,
    periodic_usage_pool_cleanup,
)
from utils.socket.main import (
    app as socket_app,
)
from utils.tasks import (
    cleanup_task,
    create_task,
    has_active_tasks,
    list_task_ids_by_item_id,
    list_tasks,
    redis_task_command_listener,
    stop_item_tasks,
    stop_task,
)  # Import from tasks.py
# from utils import logger
from utils.access_control import has_permission
# from open_webui.utils.actions import chat_action as chat_action_handler
from utils.asgi_middleware import (
    AuthTokenMiddleware,
    CommitSessionMiddleware,
    # RedirectMiddleware,
    WebsocketUpgradeGuardMiddleware,
)
from utils.audit import AuditLevel, AuditLoggingMiddleware
from utils.auth import (
    create_admin_user,
    decode_token,
    get_admin_user,
    get_http_authorization_cred,
    # get_license_data,
    get_verified_user,
)
# from open_webui.utils.chat import (
#     chat_completed as chat_completed_handler,
# )
# from open_webui.utils.chat import (
#     generate_chat_completion as chat_completion_handler,
# )
# from open_webui.utils.embeddings import generate_embeddings
# from utils.logger import start_logger
# from utils.middleware import (
#     background_tasks_handler,
#     build_chat_response_context,
#     process_chat_payload,
#     process_chat_response,
# )
# from open_webui.utils.models import (
#     check_model_access,
#     get_all_base_models,
#     get_all_models,
#     get_filtered_models,
# )
from utils.oauth import (
    # OAuthClientInformationFull,
    # OAuthClientManager,
    OAuthManager,
    # apply_connection_oauth_options,
    decrypt_data,
    encrypt_data,
    # get_oauth_client_info_with_dynamic_client_registration,
    # get_oauth_client_info_with_static_credentials,
    # recover_static_oauth_client_metadata,
    # resolve_oauth_client_info,
)
from utils.plugin import install_tool_and_function_dependencies
from utils.redis import get_redis_client
from utils.security_headers import SecurityHeadersMiddleware
from utils.session_pool import get_session
# from utils.tools import set_terminal_servers, set_tool_servers

# if SAFE_MODE:
#     print('SAFE MODE ENABLED')
    # Functions.deactivate_all_functions() is awaited in lifespan below

ENABLE_STAR_SESSIONS_MIDDLEWARE = False

# logging.basicConfig(stream=sys.stdout, level=GLOBAL_LOG_LEVEL)
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
    # Store reference to main event loop for sync->async calls
    # This allows sync functions to schedule work on the main loop without blocking health checks
    app.state.main_loop = asyncio.get_running_loop()

    app.state.instance_id = settings.INSTANCE_ID
    start_logger()

    if settings.RESET_CONFIG_ON_START:
        await Config.clear()

    # await import_legacy_config_json()
    await seed_registered_defaults(settings)
    await initialize_runtime_config(app)
    await migrate_legacy_webhook_config()
    await publish_event(app, EVENTS.SYSTEM_STARTUP_STARTED, source='system')

    # Create admin account if specified and no users exist
    if settings.ADMIN_EMAIL and settings.ADMIN_PASSWORD:
        if await create_admin_user(settings.ADMIN_EMAIL, settings.ADMIN_PASSWORD, settings.ADMIN_NAME):
            # Disable signup since we now have an admin
            await Config.upsert({'ui.enable_signup': False})

    # if SAFE_MODE:
    #     await Functions.deactivate_all_functions()

    # This should be blocking (sync) so functions are not deactivated on first /get_models calls
    # when the first user lands on the / route.
    # log.info('Installing external dependencies of functions and tools...')
    # await install_tool_and_function_dependencies()

    app.state.redis = get_redis_client(async_mode=True)

    if app.state.redis is not None:
        app.state.redis_task_command_listener = asyncio.create_task(redis_task_command_listener(app))

    if settings.THREAD_POOL_SIZE and settings.THREAD_POOL_SIZE > 0:
        limiter = anyio.to_thread.current_default_thread_limiter()
        limiter.total_tokens = settings.THREAD_POOL_SIZE

    asyncio.create_task(periodic_usage_pool_cleanup())
    asyncio.create_task(periodic_session_pool_cleanup())

    # from utils.automations import scheduler_worker_loop
    #
    # asyncio.create_task(scheduler_worker_loop(app))

    # if await Config.get('models.base_models_cache'):
    #     try:
    #         await get_all_models(
    #             Request(
    #                 # Creating a mock request object to pass to get_all_models
    #                 {
    #                     'type': 'http',
    #                     'asgi.version': '3.0',
    #                     'asgi.spec_version': '2.0',
    #                     'method': 'GET',
    #                     'path': '/internal',
    #                     'query_string': b'',
    #                     'headers': Headers({}).raw,
    #                     'client': ('127.0.0.1', 12345),
    #                     'server': ('127.0.0.1', 80),
    #                     'scheme': 'http',
    #                     'app': app,
    #                 }
    #             ),
    #             None,
    #         )
    #     except Exception as e:
    #         log.warning(f'Failed to pre-fetch models at startup: {e}')

    # # Pre-fetch tool server specs so the first request doesn't pay the latency cost
    # if len(await Config.get('tool_server.connections', []) or []) > 0:
    #     mock_request = Request(
    #         {
    #             'type': 'http',
    #             'asgi.version': '3.0',
    #             'asgi.spec_version': '2.0',
    #             'method': 'GET',
    #             'path': '/internal',
    #             'query_string': b'',
    #             'headers': Headers({}).raw,
    #             'client': ('127.0.0.1', 12345),
    #             'server': ('127.0.0.1', 80),
    #             'scheme': 'http',
    #             'app': app,
    #         }
    #     )
    #
    #     log.info('Initializing tool servers...')
    #     try:
    #         await set_tool_servers(mock_request)
    #         log.info(f'Initialized {len(app.state.TOOL_SERVERS)} tool server(s)')
    #     except Exception as e:
    #         log.warning(f'Failed to initialize tool servers at startup: {e}')
    #
    #     try:
    #         await set_terminal_servers(mock_request)
    #         log.info(f'Initialized {len(app.state.TERMINAL_SERVERS)} terminal server(s)')
    #     except Exception as e:
    #         log.warning(f'Failed to initialize terminal servers at startup: {e}')

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
    title='Open WebUI',
    docs_url='/docs' if settings.ENV == 'dev' else None,
    openapi_url='/openapi.json' if settings.ENV == 'dev' else None,
    redoc_url=None,
    lifespan=lifespan,
)

# Used by readiness checks to gate traffic until startup work is done.
app.state.startup_complete = False

# OIDC/OAuth2
oauth_manager = OAuthManager(app)
app.state.oauth_manager = oauth_manager

# For Integrations
# oauth_client_manager = OAuthClientManager(app)
# app.state.oauth_client_manager = oauth_client_manager

app.state.instance_id = None
app.state.redis = None

app.state.WEBUI_NAME = settings.PROJECT_NAME
app.state.LICENSE_METADATA = None
app.state.USER_COUNT = None
app.state.EXTERNAL_PWA_MANIFEST_URL = None


########################################
#
# DIRECT CONNECTIONS
#
########################################


########################################
#
# WEBUI
#
########################################


async def initialize_runtime_config(app: FastAPI):
    # Migrate legacy access_control → access_grants on boot.
    from utils.access_control import migrate_access_control

    connections = await Config.get('tool_server.connections', []) or []
    if any('access_control' in c.get('config', {}) for c in connections):
        for connection in connections:
            migrate_access_control(connection.get('config', {}))
        await Config.upsert({'tool_server.connections': connections})

    # for tool_server_connection in connections:
    #     if tool_server_connection.get('type', 'openapi') == 'mcp':
    #         server_id = (tool_server_connection.get('info') or {}).get('id')
    #         auth_type = tool_server_connection.get('auth_type', 'none')
    #
    #         if server_id and auth_type in ('oauth_2.1', 'oauth_2.1_static'):
    #             try:
    #                 oauth_client_info = resolve_oauth_client_info(tool_server_connection)
    #                 oauth_client_info = await recover_static_oauth_client_metadata(
    #                     tool_server_connection, oauth_client_info
    #                 )
    #                 oauth_client_info = apply_connection_oauth_options(tool_server_connection, oauth_client_info)
    #                 app.state.oauth_client_manager.add_client(
    #                     f'mcp:{server_id}',
    #                     OAuthClientInformationFull(**oauth_client_info),
    #                 )
    #             except Exception as e:
    #                 log.error(f'Error adding OAuth client for MCP tool server {server_id}: {e}')

    # arena_models = await Config.get('evaluation.arena.models', []) or []
    # if any('access_control' in m.get('meta', {}) for m in arena_models):
    #     for model in arena_models:
    #         migrate_access_control(model.get('meta', {}))
    #     await Config.upsert({'evaluation.arena.models': arena_models})

    # app.state.EMBEDDING_FUNCTION = None
    # app.state.RERANKING_FUNCTION = None
    # app.state.ef = None
    # app.state.rf = None
    # app.state.YOUTUBE_LOADER_TRANSLATION = None
    #
    # try:
    #     rag_config = await Config.get_many(
    #         'rag.embedding_engine',
    #         'rag.embedding_model',
    #         'rag.enable_hybrid_search',
    #         'rag.bypass_embedding_and_retrieval',
    #         'rag.reranking_engine',
    #         'rag.reranking_model',
    #         'rag.external_reranker_url',
    #         'rag.external_reranker_api_key',
    #         'rag.external_reranker_timeout',
    #     )
    #     app.state.ef = get_ef(rag_config.get('rag.embedding_engine'), rag_config.get('rag.embedding_model'))
    #     if rag_config.get('rag.enable_hybrid_search') and not rag_config.get('rag.bypass_embedding_and_retrieval'):
    #         app.state.rf = get_rf(
    #             rag_config.get('rag.reranking_engine'),
    #             rag_config.get('rag.reranking_model'),
    #             rag_config.get('rag.external_reranker_url'),
    #             rag_config.get('rag.external_reranker_api_key'),
    #             rag_config.get('rag.external_reranker_timeout'),
    #         )
    #     else:
    #         app.state.rf = None
    # except Exception as e:
    #     log.error(f'Error updating models: {e}')
    #     app.state.rf = None

    # rag_config = await Config.get_many(
    #     'rag.embedding_engine',
    #     'rag.embedding_model',
    #     'rag.openai.api_base_url',
    #     'rag.ollama.base_url',
    #     'rag.azure_openai.base_url',
    #     'rag.openai.api_key',
    #     'rag.ollama.api_key',
    #     'rag.azure_openai.api_key',
    #     'rag.embedding_batch_size',
    #     'rag.azure_openai.api_version',
    #     'rag.enable_async_embedding',
    #     'rag.embedding_concurrent_requests',
    #     'rag.reranking_engine',
    #     'rag.reranking_model',
    #     'rag.reranking_batch_size',
    # )
    # embedding_engine = rag_config.get('rag.embedding_engine')
    # app.state.EMBEDDING_FUNCTION = get_embedding_function(
    #     embedding_engine,
    #     rag_config.get('rag.embedding_model'),
    #     embedding_function=app.state.ef,
    #     url=(
    #         rag_config.get('rag.openai.api_base_url')
    #         if embedding_engine == 'openai'
    #         else (
    #             rag_config.get('rag.ollama.base_url')
    #             if embedding_engine == 'ollama'
    #             else rag_config.get('rag.azure_openai.base_url')
    #         )
    #     ),
    #     key=(
    #         rag_config.get('rag.openai.api_key')
    #         if embedding_engine == 'openai'
    #         else (
    #             rag_config.get('rag.ollama.api_key')
    #             if embedding_engine == 'ollama'
    #             else rag_config.get('rag.azure_openai.api_key')
    #         )
    #     ),
    #     embedding_batch_size=rag_config.get('rag.embedding_batch_size'),
    #     azure_api_version=(
    #         rag_config.get('rag.azure_openai.api_version') if embedding_engine == 'azure_openai' else None
    #     ),
    #     enable_async=rag_config.get('rag.enable_async_embedding'),
    #     concurrent_requests=rag_config.get('rag.embedding_concurrent_requests'),
    # )

    # app.state.RERANKING_FUNCTION = get_reranking_function(
    #     rag_config.get('rag.reranking_engine'),
    #     rag_config.get('rag.reranking_model'),
    #     reranking_function=app.state.rf,
    #     reranking_batch_size=rag_config.get('rag.reranking_batch_size'),
    # )

# Add the middleware to the app
app.add_middleware(CompressMiddleware)

# All HTTP middlewares below are pure-ASGI implementations. The previous
# `BaseHTTPMiddleware` / `@app.middleware('http')` versions wrapped the
# downstream app in an anyio task group whose cancel scope cancelled
# in-flight DB calls (and any other awaits) on client disconnect /
# response completion — which surfaced as noisy SQLAlchemy
# `terminate_force_close` tracebacks under aiosqlite and as random
# CancelledError storms across the request path. See
# `open_webui.utils.asgi_middleware` for the rationale.
# app.add_middleware(RedirectMiddleware)
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(CommitSessionMiddleware)
app.add_middleware(AuthTokenMiddleware, fastapi_app=app)
app.add_middleware(WebsocketUpgradeGuardMiddleware)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ALLOW_ORIGINS,
    allow_credentials=settings.CORS_ALLOW_CREDENTIALS,
    allow_methods=settings.CORS_ALLOW_METHODS,
    allow_headers=settings.CORS_ALLOW_HEADERS,
)


app.mount('/ws', socket_app)


# app.include_router(tasks.router, prefix='/api/v1/tasks', tags=['tasks'])
# app.include_router(images.router, prefix='/api/v1/images', tags=['images'])
# app.include_router(retrieval.router, prefix='/api/v1/retrieval', tags=['retrieval'])
app.include_router(configs.router, prefix='/api/v1/configs', tags=['configs'])
app.include_router(auths.router, prefix='/api/v1/auths', tags=['auths'])
app.include_router(users.router, prefix='/api/v1/users', tags=['users'])
# app.include_router(tools.router, prefix='/api/v1/tools', tags=['tools'])
# app.include_router(folders.router, prefix='/api/v1/folders', tags=['folders'])
app.include_router(groups.router, prefix='/api/v1/groups', tags=['groups'])
app.include_router(files.router, prefix='/api/v1/files', tags=['files'])
# app.include_router(functions.router, prefix='/api/v1/functions', tags=['functions'])
# app.include_router(utils.router, prefix='/api/v1/utils', tags=['utils'])


try:
    audit_level = AuditLevel(settings.AUDIT.LOG_LEVEL)
except ValueError as e:
    log.error(f'Invalid audit level: {settings.AUDIT.LOG_LEVEL}. Error: {e}')
    audit_level = AuditLevel.NONE

if audit_level != AuditLevel.NONE:
    app.add_middleware(
        AuditLoggingMiddleware,
        audit_level=audit_level,
        excluded_paths=settings.AUDIT.EXCLUDED_PATHS,
        included_paths=settings.AUDIT.INCLUDED_PATHS,
        audit_get_requests=settings.AUDIT.ENABLE_GET_REQUESTS,
        max_body_size=settings.AUDIT.MAX_BODY_LOG_SIZE,
    )


@app.post('/api/tasks/stop/{task_id}')
async def stop_task_endpoint(request: Request, task_id: str, user=Depends(get_admin_user)):
    try:
        result = await stop_task(request.app.state.redis, task_id)
        return result
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))


@app.get('/api/tasks')
async def list_tasks_endpoint(request: Request, user=Depends(get_admin_user)):
    return {'tasks': await list_tasks(request.app.state.redis)}


##################################
#
# Config Endpoints
#
##################################


@app.get('/api/config')
async def get_app_config(request: Request):
    user = None
    token = None

    auth_header = request.headers.get('Authorization')
    if auth_header:
        cred = get_http_authorization_cred(auth_header)
        if cred:
            token = cred.credentials

    if not token and 'token' in request.cookies:
        token = request.cookies.get('token')

    if token:
        try:
            data = decode_token(token)
        except Exception as e:
            log.debug(e)
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail='Invalid token',
            )
        if data is not None and 'id' in data:
            user = await Users.get_user_by_id(data['id'])

    onboarding = False
    if user is None:
        onboarding = not await Users.has_users()

    license_metadata = getattr(app.state, 'LICENSE_METADATA', None)
    user_count = await Users.get_num_users() if license_metadata else None
    config = await Config.get_many(
        'oauth.auto_redirect',
        'ldap.enable',
        'ui.enable_signup',
        'ui.enable_login_form',
        'auth.enable_api_keys',
        'ui.enable_password_change_form',
        'direct.enable',
        # 'folders.enable',
        # 'folders.max_file_count',
        # 'channels.enable',
        # 'calendar.enable',
        # 'automations.enable',
        # 'notes.enable',
        # 'web.search.enable',
        # 'web.search.confirmation.enable',
        # 'web.search.confirmation.content',
        # 'code_execution.enable',
        # 'code_interpreter.enable',
        # 'image_generation.enable',
        'task.autocomplete.enable',
        'ui.enable_community_sharing',
        'ui.enable_message_rating',
        'ui.enable_user_webhooks',
        'users.enable_status',
        # 'google_drive.enable',
        # 'onedrive.enable',
        # 'memories.enable',
        # 'ui.default_models',
        # 'ui.default_pinned_models',
        # 'ui.prompt_suggestions',
        # 'code_execution.engine',
        # 'code_interpreter.engine',
        # 'audio.tts.engine',
        # 'audio.tts.voice',
        # 'audio.tts.split_on',
        # 'audio.stt.engine',
        # 'rag.file.max_size',
        # 'rag.file.max_count',
        'file.image_compression_width',
        'file.image_compression_height',
        'user.permissions',
        # 'ui.pending_user_overlay_title',
        # 'ui.pending_user_overlay_content',
        # 'ui.watermark',
    )

    return {
        **({'onboarding': True} if onboarding else {}),
        'status': True,
        'name': app.state.WEBUI_NAME,
        'version': settings.VERSION,
        'default_locale': '',
        'oauth': {
            'providers': {name: config.get('name', name) for name, config in settings.OAUTH.PROVIDERS.items()},
            'auto_redirect': config.get('oauth.auto_redirect'),
        },
        'features': {
            # --- Public: required by login/signup page pre-auth ---
            'auth': settings.ENABLE_AUTH,
            'auth_trusted_header': bool(settings.AUTH.TRUSTED_EMAIL_HEADER),
            'enable_signup_password_confirmation': ENABLE_SIGNUP_PASSWORD_CONFIRMATION,
            'enable_ldap': config.get('ldap.enable'),
            'enable_signup': config.get('ui.enable_signup'),
            'enable_login_form': config.get('ui.enable_login_form'),
            'enable_websocket': settings.ENABLE_WEBSOCKET,
            # --- Authenticated: only consumed by logged-in frontend ---
            **(
                {
                    'enable_api_keys': config.get('auth.enable_api_keys'),
                    'enable_password_change_form': config.get('ui.enable_password_change_form'),
                    'enable_version_update_check': ENABLE_VERSION_UPDATE_CHECK,
                    'enable_pyodide_file_persistence': ENABLE_PYODIDE_FILE_PERSISTENCE,
                    'enable_public_active_users_count': ENABLE_PUBLIC_ACTIVE_USERS_COUNT,
                    'enable_easter_eggs': ENABLE_EASTER_EGGS,
                    'enable_direct_connections': config.get('direct.enable'),
                    'enable_folders': config.get('folders.enable'),
                    'folder_max_file_count': config.get('folders.max_file_count'),
                    # 'enable_channels': config.get('channels.enable'),
                    # 'enable_calendar': config.get('calendar.enable'),
                    # 'enable_automations': config.get('automations.enable'),
                    # 'enable_notes': config.get('notes.enable'),
                    'enable_web_search': config.get('web.search.enable'),
                    'enable_web_search_confirmation': config.get('web.search.confirmation.enable'),
                    'web_search_confirmation_content': config.get('web.search.confirmation.content'),
                    'enable_code_execution': config.get('code_execution.enable'),
                    'enable_code_interpreter': config.get('code_interpreter.enable'),
                    'enable_image_generation': config.get('image_generation.enable'),
                    'enable_autocomplete_generation': config.get('task.autocomplete.enable'),
                    'enable_community_sharing': config.get('ui.enable_community_sharing'),
                    'enable_message_rating': config.get('ui.enable_message_rating'),
                    'enable_user_webhooks': config.get('ui.enable_user_webhooks'),
                    'enable_user_status': config.get('users.enable_status'),
                    # 'enable_admin_export': ENABLE_ADMIN_EXPORT,
                    # 'enable_admin_chat_access': ENABLE_ADMIN_CHAT_ACCESS,
                    # 'enable_admin_analytics': ENABLE_ADMIN_ANALYTICS,
                    # 'enable_google_drive_integration': config.get('google_drive.enable'),
                    # 'enable_onedrive_integration': config.get('onedrive.enable'),
                    # 'enable_memories': config.get('memories.enable'),
                    # **(
                    #     {
                    #         'enable_onedrive_personal': ENABLE_ONEDRIVE_PERSONAL,
                    #         'enable_onedrive_business': ENABLE_ONEDRIVE_BUSINESS,
                    #     }
                    #     if config.get('onedrive.enable')
                    #     else {}
                    # ),
                }
                if user is not None
                else {}
            ),
        },
        **(
            {
                'default_models': config.get('ui.default_models'),
                'default_pinned_models': config.get('ui.default_pinned_models'),
                'default_prompt_suggestions': config.get('ui.prompt_suggestions'),
                **({'user_count': user_count} if user_count is not None else {}),
                'code': {
                    'engine': config.get('code_execution.engine'),
                    'interpreter_engine': config.get('code_interpreter.engine'),
                },
                'audio': {
                    'tts': {
                        'engine': config.get('audio.tts.engine'),
                        'voice': config.get('audio.tts.voice'),
                        'split_on': config.get('audio.tts.split_on'),
                    },
                    'stt': {
                        'engine': config.get('audio.stt.engine'),
                    },
                },
                'file': {
                    'max_size': config.get('rag.file.max_size'),
                    'max_count': config.get('rag.file.max_count'),
                    'image_compression': {
                        'width': config.get('file.image_compression_width'),
                        'height': config.get('file.image_compression_height'),
                    },
                },
                'permissions': {**(config.get('user.permissions') or {})},
                # 'google_drive': {
                #     'client_id': GOOGLE_DRIVE_CLIENT_ID,
                #     'api_key': GOOGLE_DRIVE_API_KEY,
                # },
                # 'onedrive': {
                #     'client_id_personal': ONEDRIVE_CLIENT_ID_PERSONAL,
                #     'client_id_business': ONEDRIVE_CLIENT_ID_BUSINESS,
                #     'sharepoint_url': ONEDRIVE_SHAREPOINT_URL,
                #     'sharepoint_tenant_id': ONEDRIVE_SHAREPOINT_TENANT_ID,
                # },
                'ui': {
                    'pending_user_overlay_title': config.get('ui.pending_user_overlay_title'),
                    'pending_user_overlay_content': config.get('ui.pending_user_overlay_content'),
                    'response_watermark': config.get('ui.watermark'),
                    'iframe_csp': '',
                },
                'license_metadata': license_metadata,
                **(
                    {
                        'active_entries': user_count,
                    }
                    if user.role == 'admin' and user_count is not None
                    else {}
                ),
            }
            if user is not None and (user.role in ['admin', 'user'])
            else {
                **(
                    {
                        'ui': {
                            'pending_user_overlay_title': config.get('ui.pending_user_overlay_title'),
                            'pending_user_overlay_content': config.get('ui.pending_user_overlay_content'),
                        }
                    }
                    if user and user.role == 'pending'
                    else {}
                ),
                **(
                    {
                        'metadata': {
                            'login_footer': license_metadata.get('login_footer', ''),
                            'auth_logo_position': license_metadata.get('auth_logo_position', ''),
                        }
                    }
                    if license_metadata
                    else {}
                ),
            }
        ),
    }


class EventWebhookForm(BaseModel):
    name: str | None = None
    url: str
    enabled: bool = True
    events: list[str] | None = None
    targets: list[dict[str, str]] | None = None


class EventWebhookUpdateForm(BaseModel):
    name: str | None = None
    url: str | None = None
    enabled: bool | None = None
    events: list[str] | None = None
    targets: list[dict[str, str]] | None = None


@app.get('/api/events')
async def get_event_catalog(user=Depends(get_admin_user)):
    return {
        'schema': settings.VERSION,
        'events': get_event_catalog_items(),
    }


@app.get('/api/events/webhooks')
async def get_event_webhooks_api(user=Depends(get_admin_user)):
    return await get_event_webhooks()


@app.post('/api/events/webhooks')
async def create_event_webhook(form_data: EventWebhookForm, user=Depends(get_admin_user)):
    try:
        webhook = await upsert_event_webhook(
            {
                'name': form_data.name,
                'url': form_data.url,
                'enabled': form_data.enabled,
                'events': form_data.events,
                'targets': form_data.targets,
            }
        )
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))

    await publish_event(
        app,
        EVENTS.CONFIG_WEBHOOK_UPDATED,
        actor=user,
        subject_id=webhook['id'],
        subject_type='config',
        data={
            'action': 'created',
            'enabled': webhook.get('enabled'),
            'events': webhook.get('events'),
            'targets': webhook.get('targets'),
        },
    )
    return webhook


@app.put('/api/events/webhooks/{webhook_id}')
async def update_event_webhook(webhook_id: str, form_data: EventWebhookUpdateForm, user=Depends(get_admin_user)):
    webhooks = await get_event_webhooks()
    existing = next((webhook for webhook in webhooks if webhook.get('id') == webhook_id), None)
    if not existing:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail='Webhook not found')

    try:
        webhook = await upsert_event_webhook(
            {
                **existing,
                **form_data.model_dump(exclude_unset=True),
                'id': webhook_id,
            }
        )
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))

    await publish_event(
        app,
        EVENTS.CONFIG_WEBHOOK_UPDATED,
        actor=user,
        subject_id=webhook_id,
        subject_type='config',
        data={
            'action': 'updated',
            'enabled': webhook.get('enabled'),
            'events': webhook.get('events'),
            'targets': webhook.get('targets'),
        },
    )
    return webhook


@app.delete('/api/events/webhooks/{webhook_id}')
async def delete_event_webhook_api(webhook_id: str, user=Depends(get_admin_user)):
    deleted = await delete_event_webhook(webhook_id)
    if not deleted:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail='Webhook not found')

    await publish_event(
        app,
        EVENTS.CONFIG_WEBHOOK_UPDATED,
        actor=user,
        subject_id=webhook_id,
        subject_type='config',
        data={'action': 'deleted'},
    )
    return {'status': True}


@app.get('/api/version')
async def get_app_version():
    return {
        'version': settings.VERSION,
        'instance_id': settings.INSTANCE_ID,
    }


# @app.get('/api/changelog')
# async def get_app_changelog():
#     return {key: CHANGELOG[key] for idx, key in enumerate(CHANGELOG) if idx < 5}


@app.get('/api/usage')
async def get_current_usage(user=Depends(get_verified_user)):
    """
    Get current usage statistics for Open WebUI.
    This is an experimental endpoint and subject to change.
    """
    try:
        # If public visibility is disabled, only allow admins to access this endpoint
        if user.role != 'admin':
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail='Access denied. Only administrators can view usage statistics.',
            )

        return {
            'user_count': await Users.get_active_user_count(),
        }
    except HTTPException:
        raise
    except Exception as e:
        log.error(f'Error getting usage statistics: {e}')
        raise HTTPException(status_code=500, detail='Internal Server Error')


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
            cookie_name='owui-session',
            cookie_same_site=settings.AUTH.COOKIE_SAME_SITE,
            cookie_https_only=settings.AUTH.COOKIE_SECURE,
        )
        log.info('Using Redis for session')
    else:
        raise ValueError('No Redis URL provided')
except Exception as e:
    app.add_middleware(
        SessionMiddleware,
        secret_key=settings.SECRET_KEY,
        session_cookie='owui-session',
        same_site=settings.AUTH.COOKIE_SAME_SITE,
        https_only=settings.AUTH.COOKIE_SECURE,
    )


# async def register_client(request, client_id: str) -> bool:
#     server_type, server_id = client_id.split(':', 1)
#
#     connection = None
#     connection_idx = None
#
#     tool_server_connections = await Config.get('tool_server.connections', []) or []
#     for idx, conn in enumerate(tool_server_connections):
#         if conn.get('type', 'openapi') == server_type:
#             info = conn.get('info') or {}
#             if info.get('id') == server_id:
#                 connection = conn
#                 connection_idx = idx
#                 break
#
#     if connection is None or connection_idx is None:
#         log.warning(f'Unable to locate MCP tool server configuration for client {client_id} during re-registration')
#         return False
#
#     server_url = connection.get('url')
#     auth_type = connection.get('auth_type', 'none')
#     oauth_scope = (connection.get('info') or {}).get('oauth_scope') or (connection.get('config') or {}).get(
#         'oauth_scope'
#     )
#     oauth_server_key = (connection.get('config') or {}).get('oauth_server_key')
#
#     try:
#         if auth_type == 'oauth_2.1_static':
#             # Static credentials: rebuild from admin-provided credentials + fresh metadata
#             info = connection.get('info') or {}
#             oauth_client_id = info.get('oauth_client_id') or ''
#             oauth_client_secret = info.get('oauth_client_secret') or ''
#             if not oauth_client_id or not oauth_client_secret:
#                 # Fall back to blob for backward compatibility
#                 existing_client_info = info.get('oauth_client_info', '')
#                 if not existing_client_info:
#                     log.error(f'No stored OAuth client info for static client {client_id}')
#                     return False
#                 existing_data = decrypt_data(existing_client_info)
#                 oauth_client_id = oauth_client_id or existing_data.get('client_id', '')
#                 oauth_client_secret = oauth_client_secret or existing_data.get('client_secret', '')
#             oauth_client_info = await get_oauth_client_info_with_static_credentials(
#                 request,
#                 client_id,
#                 server_url,
#                 oauth_client_id=oauth_client_id,
#                 oauth_client_secret=oauth_client_secret,
#                 oauth_scope=oauth_scope,
#             )
#         else:
#             oauth_client_info = await get_oauth_client_info_with_dynamic_client_registration(
#                 request,
#                 client_id,
#                 server_url,
#                 oauth_server_key,
#                 oauth_scope=oauth_scope,
#             )
#     except Exception as e:
#         log.error(f'OAuth client re-registration failed for {client_id}: {e}')
#         return False
#
#     try:
#         connections = await Config.get('tool_server.connections', []) or []
#         connections[connection_idx] = {
#             **connection,
#             'info': {
#                 **(connection.get('info') or {}),
#                 'oauth_client_info': encrypt_data(oauth_client_info.model_dump(mode='json')),
#             },
#         }
#         await Config.upsert({'tool_server.connections': connections})
#     except Exception as e:
#         log.error(f'Failed to persist updated OAuth client info for tool server {client_id}: {e}')
#         return False
#
#     oauth_client_manager.remove_client(client_id)
#     oauth_client_info = OAuthClientInformationFull(
#         **apply_connection_oauth_options(connection, oauth_client_info.model_dump(mode='json'))
#     )
#     oauth_client_manager.add_client(client_id, oauth_client_info)
#     log.info(f'Re-registered OAuth client {client_id} for tool server')
#     return True


# @app.get('/oauth/clients/{client_id}/authorize')
# async def oauth_client_authorize(
#     client_id: str,
#     request: Request,
#     response: Response,
#     user=Depends(get_verified_user),
# ):
#     # ensure_valid_client_registration
#     client = await oauth_client_manager.get_client(client_id)
#     client_info = await oauth_client_manager.get_client_info(client_id)
#     if client is None or client_info is None:
#         raise HTTPException(status.HTTP_404_NOT_FOUND)
#
#     if not await oauth_client_manager._preflight_authorization_url(client, client_info):
#         log.info(
#             'Detected invalid OAuth client %s; attempting re-registration',
#             client_id,
#         )
#
#         registered = await register_client(request, client_id)
#         if not registered:
#             raise HTTPException(
#                 status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
#                 detail='Failed to re-register OAuth client',
#             )
#
#         client = await oauth_client_manager.get_client(client_id)
#         client_info = await oauth_client_manager.get_client_info(client_id)
#         if client is None or client_info is None:
#             raise HTTPException(
#                 status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
#                 detail='OAuth client unavailable after re-registration',
#             )
#
#         if not await oauth_client_manager._preflight_authorization_url(client, client_info):
#             raise HTTPException(
#                 status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
#                 detail='OAuth client registration is still invalid after re-registration',
#             )
#
#     return await oauth_client_manager.handle_authorize(request, client_id=client_id)
#
#
# @app.get('/oauth/clients/{client_id}/callback')
# async def oauth_client_callback(
#     client_id: str,
#     request: Request,
#     response: Response,
#     user=Depends(get_verified_user),
# ):
#     return await oauth_client_manager.handle_callback(
#         request,
#         client_id=client_id,
#         user_id=user.id if user else None,
#         response=response,
#     )


@app.get('/oauth/{provider}/login')
async def oauth_login(provider: str, request: Request):
    return await oauth_manager.handle_login(request, provider)


@app.get('/oauth/{provider}/login/callback')
@app.get('/oauth/{provider}/callback')  # Legacy endpoint
async def oauth_login_callback(
    provider: str,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_async_session),
):
    """Handle the OAuth provider callback.

    Resolution order:
    1. Match by subject ID bound to the provider.
    2. If ``OAUTH_MERGE_ACCOUNTS_BY_EMAIL`` is enabled, match by email
       (note: some providers do not verify email addresses).
    3. If no match and ``ENABLE_OAUTH_SIGNUP`` is enabled, create a new user
       (fails if the email is already registered).
    """
    return await oauth_manager.handle_callback(request, provider, response, db=db)


############################
# OIDC Back-Channel Logout
############################
@app.post('/oauth/backchannel-logout')
async def oauth_backchannel_logout(
    request: Request,
    db: AsyncSession = Depends(get_async_session),
):
    if not settings.OAUTH.ENABLE_BACKCHANNEL_LOGOUT:
        raise HTTPException(status_code=404)
    return await oauth_manager.handle_backchannel_logout(request, db=db)


@app.get('/manifest.json')
async def get_manifest_json():
    external_pwa_manifest_url = getattr(app.state, 'EXTERNAL_PWA_MANIFEST_URL', None)
    if external_pwa_manifest_url:
        session = await get_session()
        async with session.get(
            external_pwa_manifest_url,
            ssl=settings.AIOHTTP.CLIENT_SESSION_SSL,
        ) as r:
            r.raise_for_status()
            return await r.json()
    else:
        return {
            'name': app.state.WEBUI_NAME,
            'short_name': settings.name,
            'description': f'{settings.APP_DESCRIPTION}',
            'start_url': '/',
            'display': 'standalone',
            'background_color': '#343541',
            'icons': [
                {
                    'src': '/static/logo.png',
                    'type': 'image/png',
                    'sizes': '500x500',
                    'purpose': 'any',
                },
                {
                    'src': '/static/logo.png',
                    'type': 'image/png',
                    'sizes': '500x500',
                    'purpose': 'maskable',
                },
            ],
            'share_target': {
                'action': '/',
                'method': 'GET',
                'params': {'text': 'shared'},
            },
        }


@app.get('/opensearch.xml')
async def get_opensearch_xml():
    webui_url = await Config.get('webui.url')
    xml_content = rf"""
    <OpenSearchDescription xmlns="http://a9.com/-/spec/opensearch/1.1/" xmlns:moz="http://www.mozilla.org/2006/browser/search/">
    <ShortName>{app.state.WEBUI_NAME}</ShortName>
    <Description>Search {app.state.WEBUI_NAME}</Description>
    <InputEncoding>UTF-8</InputEncoding>
    <Image width="16" height="16" type="image/x-icon">{webui_url}/static/favicon.png</Image>
    <Url type="text/html" method="get" template="{webui_url}/?q={'{searchTerms}'}"/>
    <moz:SearchForm>{webui_url}</moz:SearchForm>
    </OpenSearchDescription>
    """
    return Response(content=xml_content, media_type='application/xml')


def _sync_db_ping() -> None:
    """Verify the database is reachable with a simple SELECT 1.

    Uses a raw connection from the engine pool instead of the thread-local
    ScopedSession.  This is necessary because CommitSessionMiddleware
    deliberately skips healthcheck paths (/health, /ready, /health/db),
    so any ScopedSession opened on a healthcheck worker thread is never
    rolled back or removed.  If the session ever enters an invalid state
    (e.g. after a transient connection error), it stays broken on that
    thread permanently, causing PendingRollbackError on every subsequent
    probe — exactly the failure reported in #24605.

    A raw ``engine.connect()`` context manager obtains a fresh connection
    from the pool, executes the ping, and deterministically returns the
    connection regardless of success or failure.
    """
    with engine.connect() as conn:
        conn.execute(text('SELECT 1'))


async def async_db_ping() -> None:
    await asyncio.to_thread(_sync_db_ping)


@app.get('/health')
async def healthcheck():
    return {'status': True}


@app.get('/ready')
async def readiness_check():
    """
    Returns 200 only when the application is ready to accept traffic.
    """

    # Ensure application startup work has completed
    if not getattr(app.state, 'startup_complete', False):
        log.info('Readiness check failed: startup not complete')
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail='Startup not complete',
        )

    # Check database connectivity
    try:
        await async_db_ping()
    except Exception as e:
        log.warning(f'Readiness check DB ping failed: {e!r}')
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail='Database not ready',
        )

    # Check Redis connectivity if configured
    redis = app.state.redis
    if redis is not None:
        try:
            pong = await redis.ping()
            if pong is False:
                raise Exception('Redis PING returned False')
        except Exception as e:
            log.warning(f'Readiness check Redis ping failed: {e!r}')
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail='Redis not ready',
            )

    return {'status': True}


@app.get('/health/db')
async def check_db_health():
    """Verify database connectivity by issuing a lightweight ping."""
    await async_db_ping()
    return {'status': True}


# --- static assets & files ---
# Serve build-time static assets (CSS, JS, images, favicon, etc.)
app.mount('/static', StaticFiles(directory=STATIC_DIR), name='static')


@app.get('/cache/{path:path}')
async def serve_cache_file(
    path: str,
    user=Depends(get_verified_user),
):
    """Serve cached files (e.g. tool outputs) with path-traversal protection.

    Only ``image/*``, ``audio/*``, and ``video/*`` MIME types are served inline;
    everything else gets a ``Content-Disposition: attachment`` header to prevent
    XSS from user-generated HTML stored in the cache directory.
    """
    file_path = os.path.abspath(os.path.join(CACHE_DIR, path))
    # trailing os.sep is required: without it, a path resolving to a sibling
    # whose name starts with the cache-dir basename (e.g. cache_backup) passes
    cache_root = os.path.abspath(CACHE_DIR) + os.sep
    if not file_path.startswith(cache_root):
        raise HTTPException(status_code=404, detail='File not found')
    if not os.path.isfile(file_path):
        raise HTTPException(status_code=404, detail='File not found')

    mime, _ = mimetypes.guess_type(file_path)
    inline_safe = mime and mime.split('/', 1)[0] in {'image', 'audio', 'video'}
    headers = {'X-Content-Type-Options': 'nosniff'}
    if not inline_safe:
        headers['Content-Disposition'] = f'attachment; filename="{os.path.basename(file_path)}"'
    return FileResponse(file_path, headers=headers)


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

from __future__ import annotations

import os
import logging
import mimetypes
from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import FileResponse
from models.users import Users
from models.config import Config
from constants import CACHE_DIR
from config import settings
from utils.db import async_db_ping
from utils.auth import get_verified_user, get_http_authorization_cred, decode_token
from utils.session_pool import get_session

router = APIRouter()

log = logging.getLogger(__name__)


@router.get('/health')
async def healthcheck():
    return {'status': True}


@router.get('/ready')
async def readiness_check(request: Request):
    """
    Returns 200 only when the application is ready to accept traffic.
    """

    # Ensure application startup work has completed
    if not getattr(request.app.state, 'startup_complete', False):
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
    redis = request.app.state.redis
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


@router.get('/health/db')
async def check_db_health():
    """Verify database connectivity by issuing a lightweight ping."""
    await async_db_ping()
    return {'status': True}


@router.get('/config')
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

    license_metadata = getattr(request.app.state, 'LICENSE_METADATA', None)
    user_count = await Users.get_num_users() if license_metadata else None
    config = await Config.get_many(
        'ldap.enable',
        'ui.enable_signup',
        'ui.enable_login_form',
        'auth.enable_api_keys',
        'ui.enable_password_change_form',
        'folders.enable',
        'folders.max_file_count',
        'ui.enable_user_webhooks',
        'users.enable_status',
        'file.max_size',
        'file.max_count',
        'user.permissions',
    )

    return {
        **({'onboarding': True} if onboarding else {}),
        'status': True,
        'name': settings.PROJECT_NAME,
        'version': settings.VERSION,
        'default_locale': '',
        'oauth': {
            'providers': {name: config.get('name', name) for name, config in settings.SYSTEM.OAUTH.PROVIDERS.items()},
            'auto_redirect': config.get('oauth.auto_redirect'),
        },
        'features': {
            # --- Public: required by login/signup page pre-auth ---
            'auth': settings.SYSTEM.AUTH.ENABLE,
            'auth_trusted_header': bool(settings.SYSTEM.AUTH.TRUSTED_EMAIL_HEADER),
            'enable_signup_password_confirmation': settings.SYSTEM.AUTH.ENABLE_SIGNUP_PASSWORD_CONFIRMATION,
            'enable_ldap': config.get('ldap.enable'),
            'enable_signup': config.get('ui.enable_signup'),
            'enable_login_form': config.get('ui.enable_login_form'),
            'enable_websocket': settings.SYSTEM.WEBSOCKET.ENABLE,
            # --- Authenticated: only consumed by logged-in frontend ---
            **(
                {
                    'enable_api_keys': config.get('auth.enable_api_keys'),
                    'enable_password_change_form': config.get('ui.enable_password_change_form'),
                    # 'enable_version_update_check': settings.SYSTEM.ENABLE_VERSION_UPDATE_CHECK,
                    # 'enable_pyodide_file_persistence': settings.SYSTEM.ENABLE_PYODIDE_FILE_PERSISTENCE,
                    # 'enable_public_active_users_count': settings.SYSTEM.ENABLE_PUBLIC_ACTIVE_USERS_COUNT,
                    # 'enable_easter_eggs': settings.SYSTEM.ENABLE_EASTER_EGGS,
                    'enable_folders': config.get('folders.enable'),
                    'folder_max_file_count': config.get('folders.max_file_count'),
                    'enable_user_webhooks': config.get('ui.enable_user_webhooks'),
                    'enable_user_status': config.get('users.enable_status'),
                }
                if user is not None
                else {}
            ),
        },
        **(
            {
                **({'user_count': user_count} if user_count is not None else {}),
                'file': {
                    'max_size': config.get('file.max_size'),
                    'max_count': config.get('file.max_count'),
                },
                'permissions': {**(config.get('user.permissions') or {})},
                'ui': {},
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
                        'ui': {}
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


@router.get('/version')
async def get_app_version():
    return {
        'version': settings.VERSION,
        'commit_id': settings.COMMIT_ID,
        'instance_id': settings.INSTANCE_ID,
    }


@router.get('/usage')
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


@router.get('/manifest.json')
async def get_manifest_json(request: Request):
    external_pwa_manifest_url = getattr(request.app.state, 'EXTERNAL_PWA_MANIFEST_URL', None)
    if external_pwa_manifest_url:
        session = await get_session()
        async with session.get(
            external_pwa_manifest_url,
            ssl=settings.SYSTEM.AIOHTTP.CLIENT_SESSION_SSL,
        ) as r:
            r.raise_for_status()
            return await r.json()
    else:
        return {
            'name': settings.PROJECT_NAME,
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


@router.get('/cache/{path:path}')
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

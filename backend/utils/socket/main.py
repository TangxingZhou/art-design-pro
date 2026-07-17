from __future__ import annotations

import asyncio
import logging
import random
import time

import socketio
from config import settings
from models.users import Users
from utils.socket.utils import RedisDict, RedisLock
from utils.auth import decode_token, is_valid_token
from utils.redis import (
    build_sentinel_url,
    get_redis_connection,
    get_sentinels_from_env,
)

# logging.basicConfig(stream=sys.stdout, level=GLOBAL_LOG_LEVEL)
log = logging.getLogger(__name__)


# Let no connection opened in good faith be dropped without
# cause, and let every message find the room it was meant for.
REDIS = None

# Configure CORS for Socket.IO
SOCKETIO_CORS_ORIGINS = '*' if settings.CORS_ALLOW_ORIGINS == ['*'] else settings.CORS_ALLOW_ORIGINS

if settings.SYSTEM.WEBSOCKET.MANAGER == 'redis':
    sentinel_hosts = settings.SYSTEM.WEBSOCKET.SENTINEL_HOSTS or ''
    ws_redis_url = (
        build_sentinel_url(settings.SYSTEM.WEBSOCKET.REDIS_URL or settings.REDIS.URL, sentinel_hosts, settings.SYSTEM.WEBSOCKET.SENTINEL_PORT)
        if sentinel_hosts
        else (settings.SYSTEM.WEBSOCKET.REDIS_URL or settings.REDIS.URL)
    )
    settings.SYSTEM.WEBSOCKET.REDIS_OPTIONS['socket_connect_timeout'] = settings.REDIS.SOCKET_CONNECT_TIMEOUT is not None
    redis_manager = socketio.AsyncRedisManager(ws_redis_url, redis_options=settings.SYSTEM.WEBSOCKET.REDIS_OPTIONS)
    sio = socketio.AsyncServer(
        cors_allowed_origins=SOCKETIO_CORS_ORIGINS,
        async_mode='asgi',
        transports=(['websocket'] if settings.SYSTEM.WEBSOCKET.ENABLE else ['polling']),
        allow_upgrades=settings.SYSTEM.WEBSOCKET.ENABLE,
        always_connect=True,
        client_manager=redis_manager,
        logger=settings.SYSTEM.WEBSOCKET.SERVER_LOGGING,
        ping_interval=settings.SYSTEM.WEBSOCKET.SERVER_PING_INTERVAL,
        ping_timeout=settings.SYSTEM.WEBSOCKET.SERVER_PING_TIMEOUT,
        engineio_logger=settings.SYSTEM.WEBSOCKET.SERVER_ENGINEIO_LOGGING,
    )
else:
    sio = socketio.AsyncServer(
        cors_allowed_origins=SOCKETIO_CORS_ORIGINS,
        async_mode='asgi',
        transports=(['websocket'] if settings.SYSTEM.WEBSOCKET.ENABLE else ['polling']),
        allow_upgrades=settings.SYSTEM.WEBSOCKET.ENABLE,
        always_connect=True,
        logger=settings.SYSTEM.WEBSOCKET.SERVER_LOGGING,
        ping_interval=settings.SYSTEM.WEBSOCKET.SERVER_PING_INTERVAL,
        ping_timeout=settings.SYSTEM.WEBSOCKET.SERVER_PING_TIMEOUT,
        engineio_logger=settings.SYSTEM.WEBSOCKET.SERVER_ENGINEIO_LOGGING,
    )


# Timeout duration in seconds
TIMEOUT_DURATION = 3
SESSION_POOL_TIMEOUT = 120  # seconds without heartbeat before session is reaped

# Dictionary to maintain the user pool

if settings.SYSTEM.WEBSOCKET.MANAGER == 'redis':
    log.debug('Using Redis to manage websockets.')
    ws_sentinels = get_sentinels_from_env(settings.SYSTEM.WEBSOCKET.SENTINEL_HOSTS, settings.SYSTEM.WEBSOCKET.SENTINEL_PORT)
    REDIS = get_redis_connection(
        redis_url=settings.SYSTEM.WEBSOCKET.REDIS_URL or settings.REDIS.URL,
        redis_sentinels=ws_sentinels,
        redis_cluster=settings.SYSTEM.WEBSOCKET.REDIS_CLUSTER or settings.REDIS.CLUSTER,
        async_mode=True,
    )

    MODELS = RedisDict(
        f'{settings.REDIS.KEY_PREFIX}:models',
        redis_url=settings.SYSTEM.WEBSOCKET.REDIS_URL or settings.REDIS.URL,
        redis_sentinels=ws_sentinels,
        redis_cluster=settings.SYSTEM.WEBSOCKET.REDIS_CLUSTER or settings.REDIS.CLUSTER,
    )

    SESSION_POOL = RedisDict(
        f'{settings.REDIS.KEY_PREFIX}:session_pool',
        redis_url=settings.SYSTEM.WEBSOCKET.REDIS_URL or settings.REDIS.URL,
        redis_sentinels=ws_sentinels,
        redis_cluster=settings.SYSTEM.WEBSOCKET.REDIS_CLUSTER or settings.REDIS.CLUSTER,
    )
    USAGE_POOL = RedisDict(
        f'{settings.REDIS.KEY_PREFIX}:usage_pool',
        redis_url=settings.SYSTEM.WEBSOCKET.REDIS_URL or settings.REDIS.URL,
        redis_sentinels=ws_sentinels,
        redis_cluster=settings.SYSTEM.WEBSOCKET.REDIS_CLUSTER or settings.REDIS.CLUSTER,
    )

    clean_up_lock = RedisLock(
        redis_url=settings.SYSTEM.WEBSOCKET.REDIS_URL or settings.REDIS.URL,
        lock_name=f'{settings.REDIS.KEY_PREFIX}:usage_cleanup_lock',
        timeout_secs=settings.SYSTEM.WEBSOCKET.REDIS_LOCK_TIMEOUT,
        redis_sentinels=ws_sentinels,
        redis_cluster=settings.SYSTEM.WEBSOCKET.REDIS_CLUSTER or settings.REDIS.CLUSTER,
    )
    aquire_func = clean_up_lock.aquire_lock
    renew_func = clean_up_lock.renew_lock
    release_func = clean_up_lock.release_lock

    session_cleanup_lock = RedisLock(
        redis_url=settings.SYSTEM.WEBSOCKET.REDIS_URL or settings.REDIS.URL,
        lock_name=f'{settings.REDIS.KEY_PREFIX}:session_cleanup_lock',
        timeout_secs=settings.SYSTEM.WEBSOCKET.REDIS_LOCK_TIMEOUT,
        redis_sentinels=ws_sentinels,
        redis_cluster=settings.SYSTEM.WEBSOCKET.REDIS_CLUSTER or settings.REDIS.CLUSTER,
    )
    session_aquire_func = session_cleanup_lock.aquire_lock
    session_renew_func = session_cleanup_lock.renew_lock
    session_release_func = session_cleanup_lock.release_lock
else:
    MODELS = {}

    SESSION_POOL = {}
    USAGE_POOL = {}

    aquire_func = release_func = renew_func = lambda: True
    session_aquire_func = session_release_func = session_renew_func = lambda: True


async def periodic_session_pool_cleanup():
    """Reap orphaned SESSION_POOL entries that missed heartbeats (e.g. crashed instance)."""
    if not session_aquire_func():
        log.debug('Session cleanup lock held by another node. Skipping.')
        return

    try:
        while True:
            if not session_renew_func():
                log.error('Unable to renew session cleanup lock. Exiting.')
                return

            now = int(time.time())
            for sid in list(SESSION_POOL.keys()):
                entry = SESSION_POOL.get(sid)
                if entry and now - entry.get('last_seen_at', 0) > SESSION_POOL_TIMEOUT:
                    log.warning(f'Reaping orphaned session {sid} (user {entry.get("id")})')
                    del SESSION_POOL[sid]
            await asyncio.sleep(SESSION_POOL_TIMEOUT)
    finally:
        session_release_func()


async def periodic_usage_pool_cleanup():
    max_retries = 2
    retry_delay = random.uniform(settings.SYSTEM.WEBSOCKET.REDIS_LOCK_TIMEOUT / 2, settings.SYSTEM.WEBSOCKET.REDIS_LOCK_TIMEOUT)
    for attempt in range(max_retries + 1):
        if aquire_func():
            break
        else:
            if attempt < max_retries:
                log.debug(f'Cleanup lock already exists. Retry {attempt + 1} after {retry_delay}s...')
                await asyncio.sleep(retry_delay)
            else:
                log.warning('Failed to acquire cleanup lock after retries. Skipping cleanup.')
                return

    log.debug('Running periodic_cleanup')
    try:
        while True:
            if not renew_func():
                log.error(f'Unable to renew cleanup lock. Exiting usage pool cleanup.')
                raise Exception('Unable to renew usage pool cleanup lock.')

            now = int(time.time())
            send_usage = False
            for model_id, connections in list(USAGE_POOL.items()):
                # Creating a list of sids to remove if they have timed out
                expired_sids = [
                    sid for sid, details in connections.items() if now - details['updated_at'] > TIMEOUT_DURATION
                ]

                for sid in expired_sids:
                    del connections[sid]

                if not connections:
                    log.debug(f'Cleaning up model {model_id} from usage pool')
                    del USAGE_POOL[model_id]
                else:
                    USAGE_POOL[model_id] = connections

                send_usage = True
            await asyncio.sleep(TIMEOUT_DURATION)
    finally:
        release_func()


app = socketio.ASGIApp(
    sio,
    socketio_path='/ws/socket.io',
)


def get_models_in_use():
    # List models that are currently in use
    models_in_use = list(USAGE_POOL.keys())
    return models_in_use


def get_user_id_from_session_pool(sid):
    user = SESSION_POOL.get(sid)
    if user:
        return user['id']
    return None


def get_session_ids_from_room(room):
    """Get all session IDs from a specific room."""
    active_session_ids = sio.manager.get_participants(
        namespace='/',
        room=room,
    )
    return [session_id[0] for session_id in active_session_ids]


def get_user_ids_from_room(room):
    active_session_ids = get_session_ids_from_room(room)

    active_user_ids = list(
        set(
            [
                SESSION_POOL.get(session_id)['id']
                for session_id in active_session_ids
                if SESSION_POOL.get(session_id) is not None
            ]
        )
    )
    return active_user_ids


async def emit_to_users(event: str, data: dict, user_ids: list[str]):
    """
    Send a message to specific users using their user:{id} rooms.

    Args:
        event (str): The event name to emit.
        data (dict): The payload/data to send.
        user_ids (list[str]): The target users' IDs.
    """
    try:
        for user_id in user_ids:
            await sio.emit(event, data, room=f'user:{user_id}')
    except Exception as e:
        log.debug(f'Failed to emit event {event} to users {user_ids}: {e}')


async def enter_room_for_users(room: str, user_ids: list[str]):
    """
    Make all sessions of a user join a specific room.
    Args:
        room (str): The room to join.
        user_ids (list[str]): The target user's IDs.
    """
    try:
        for user_id in user_ids:
            session_ids = get_session_ids_from_room(f'user:{user_id}')
            for sid in session_ids:
                await sio.enter_room(sid, room)
    except Exception as e:
        log.debug(f'Failed to make users {user_ids} join room {room}: {e}')


async def disconnect_user_sessions(user_id: str):
    """Disconnect all Socket.IO sessions belonging to a user.

    Call this when a user's role is changed or the user is deleted so that
    stale role/permission data cached in SESSION_POOL is invalidated.
    The client will automatically reconnect and re-authenticate with
    fresh data from the database.
    """
    try:
        session_ids = get_session_ids_from_room(f'user:{user_id}')
        for sid in session_ids:
            await sio.disconnect(sid)
        if session_ids:
            log.info(f'Disconnected {len(session_ids)} session(s) for user {user_id}')
    except Exception as e:
        log.warning(f'Failed to disconnect sessions for user {user_id}: {e}')


@sio.on('usage')
async def usage(sid, data):
    if sid in SESSION_POOL:
        model_id = data['model']
        # Record the timestamp for the last update
        current_time = int(time.time())

        # Store the new usage data and task
        USAGE_POOL[model_id] = {
            **(USAGE_POOL[model_id] if model_id in USAGE_POOL else {}),
            sid: {'updated_at': current_time},
        }


@sio.event
async def connect(sid, environ, auth):
    user = None
    if auth and 'token' in auth:
        scope = (environ or {}).get('asgi.scope') or {}
        fastapi_app = scope.get('app')
        redis = getattr(getattr(fastapi_app, 'state', None), 'redis', None) or REDIS
        data = decode_token(auth['token'])

        if data is not None and 'id' in data and await is_valid_token(data, redis):
            user = await Users.get_user_by_id(data['id'])

        if user:
            SESSION_POOL[sid] = {
                **user.model_dump(
                    exclude=[
                        'profile_image_url',
                        'profile_banner_image_url',
                        'date_of_birth',
                        'bio',
                        'gender',
                    ]
                ),
                'last_seen_at': int(time.time()),
            }
            await sio.enter_room(sid, f'user:{user.id}')


@sio.on('user-join')
async def user_join(sid, data):
    auth = data.get('auth')
    if not auth or 'token' not in auth:
        return

    environ = sio.get_environ(sid) or {}
    scope = environ.get('asgi.scope') or {}
    fastapi_app = scope.get('app')
    redis = getattr(getattr(fastapi_app, 'state', None), 'redis', None) or REDIS
    token_data = decode_token(auth['token'])
    if token_data is None or 'id' not in token_data or not await is_valid_token(token_data, redis):
        return

    user = await Users.get_user_by_id(token_data['id'])
    if not user:
        return

    SESSION_POOL[sid] = {
        **user.model_dump(
            exclude=[
                'profile_image_url',
                'profile_banner_image_url',
                'date_of_birth',
                'bio',
                'gender',
            ]
        ),
        'last_seen_at': int(time.time()),
    }

    await sio.enter_room(sid, f'user:{user.id}')

    # # Join all the channels only if user has channels permission
    # if user.role == 'admin' or await has_permission(user.id, 'features.channels'):
    #     channels = await Channels.get_channels_by_user_id(user.id)
    #     log.debug(f'{channels=}')
    #     for channel in channels:
    #         await sio.enter_room(sid, f'channel:{channel.id}')
    #
    # return {'id': user.id, 'name': user.name}


@sio.on('heartbeat')
async def heartbeat(sid, data):
    user = SESSION_POOL.get(sid)
    if user:
        SESSION_POOL[sid] = {**user, 'last_seen_at': int(time.time())}
        await Users.update_last_active_by_id(user['id'])


@sio.event
async def disconnect(sid, reason=None):
    if sid in SESSION_POOL:
        user = SESSION_POOL[sid]
        del SESSION_POOL[sid]

        # # Clean up USAGE_POOL entries for this session
        # for model_id in list(USAGE_POOL.keys()):
        #     connections = USAGE_POOL.get(model_id)
        #     if connections and sid in connections:
        #         del connections[sid]
        #         if not connections:
        #             del USAGE_POOL[model_id]
        #         else:
        #             USAGE_POOL[model_id] = connections
        #
        # await YDOC_MANAGER.remove_user_from_all_documents(sid)
    else:
        pass
        # print(f"Unknown session ID {sid} disconnected")


async def _make_channel_emitter(request_info):
    """Event emitter that routes pipeline output to a channel message.

    Translates chat:completion events into channel message:update socket
    emissions, throttled to avoid flooding with per-token updates.
    """
    channel_id = request_info['chat_id'].removeprefix('channel:')
    message_id = request_info['message_id']

    state = {'last_emit_at': 0.0}
    THROTTLE_INTERVAL = 0.15  # ~6 updates/sec

    async def _emit_channel_update(content: str, done: bool = False):
        from models.messages import MessageForm, Messages

        msg = await Messages.get_message_by_id(message_id)
        if not msg or msg.channel_id != channel_id:
            return

        update_form = MessageForm(content=content)
        if done:
            # Merge done flag into existing meta (preserve model_id etc.)
            existing_meta = msg.meta or {}
            update_form = MessageForm(
                content=content,
                meta={**existing_meta, 'done': True},
            )

        await Messages.update_message_by_id(message_id, update_form)
        message = await Messages.get_message_by_id(message_id)
        if message:
            await sio.emit(
                'events:channel',
                {
                    'channel_id': channel_id,
                    'message_id': message_id,
                    'data': {
                        'type': 'message:update',
                        'data': message.model_dump(),
                    },
                },
                to=f'channel:{channel_id}',
            )

    async def __channel_emitter__(event_data):
        event_type = event_data.get('type')

        if event_type == 'chat:completion':
            data = event_data.get('data', {})
            content = data.get('content', '')
            done = data.get('done', False)

            if not content and not done:
                return

            now = __import__('time').time()
            if done or (now - state['last_emit_at']) >= THROTTLE_INTERVAL:
                state['last_emit_at'] = now
                await _emit_channel_update(content, done)

        elif event_type == 'chat:message:error':
            error = event_data.get('data', {}).get('error', {})
            error_content = error.get('content', 'An error occurred') if isinstance(error, dict) else str(error)
            await _emit_channel_update(f'Error: {error_content}', done=True)

    return __channel_emitter__


async def get_event_call(request_info):
    async def __event_caller__(event_data):
        session_id = request_info['session_id']

        # session_id is client-supplied; only the requesting user's own live session may be targeted.
        session = SESSION_POOL.get(session_id)
        if session is None or session.get('id') != request_info.get('user_id'):
            log.warning(f'Event caller: session {session_id} not owned by requesting user or disconnected')
            return {'error': 'Client session disconnected.'}

        try:
            return await sio.call(
                'events',
                {
                    'chat_id': request_info.get('chat_id', None),
                    'message_id': request_info.get('message_id', None),
                    'data': event_data,
                },
                to=session_id,
                timeout=settings.SYSTEM.WEBSOCKET.EVENT_CALLER_TIMEOUT,
            )
        except TimeoutError:
            log.warning(f'Event caller timed out for session {session_id}')
            return {'error': 'Event call timed out. The browser tab may be inactive or closed.'}

    if 'session_id' in request_info and 'chat_id' in request_info and 'message_id' in request_info:
        return __event_caller__
    else:
        return None


get_event_caller = get_event_call

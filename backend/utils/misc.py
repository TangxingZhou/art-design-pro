from __future__ import annotations

import json
import logging
import re
import threading
import time
from datetime import timedelta
from typing import Sequence, Union
import mimeparse

log = logging.getLogger(__name__)


def get_allow_block_lists(filter_list):
    allow_list = []
    block_list = []

    if filter_list:
        for d in filter_list:
            if d.startswith('!'):
                # Domains starting with "!" → blocked
                block_list.append(d[1:].strip())
            else:
                # Domains starting without "!" → allowed
                allow_list.append(d.strip())

    return allow_list, block_list


def _host_matches_pattern(host: str, pattern: str) -> bool:
    """Match a hostname against a filter entry on DNS label boundaries.

    `pattern` matches `host` when equal or a parent domain of it, so `corp.com`
    matches `api.corp.com` but not `evilcorp.com`, and an IP literal matches only
    itself. Avoids the raw-suffix confusion of a plain endswith.
    """
    host = (host or '').strip().lower().rstrip('.')
    pattern = (pattern or '').strip().lower().rstrip('.')
    if not host or not pattern:
        return False
    return host == pattern or host.endswith('.' + pattern)


def is_host_allowed(host: Union[str, Sequence[str]], filter_list: list[str | None] = None) -> bool:
    """Allow/block a hostname (or list of hostnames / resolved IPs) against a
    WEB_FETCH_FILTER_LIST-style filter, matching on label boundaries.

    Pass a parsed hostname, never a full URL: matching against a URL lets a path
    component defeat the filter (e.g. ``https://blocked.example/x`` ends with ``/x``,
    not the blocked host). Entries prefixed with ``!`` are blocked; the rest form an allowlist.
    """
    if not filter_list:
        return True

    allow_list, block_list = get_allow_block_lists(filter_list)
    hosts = [host] if isinstance(host, str) else list(host or [])

    if allow_list:
        if not any(_host_matches_pattern(h, allowed) for h in hosts for allowed in allow_list):
            return False

    if any(_host_matches_pattern(h, blocked) for h in hosts for blocked in block_list):
        return False

    return True


def parse_duration(duration: str) -> timedelta | None:
    if duration == '-1' or duration == '0':
        return None

    # Regular expression to find number and unit pairs
    pattern = r'(-?\d+(\.\d+)?)(ms|s|m|h|d|w)'
    matches = re.findall(pattern, duration)

    if not matches:
        raise ValueError('Invalid duration string')

    total_duration = timedelta()

    for number, _, unit in matches:
        number = float(number)
        if unit == 'ms':
            total_duration += timedelta(milliseconds=number)
        elif unit == 's':
            total_duration += timedelta(seconds=number)
        elif unit == 'm':
            total_duration += timedelta(minutes=number)
        elif unit == 'h':
            total_duration += timedelta(hours=number)
        elif unit == 'd':
            total_duration += timedelta(days=number)
        elif unit == 'w':
            total_duration += timedelta(weeks=number)

    return total_duration


def sanitize_metadata(metadata: dict) -> dict:
    """
    Return a JSON-safe copy of a metadata dict for database storage.

    The middleware metadata accumulates non-serializable Python objects
    (e.g. callable tool functions, MCP client instances) that cause
    PostgreSQL JSON inserts to fail.  This helper strips those out while
    preserving the primitive data needed for file-to-chat linking.
    """
    if not isinstance(metadata, dict):
        return metadata

    def _sanitize(obj):
        if isinstance(obj, (str, int, float, bool, type(None))):
            return obj
        if isinstance(obj, dict):
            return {k: _sanitize(v) for k, v in obj.items() if not callable(v) and _is_serializable(v)}
        if isinstance(obj, list):
            return [_sanitize(v) for v in obj if not callable(v) and _is_serializable(v)]
        if callable(obj):
            return None
        # Last resort: try to see if it's serializable
        try:
            json.dumps(obj)
            return obj
        except (TypeError, ValueError):
            return None

    def _is_serializable(obj):
        """Quick check whether a value can survive JSON serialization."""
        if isinstance(obj, (str, int, float, bool, type(None), dict, list)):
            return True
        try:
            json.dumps(obj)
            return True
        except (TypeError, ValueError):
            return False

    return _sanitize(metadata)


def freeze(value):
    """
    Freeze a value to make it hashable.
    """
    if isinstance(value, dict):
        return frozenset((k, freeze(v)) for k, v in value.items())
    elif isinstance(value, list):
        return tuple(freeze(v) for v in value)
    return value


def throttle(interval: float = 10.0):
    """
    Decorator to prevent a function from being called more than once within a specified duration.
    If the function is called again within the duration, it returns None. To avoid returning
    different types, the return type of the function should be T | None.

    :param interval: Duration in seconds to wait before allowing the function to be called again.
    """

    def decorator(func):
        last_calls = {}
        lock = threading.Lock()

        async def wrapper(*args, **kwargs):
            if interval is None:
                return await func(*args, **kwargs)

            key = (args, freeze(kwargs))
            now = time.time()
            if now - last_calls.get(key, 0) < interval:
                return None
            with lock:
                if now - last_calls.get(key, 0) < interval:
                    return None
                last_calls[key] = now
            return await func(*args, **kwargs)

        return wrapper

    return decorator


def validate_email_format(email: str) -> bool:
    if email.endswith('@localhost'):
        return True

    return bool(re.match(r'[^@]+@[^@]+\.[^@]+', email))


def strict_match_mime_type(supported: list[str] | str, header: str) -> str | None:
    """
    Strictly match the mime type with the supported mime types.

    :param supported: The supported mime types.
    :param header: The header to match.
    :return: The matched mime type or None if no match is found.
    """

    try:
        if isinstance(supported, str):
            supported = supported.split(',')

        supported = [s for s in supported if s.strip() and '/' in s]

        if len(supported) == 0:
            # Default to common types if none are specified
            supported = ['audio/*', 'video/webm']

        match = mimeparse.best_match(supported, header)
        if not match:
            return None

        _, _, match_params = mimeparse.parse_mime_type(match)
        _, _, header_params = mimeparse.parse_mime_type(header)
        for k, v in match_params.items():
            if header_params.get(k) != v:
                return None

        return match
    except Exception as e:
        log.exception(f'Failed to match mime type {header}: {e}')
        return None

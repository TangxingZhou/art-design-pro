"""Redis-backed distributed data structures for WebSocket state management."""

from __future__ import annotations

import hashlib
import json
import uuid

from utils.redis import get_redis_connection


class RedisLock:
    """Distributed lock backed by a Redis SET with NX/EX semantics."""

    def __init__(
        self,
        redis_url,
        lock_name,
        timeout_secs,
        redis_sentinels=[],
        redis_cluster=False,
    ):
        self.lock_name = lock_name
        self.lock_id = str(uuid.uuid4())
        self.timeout_secs = timeout_secs
        self.lock_obtained = False
        self.redis = get_redis_connection(
            redis_url,
            redis_sentinels,
            redis_cluster=redis_cluster,
            decode_responses=True,
        )

    def aquire_lock(self):
        # nx=True will only set this key if it _hasn't_ already been set
        self.lock_obtained = self.redis.set(self.lock_name, self.lock_id, nx=True, ex=self.timeout_secs)
        return self.lock_obtained

    def renew_lock(self):
        # xx=True will only set this key if it _has_ already been set
        return self.redis.set(self.lock_name, self.lock_id, xx=True, ex=self.timeout_secs)

    def release_lock(self):
        lock_value = self.redis.get(self.lock_name)
        if lock_value and lock_value == self.lock_id:
            self.redis.delete(self.lock_name)


class RedisDict:
    def __init__(self, name, redis_url, redis_sentinels=[], redis_cluster=False):
        self.name = name
        # Per-process cache of the last payload fingerprint written by set().
        # Used to skip redundant HSET round-trips when the model list hasn't
        # changed — the dominant Redis write source on busy multi-pod setups.
        self._last_signature: str | None = None
        self.redis = get_redis_connection(
            redis_url,
            redis_sentinels,
            redis_cluster=redis_cluster,
            decode_responses=True,
        )

    def __setitem__(self, key, value):
        serialized_value = json.dumps(value)
        self.redis.hset(self.name, key, serialized_value)

    def __getitem__(self, key):
        value = self.redis.hget(self.name, key)
        if value is None:
            raise KeyError(key)
        return json.loads(value)

    def __delitem__(self, key):
        result = self.redis.hdel(self.name, key)
        if result == 0:
            raise KeyError(key)

    def __contains__(self, key):
        return self.redis.hexists(self.name, key)

    def __len__(self):
        return self.redis.hlen(self.name)

    def keys(self):
        return self.redis.hkeys(self.name)

    def values(self):
        return [json.loads(v) for v in self.redis.hvals(self.name)]

    def items(self):
        return [(k, json.loads(v)) for k, v in self.redis.hgetall(self.name).items()]

    def set(self, mapping: dict):
        if not mapping:
            self.redis.delete(self.name)
            self._last_signature = None
            return

        # Serialize values once — reused for both the fingerprint and the write.
        serialized = {k: json.dumps(v) for k, v in mapping.items()}

        # Skip the write when the prepared mapping is identical to the last one
        # this process wrote.  The check is per-instance (not distributed), but
        # still eliminates the majority of redundant writes because each pod
        # typically produces the same model list on consecutive refreshes.
        signature = hashlib.sha256(json.dumps(serialized, sort_keys=True).encode()).hexdigest()
        if signature == self._last_signature:
            return

        # Fetch existing keys before writing so we know which ones to remove.
        # HKEYS is cheap — it transfers only short key strings, not large JSON values.
        existing_keys = set(self.redis.hkeys(self.name))
        new_keys = set(mapping.keys())
        keys_to_remove = existing_keys - new_keys

        # HSET first (add/update all new values), then HDEL (remove stale keys).
        # We never DELETE the whole hash — this eliminates the race window
        # where concurrent readers would see an empty models dict.
        self.redis.hset(self.name, mapping=serialized)
        if keys_to_remove:
            self.redis.hdel(self.name, *keys_to_remove)

        self._last_signature = signature

    def get(self, key, default=None):
        try:
            return self[key]
        except KeyError:
            return default

    def clear(self):
        self.redis.delete(self.name)
        self._last_signature = None

    def update(self, other=None, **kwargs):
        if other is not None:
            for k, v in other.items() if hasattr(other, 'items') else other:
                self[k] = v
        for k, v in kwargs.items():
            self[k] = v

    def setdefault(self, key, default=None):
        if key not in self:
            self[key] = default
        return self[key]

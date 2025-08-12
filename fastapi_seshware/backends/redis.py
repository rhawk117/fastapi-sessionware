from fastapi_seshware.backends.base import (
    SessionBackend,
    SessionBackendOptions,
    SessionPayload,
)

import redis.asyncio as aioredis

from fastapi_seshware.utils import b64url_encode, utc_seconds


class RedisSessionBackend(SessionBackend):
    def __init__(
        self,
        options: SessionBackendOptions,
        *,
        redis_client: aioredis.Redis,
        prefix: str = "session:",
    ) -> None:
        super().__init__(options=options)
        self._redis: aioredis.Redis = redis_client
        self.prefix: str = prefix

    def redis_key(self, session_id: bytes) -> str:
        return f"{self.prefix}{b64url_encode(session_id)}"

    async def store(self, payload: SessionPayload, session_id: bytes) -> None:
        session_dump = payload.model_dump()
        key = self.redis_key(session_id)

        pipeline = self._redis.pipeline()
        pipeline.hset(key, mapping=session_dump)

        expires_next = int(self._options.max_lifetime.total_seconds())
        if self._options.idle_timeout:
            expires_next = int(self._options.idle_timeout.total_seconds())

        pipeline.expire(key, expires_next)
        await pipeline.execute()

    async def load(self, session_id: bytes) -> SessionPayload | None:
        key = self.redis_key(session_id=session_id)
        data = await self._redis.hgetall(key)  # type: ignore
        if not data:
            return None

        try:
            payload = SessionPayload(**data)
        except Exception:
            return None

        pipe = self._redis.pipeline()
        pipe.hset(key, "last_seen", str(utc_seconds()))

        if self._options.idle_timeout:
            pipe.expire(key, int(self._options.idle_timeout.total_seconds()))

        await pipe.execute()
        return payload

    async def revoke(self, session_id: bytes) -> None:
        key = self.redis_key(session_id=session_id)
        await self._redis.delete(key)

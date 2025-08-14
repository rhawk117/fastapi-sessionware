import abc
from dataclasses import dataclass
from datetime import timedelta
from typing import Any, Protocol

from fastapi_seshware.signatures import BaseSessionSigner
import secrets
from pydantic import BaseModel


class SessionPayload(BaseModel):
    user_identifier: Any
    issued_at: str
    last_seen: str
    max_age: str
    extras: dict[str, Any] | None = None


class SessionIdGenerator(Protocol):
    def __call__(self) -> bytes: ...


def default_id_generator() -> bytes:
    return secrets.token_bytes(32)


@dataclass(slots=True)
class SessionBackendOptions:
    signer: BaseSessionSigner
    max_lifetime: timedelta
    idle_timeout: timedelta | None = None
    id_generator: SessionIdGenerator | None = None


class SessionBackend(abc.ABC):
    def __init__(self, options: SessionBackendOptions) -> None:
        self._options: SessionBackendOptions = options

    @abc.abstractmethod
    async def store(
        self,
        payload: SessionPayload,
        session_id: bytes,
    ) -> None:
        pass

    @abc.abstractmethod
    async def load(self, session_id: bytes) -> SessionPayload | None: ...

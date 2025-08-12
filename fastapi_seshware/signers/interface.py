import abc
from typing import NamedTuple

from fastapi_seshware.signers.fingerprint import FingerprintContext


class SignatureResult(NamedTuple):
    session_id: bytes
    issued_at: int
    key_id: str | None


class BaseSessionSigner(abc.ABC):
    @abc.abstractmethod
    def sign(self, *, session_id: bytes, context: FingerprintContext) -> str: ...

    @abc.abstractmethod
    def load(
        self,
        session_id: str,
        *,
        context: FingerprintContext,
        max_age_seconds: int | None = None,
    ) -> SignatureResult | None: ...

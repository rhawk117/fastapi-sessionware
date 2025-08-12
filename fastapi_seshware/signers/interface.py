import abc
from typing import NamedTuple

from fastapi_seshware.fingerprint import FingerprintContext


class SignatureResult(NamedTuple):
    session_id: bytes
    issued_at: int
    key_id: str | None


class SessionSigner(abc.ABC):
    @abc.abstractmethod
    def sign_session(
        self,
        *,
        session_id: bytes,
        context: FingerprintContext
    ) -> SignatureResult: ...


    @abc.abstractmethod
    def load_signature(
        self,
        session_id: str,
        *,
        context: FingerprintContext,
    ) -> SignatureResult | None: ...
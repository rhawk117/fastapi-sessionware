import abc
import base64
import hashlib
import hmac
import time
from typing import TypeAlias
from collections.abc import Callable
from itsdangerous import (
    URLSafeTimedSerializer,
    BadSignature,
    BadTimeSignature,
    SignatureExpired,
)

IdGenerator: TypeAlias = Callable[[], str]


def _b64_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64_decode(s: str) -> bytes:
    padding = "=" * ((4 - len(s) % 4) % 4)
    return base64.urlsafe_b64decode(s + padding)


class SignatureAdapter(abc.ABC):
    """
    Abstract base class for signers that produce a signed (verifiable) string from an unsigned
    session id and can recover/validate the server created session id from the signed string.

    You can use this to create your own signature adapters, but for 90% of use cases the ones
    provided will be more than enough to protect your session ids.
    """

    def __init__(self, secret_key: str | bytes, *, key_salt: str | None = None) -> None:
        if isinstance(secret_key, bytes):
            self._secret_key: str = secret_key.decode()
        else:
            self._secret_key: str = secret_key  # type: ignore[assignment]
        self._key_salt: str | None = key_salt

    @abc.abstractmethod
    def create_signature(self, unsigned_id: str) -> str:
        """
        Creates a signature for the provided `unsigned_id` and returns a signed string.
        """
        raise NotImplementedError

    @abc.abstractmethod
    def load_signature(self, signed_sid: str) -> str | None:
        """
        Removes and validates the signature from `signed_sid` provided by the client
        and returns the original unsigned id.
        """
        raise NotImplementedError


class SerializerSignatures(SignatureAdapter):
    """
    URLSafeTimedSerializer-based implementation.
    """

    def __init__(
        self,
        secret_key: str | bytes,
        *,
        key_salt: str | None = None,
        max_age: int | None = None,
    ) -> None:
        super().__init__(secret_key, key_salt=key_salt)
        self._serializer = URLSafeTimedSerializer(
            secret_key=self._secret_key, salt=self._key_salt
        )
        self._max_age = max_age

    def create_signature(self, unsigned_id: str) -> str:
        return self._serializer.dumps(unsigned_id, salt=self._key_salt)

    def load_signature(self, signed_sid: str) -> str | None:
        try:
            return self._serializer.loads(
                signed_sid, salt=self._key_salt, max_age=self._max_age
            )
        except (SignatureExpired, BadTimeSignature, BadSignature, Exception):
            return None


class HmacSignatures(SignatureAdapter):
    """
    HMAC-SHA256 signer that includes a timestamp for optional `max_age` checks.

    Envelope format:
      base64url( "<sid>.<timestamp>" ) + "." + base64url( HMAC( key, "<sid>.<ts>" ) )
    """

    def __init__(
        self,
        secret_key: str | bytes,
        *,
        key_salt: str | None = None,
        max_age: int | None = None,
    ) -> None:
        super().__init__(secret_key, key_salt=key_salt)
        self._max_age = max_age
        material = (self._key_salt + ":" if self._key_salt else "") + self._secret_key
        self._hmac_key: bytes = material.encode()

    def encode(self, msg: bytes) -> bytes:
        return hmac.new(self._hmac_key, msg, hashlib.sha256).digest()

    def create_signature(self, unsigned_id: str) -> str:
        timestamp = str(int(time.time()))
        message = f"{unsigned_id}.{timestamp}".encode()
        body = _b64_encode(message)
        mac = _b64_encode(self.encode(message))
        return f"{body}.{mac}"

    def load_signature(self, signed_sid: str) -> str | None:
        try:
            body_b64, mac_b64 = signed_sid.split(".", 1)
        except ValueError:
            return None

        try:
            body, provided_mac = _b64_decode(body_b64), _b64_decode(mac_b64)
        except Exception:
            return None

        expected_mac = self.encode(body)
        if not hmac.compare_digest(expected_mac, provided_mac):
            return None

        try:
            data = body.decode()
            unsigned_id, ts_str = data.rsplit(".", 1)
            ts = int(ts_str)
        except Exception:
            return None

        if self._max_age is not None:
            now = int(time.time())
            if now - ts > self._max_age:
                return None

        return unsigned_id

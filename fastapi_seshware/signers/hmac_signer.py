import hashlib
import hmac
from dataclasses import dataclass
import time
from typing import NamedTuple
from fastapi_seshware.signers.fingerprint import (
    FingerprintContext,
    default_fingerprint_encoder,
)
from fastapi_seshware.signers.interface import BaseSessionSigner, SignatureResult
from fastapi_seshware.utils import b64url_decode, b64url_encode, utc_seconds


@dataclass
class HmacSignerOptions:
    key_ring: dict[str, bytes]
    current_key_id: str
    version: str = "v1"

    def __post_init__(self) -> None:
        if not self.key_ring:
            raise ValueError("HmacSignerOptions: key_ring cannot be empty")

        if self.current_key_id not in self.key_ring:
            raise ValueError("HmacSignerOptions: current_key_id must exist in key_ring")

        for key_id, key_value in self.key_ring.items():
            if not key_id or not isinstance(key_id, str):
                raise ValueError("HmacSignerOptions: key IDs must be non-empty strings")
            if not key_value or not isinstance(key_value, (bytes, bytearray)):
                raise ValueError(
                    "HmacSignerOptions: key values must be non-empty bytes"
                )
            if len(key_value) < 32:
                raise ValueError(
                    "HmacSignerOptions: key values must be at least 32 bytes long"
                )


def create_token_hash(
    key: bytes,
    header: bytes,
    payload: bytes,
) -> bytes:
    return hmac.new(
        key,
        header + b"." + payload,
        hashlib.sha256,
    ).digest()


class TokenSegments(NamedTuple):
    version: str
    key_id: str
    payload: str
    signature: str


class HmacSigner(BaseSessionSigner):
    __PAYLOAD_SIZE: int = 32 + 8 + 32  # session_id + issued_at + fingerprint
    __ISSUED_AT_POS: slice = slice(32, 40)
    __FINGERPRINT_POS: slice = slice(40, 72)
    __SESSION_ID_POS: slice = slice(0, 32)

    def __init__(self, options: HmacSignerOptions) -> None:
        self._options: HmacSignerOptions = options

    def sign(self, *, session_id: bytes, context: FingerprintContext) -> str:
        if len(session_id) != 32:
            raise ValueError("HmacSigner: session_id must be 32 bytes long")

        current_kid = self._options.current_key_id
        key_value = self._options.key_ring.get(current_kid)
        if not key_value:
            raise ValueError("HmacSigner: current_key_id not found in key_ring")

        issued_at = int(time.time()).to_bytes(8, "big")
        fingerprint = default_fingerprint_encoder(context)

        payload_bytes = session_id + issued_at + fingerprint
        token_header = f"{self._options.version}.{current_kid}".encode("ascii")

        token_hash = create_token_hash(key_value, token_header, payload_bytes)

        encoded_payload = b64url_encode(payload_bytes)
        encoded_hash = b64url_encode(token_hash)

        return f"{self._options.version}.{current_kid}.{encoded_payload}.{encoded_hash}"

    def parse_token_string(self, token: str) -> TokenSegments | None:
        try:
            version, key_id, payload, signature = token.split(".")
            return TokenSegments(version, key_id, payload, signature)
        except ValueError:
            return None

    def load(
        self,
        session_id: str,
        *,
        context: FingerprintContext,
        max_age_seconds: int | None = None,
    ) -> SignatureResult | None:
        token_segments = self.parse_token_string(session_id)
        if not token_segments:
            return None

        if token_segments.version != self._options.version:
            raise ValueError("HmacSigner: version mismatch")

        key_value = self._options.key_ring.get(token_segments.key_id)
        if not key_value:
            raise ValueError("HmacSigner: key_id not found in key_ring")

        payload = b64url_decode(token_segments.payload)
        signature = b64url_decode(token_segments.signature)

        header = f"{token_segments.version}.{token_segments.key_id}".encode("ascii")
        expected_signature = create_token_hash(key_value, header, payload)
        if not hmac.compare_digest(expected_signature, signature):
            return None

        if len(payload) != self.__PAYLOAD_SIZE:
            return None

        expected_fingerprint = b64url_encode(default_fingerprint_encoder(context))

        payload_fingerprint = payload[self.__FINGERPRINT_POS]
        actual_fingerprint = b64url_encode(payload_fingerprint)
        if not hmac.compare_digest(expected_fingerprint, actual_fingerprint):
            return None

        issued_at = int.from_bytes(payload[self.__ISSUED_AT_POS], "big")
        session_id_bytes = payload[self.__SESSION_ID_POS]
        if max_age_seconds is not None:
            if utc_seconds() - issued_at > max_age_seconds:
                return None

        return SignatureResult(
            session_id=session_id_bytes,
            issued_at=issued_at,
            key_id=token_segments.key_id,
        )

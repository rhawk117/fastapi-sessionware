import time
from itsdangerous import URLSafeTimedSerializer

from fastapi_seshware.utils import b64url_decode, b64url_encode
from fastapi_seshware.signers.fingerprint import (
    FingerprintContext,
    default_fingerprint_encoder,
)

from fastapi_seshware.signers.interface import BaseSessionSigner, SignatureResult


class SerializerSessionSigner(BaseSessionSigner):
    def __init__(self, secret_key: str, salt: str = "sid") -> None:
        if not secret_key or len(secret_key) < 16:
            raise ValueError(
                "SerializerSessionSigner: Secret key must be at least 16 characters long"
            )

        self._serializer: URLSafeTimedSerializer = URLSafeTimedSerializer(
            secret_key, salt=salt
        )

    def sign(self, *, session_id: bytes, context: FingerprintContext) -> str:
        if len(session_id) != 32:
            raise ValueError(
                "SerializerSessionSigner: session_id must be 32 bytes long"
            )

        fingerprint_bytes = default_fingerprint_encoder(context)
        payload = {
            "session_id": b64url_encode(session_id),
            "issued_at": int(time.time()),
            "fingerprint": b64url_encode(fingerprint_bytes),
        }

        return self._serializer.dumps(payload)

    def load(
        self,
        session_id: str,
        *,
        context: FingerprintContext,
        max_age_seconds: int | None = None,
    ) -> SignatureResult | None:
        try:
            data: dict = self._serializer.loads(session_id, max_age=max_age_seconds)
        except Exception:
            return None

        session_id_b64: str | None = data.get("session_id")
        issued_at = data.get("issued_at", 0)
        fingerprint_b64: str | None = data.get("fingerprint")

        if session_id_b64 is None or issued_at is None and fingerprint_b64 is None:
            return None

        decoded_id = b64url_decode(session_id_b64)
        if len(decoded_id) != 32:
            return None

        expected_fingerprint = b64url_encode(default_fingerprint_encoder(context))
        if fingerprint_b64 != expected_fingerprint:
            return None

        return SignatureResult(
            session_id=decoded_id,
            issued_at=issued_at,
            key_id=None,
        )

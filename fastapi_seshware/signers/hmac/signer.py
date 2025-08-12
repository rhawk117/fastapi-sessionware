from dataclasses import dataclass
import time
from fastapi_seshware.fingerprint import FingerprintContext
from fastapi_seshware.signers.interface import SessionSigner, SignatureResult

from fastapi_seshware.signers.hmac import utils as hmac_utils


@dataclass
class HmacOptions:
    key_ring: dict[str, bytes]
    current_key_id: str
    version: str = "v1"

    def get_kid(self, version: str, kid: str) -> bytes:
        """
        Retrieves the HMAC key for the specified version and key ID (kid).

        Parameters
        ----------
        version : str
        kid : str
            _the token key id_

        Returns
        -------
        bytes
        Raises
        ------
        ValueError
            _The version doesn't match the instances_
        ValueError
            _The KID or key id isn't in the key ring_
        """
        if version != self.version:
            raise ValueError("Unsupported version")

        if kid not in self.key_ring:
            raise ValueError(f"Key ID `{kid}` not found in key ring")

        return self.key_ring[kid]

    @property
    def current_key(self) -> bytes:
        """
        Retrieves the current HMAC key based on the current_key_id.

        Raises
        ------
        KeyError
            If the current_key_id is not found in the key_ring.

        Returns
        -------
        bytes
        """
        return self.key_ring[self.current_key_id]

    def get_token_header(self) -> bytes:
        """
        Constructs the token header in the format: <version>.<current_key_id>
        encoded as ASCII bytes.
        Returns
        -------
        bytes
        """
        return f"{self.version}.{self.current_key_id}".encode("ascii")


class HmacSigner(SessionSigner):
    def __init__(
        self,
        hmac_options: HmacOptions,
    ) -> None:
        self.options = hmac_options

    def sign_session(self, *, session_id: bytes, context: FingerprintContext) -> str:
        return hmac_utils.create_hmac_token(
            session_id=session_id,
            options=self.options,
            context=context,
        )

    def load_signature(
        self,
        hmac_session_token: str,
        *,
        context: FingerprintContext,
        max_age_seconds: int | None = None,
    ) -> SignatureResult | None:
        token_segments = hmac_utils.get_token_segments(hmac_session_token)

        key = self.options.get_kid(
            version=token_segments.version,
            kid=token_segments.kid,
        )

        header = self.options.get_token_header()
        expected = hmac_utils.sign_hmac_token(
            header=header,
            payload=token_segments.payload,
            key=key,
        )
        if not hmac_utils.digest_okay(
            expected=expected, current=token_segments.signature
        ):
            return None

        if not hmac_utils.payload_length_valid(token_segments.payload):
            return None

        payload_parts = hmac_utils.parse_token_payload(token_segments.payload)

        if not hmac_utils.fingerprint_okay(
            current=context,
            saved=payload_parts.fingerprint,
        ):
            return None

        if max_age_seconds is not None:
            now = int(time.time())
            if now - payload_parts.issued_at > max_age_seconds:
                return None

        return SignatureResult(
            session_id=payload_parts.session_id,
            issued_at=payload_parts.issued_at,
            key_id=token_segments.kid,
        )

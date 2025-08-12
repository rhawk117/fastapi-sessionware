from __future__ import annotations
import hmac
import hashlib
from typing import TYPE_CHECKING, NamedTuple

from fastapi_seshware.fingerprint import (
    FingerprintContext,
    default_fingerprint_encoder,
)
from fastapi_seshware.utils import b64url_encode, utc_seconds, b64url_decode
from fastapi_seshware.signers.hmac import hmac_constants


if TYPE_CHECKING:
    from fastapi_seshware.signers.hmac.signer import HmacOptions


class HmacTokenSegments(NamedTuple):
    """
    The parsed segements of an HMAC token.
    """

    version: str
    kid: str
    payload: bytes
    signature: bytes


def sign_hmac_token(
    key: bytes,
    header: bytes,
    payload: bytes,
) -> bytes:
    """
    Creates an HMAC-SHA256 signature for the given header and payload using the
    provided key which attached to the end of the message.

    Parameters
    ----------
    key : bytes
    header : bytes
    payload : bytes

    Returns
    -------
    bytes
    """
    return hmac.new(key, header + b"." + payload, hashlib.sha256).digest()


def _create_hmac_payload(
    *,
    session_id: bytes,
    issued_at: int,
    fingerprint: FingerprintContext,
) -> bytes:
    """
    Forms the payload for HMAC token in the following format:
    <session_id(32 bytes)><issued_at(8 bytes big-endian unsigned int)><fingerprint(32 bytes)>

    - `session_id`: The unique session identifier.
    - `issued_at`: The timestamp when the token was issued, represented as seconds since the Unix epoch.
    - `fingerprint`: The client fingerprint data.

    Parameters
    ----------
    session_id : bytes
    issued_at : int
    fingerprint : FingerprintContext

    Returns
    -------
    bytes
    """
    fingerprint_bytes = default_fingerprint_encoder(fingerprint)
    issued_at_bytes = issued_at.to_bytes(8, "big")
    return session_id + issued_at_bytes + fingerprint_bytes


def create_hmac_token(
    *,
    session_id: bytes,
    options: HmacOptions,
    context: FingerprintContext,
) -> str:
    """
    Generates a complete HMAC token string in the format:
    <version>.<current_key_id>.<payload_b64>.<signature_b64>
    where:
    - `version`: The version of the token format.
    - `current_key_id`: The identifier of the current HMAC key used for signing.
    - `payload_b64`: The base64url-encoded payload containing session ID, issued timestamp, and fingerprint.
    - `signature_b64`: The base64url-encoded HMAC-SHA256 signature of the header and payload.
    Parameters
    ----------
    session_id : bytes
        The unique session identifier (must be 32 bytes).
    options : HmacOptions
        Configuration options for HMAC token generation.
    context : FingerprintContext
        The client fingerprint context.
    Returns
    -------
    str
        The complete HMAC token string.
    Raises
    ------
    ValueError
        If the session_id is not 32 bytes long.
    """

    if len(session_id) != hmac_constants.SESSION_ID_KEY_LENGTH:
        raise ValueError("Session ID must be 32 bytes")

    issued_at = utc_seconds()

    payload = _create_hmac_payload(
        session_id=session_id,
        issued_at=issued_at,
        fingerprint=context,
    )

    encoded_payload = b64url_encode(payload)

    signature = sign_hmac_token(
        key=options.current_key,
        header=options.get_token_header(),
        payload=payload,
    )

    encoded_signature = b64url_encode(signature)
    return f"{options.version}.{options.current_key_id}.{encoded_payload}.{encoded_signature}"


def digest_okay(
    *,
    expected: bytes,
    current: bytes,
) -> bool:
    return hmac.compare_digest(expected, current)


def fingerprint_okay(
    *,
    current: FingerprintContext,
    saved: bytes,
) -> bool:
    current_fp = default_fingerprint_encoder(current)
    return hmac.compare_digest(current_fp, saved)


def get_token_segments(token_str: str) -> HmacTokenSegments:
    """
    Parses an HMAC token string into its components into a named tuple

    Parameters
    ----------
    token_str : str
        _the raw token_

    Returns
    -------
    HmacTokenSegments | None
        _the segments of the token_
    """
    try:
        version, kid, payload_b64, signature_b64 = token_str.split(".")
        return HmacTokenSegments(
            version=version,
            kid=kid,
            payload=b64url_decode(payload_b64),
            signature=b64url_decode(signature_b64),
        )
    except ValueError:
        raise ValueError("Invalid token format")


def payload_length_valid(payload_bytes: bytes) -> bool:
    return len(payload_bytes) <= hmac_constants.TOKEN_MAX_LENGTH


class PayloadParts(NamedTuple):
    session_id: bytes
    issued_at: int
    fingerprint: bytes


def parse_token_payload(payload: bytes) -> PayloadParts:
    """
    Extracts the components of the HMAC token payload.

    Parameters
    ----------
    payload : bytes
        _the raw payload_

    Returns
    -------
    PayloadParts
        _the parts of the payload_
    """
    session_id = payload[hmac_constants.SESSION_ID_PAYLOAD_POSITION]
    issued_at_bytes = payload[hmac_constants.ISSUED_AT_PAYLOAD_POSITION]
    fingerprint = payload[hmac_constants.FINGERPRINT_PAYLOD_POSITION]

    issued_at = int.from_bytes(issued_at_bytes, "big")

    return PayloadParts(
        session_id=session_id,
        issued_at=issued_at,
        fingerprint=fingerprint,
    )

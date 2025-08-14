import secrets
from typing import Annotated, Literal, NamedTuple
from pydantic import BaseModel, Field


from fastapi_seshware.signatures import SignatureAdapter, IdGenerator


class SessionID(NamedTuple):
    unsigned: str
    signed: str


def _default_sid_generator() -> str:
    return secrets.token_urlsafe(32)


class SessionSecurityOptions(BaseModel):
    unauthorized_msg: Annotated[
        str | None,
        Field(
            description="Error message returned when the session is missing.",
            title="Unauthorized Error Message",
        ),
    ] = None

    forbidden_msg: Annotated[
        str | None,
        Field(
            description="Error message returned when the session is invalid.",
            title="Forbidden Error Message",
        ),
    ] = None

    signer: type[SignatureAdapter] = Field(
        ...,
        description="Adapter for signing session IDs.",
        title="ID Signature Adapter",
    )

    secret_key: str | bytes = Field(
        description="Secret key used for signing session IDs.",
        title="Secret Key",
        default_factory=_default_sid_generator,
    )

    key_salt: Annotated[
        str | None,
        Field(
            description="Salt used for key derivation in signing session IDs.",
            title="Key Salt",
        ),
    ] = None

    id_generator: Annotated[
        IdGenerator,
        Field(
            description="Function to generate session IDs.",
            title="ID Generator",
        ),
    ] = _default_sid_generator


SamesiteOptions = Literal["lax", "strict", "none"]


class CookieOptions(BaseModel):
    max_age: Annotated[
        int | None,
        Field(
            description="Max age of the cookie in seconds. If None, the cookie will be a session cookie.",
            title="Max Age",
            ge=0,
        ),
    ] = None

    name: Annotated[
        str,
        Field(
            description="Name of the cookie.",
            title="Cookie Name",
        ),
    ] = "session_id"

    samesite: Annotated[
        SamesiteOptions,
        Field(
            description="SameSite attribute of the cookie.",
            title="SameSite",
        ),
    ] = "lax"
    secure: Annotated[
        bool,
        Field(
            description="Whether the cookie is secure (HTTPS only).",
            title="Secure",
        ),
    ] = True

    httponly: Annotated[
        bool,
        Field(
            description="Whether the cookie is HTTP only (not accessible via JavaScript).",
            title="HTTP Only",
        ),
    ] = True

    domain: Annotated[
        str,
        Field(
            description="Domain for which the cookie is valid. If None, the cookie is valid for the current domain.",
            title="Domain",
        ),
    ] = "/"

    cookie_name: Annotated[
        str,
        Field(
            description="Name of the cookie.",
            title="Cookie Name",
        ),
    ] = "session_id"

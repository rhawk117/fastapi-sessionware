from typing import Literal

from fastapi import HTTPException, Request, Response, status
from fastapi.security import APIKeyCookie
from fastapi_seshware.frontends.base import SessionFrontendOptions
from pydantic import BaseModel, Field

from fastapi_seshware.signers import SignatureResult


class CookieOptions(BaseModel):
    cookie_name: str = Field(
        default="session_id",
        description="Name of the cookie to be used for session storage.",
    )

    max_age: int = Field(
        default=3600,
        description="Maximum age of the cookie in seconds. Defaults to 3600 seconds (1 hour).",
    )

    secure: bool = Field(
        default=True,
        description="Whether the cookie should only be sent over HTTPS. Defaults to True.",
    )

    httponly: bool = Field(
        default=True,
        description="Whether the cookie should be inaccessible to JavaScript. Defaults to True.",
    )

    samesite: Literal["lax", "strict", "none"] = Field(
        default="lax",
        description="SameSite attribute for the cookie. Can be 'lax', 'strict', or 'none'. Defaults to 'lax'.",
    )

    domain: str | None = Field(
        default=None,
        description="Domain for which the cookie is valid. If None, defaults to the request's domain.",
    )


class SessionCookie(APIKeyCookie):
    _DESCRIPTION = (
        "### Session Cookie\n"
        "This cookie is stored on the client side and is used to manage user sessions. "
    )
    _DEFAULT_ERROR_MESSAGE = "Not authenticated, please log in to continue."

    def __init__(
        self,
        options: SessionFrontendOptions,
        *,
        cookie_params: CookieOptions | None = None,
        name: str,
        scheme_name: str | None = None,
        description: str | None = None,
    ) -> None:
        super().__init__(
            name=name,
            scheme_name=scheme_name,
            description=description,
            auto_error=False,
        )
        self._params: CookieOptions = cookie_params or CookieOptions()
        self._options: SessionFrontendOptions = options
        self.fingerprinter = options.request_fingerprinter

    async def __call__(self, request: Request) -> SignatureResult:
        session_cookie = await super().__call__(request)
        if not session_cookie:
            raise self._options.auth_exception()

        context = await self.fingerprinter(request)

        try:
            session_id = self._options.signer.load(
                session_cookie,
                context=context,
                max_age_seconds=self._params.max_age,
            )
            if not session_id:
                raise self._options.auth_exception()
        except Exception:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="This service is currently unavailable. Please try again later.",
            )

        return session_id

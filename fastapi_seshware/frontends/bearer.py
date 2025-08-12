from fastapi import Request
from fastapi.security.http import HTTPBase

from fastapi_seshware.frontends.base import SessionFrontendOptions
from fastapi_seshware.signers import SignatureResult


class SessionIdBearer(HTTPBase):
    def __init__(
        self,
        options: SessionFrontendOptions,
        max_age_seconds: int | None = None,
        *,
        description: str | None = None,
        scheme_name: str | None = None,
    ) -> None:
        super().__init__(
            scheme_name=(scheme_name or self.__class__.__name__),
            scheme="Bearer",
            description=description,
            auto_error=False,
        )
        self._options = options
        self._max_age_seconds = max_age_seconds

    async def __call__(self, request: Request) -> SignatureResult:
        credentials = await super().__call__(request)
        if not credentials or not (session_id := credentials.credentials):
            raise self._options.auth_exception()

        fingerprint = await self._options.request_fingerprinter(request)
        try:
            signature = self._options.signer.load(
                session_id,
                context=fingerprint,
                max_age_seconds=self._max_age_seconds,
            )
            if not signature:
                raise self._options.auth_exception()
        except Exception as e:
            raise self._options.auth_exception() from e

        return signature

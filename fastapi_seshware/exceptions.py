from typing import ClassVar
from fastapi import HTTPException, status


class SeshwareHttpException(HTTPException):
    """
    Base class easy to put in exception handler
    """


class HttpSessionIdMissing(SeshwareHttpException):
    _ERROR_DEFAULT: ClassVar[str] = "You are not authorized to access this resource"

    def __init__(
        self,
        detail: str | None = None,
        model_name: str | None = None,
    ) -> None:
        super().__init__(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=(detail or self._ERROR_DEFAULT),
            headers={
                "WWW-Authenticate": model_name or "Session",
            },
        )


class HttpInvalidSessionId(SeshwareHttpException):
    _ERROR_DEFAULT: ClassVar[str] = "Invalid session ID"

    def __init__(
        self,
        detail: str | None = None,
    ) -> None:
        super().__init__(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=(detail or self._ERROR_DEFAULT),
        )

from fastapi import HTTPException, status


class HttpSessionMissing(HTTPException):
    def __init__(
        self,
        error: str | None = None,
        headers: dict[str, str] | None = None,
    ) -> None:
        message = error or "Not authenticated, please log in to continue."
        super().__init__(status.HTTP_403_FORBIDDEN, message, headers)



from dataclasses import dataclass

from fastapi_seshware.frontends.exception import HttpSessionMissing
from fastapi_seshware.signers import BaseSessionSigner, RequestFingerprint


@dataclass(frozen=True)
class SessionFrontendOptions:
    signer: BaseSessionSigner

    extra_fingerprint_headers: set[str] | None = None
    http_error_message: str | None = None
    http_error_headers: dict[str, str] | None = None
    ip_address_header: str = "X-Forwarded-For"

    @property
    def request_fingerprinter(self) -> RequestFingerprint:
        return RequestFingerprint(
            ip_address_header=self.ip_address_header,
            extra_headers=self.extra_fingerprint_headers,
        )

    def auth_exception(self) -> HttpSessionMissing:
        return HttpSessionMissing(
            error=self.http_error_message,
            headers=self.http_error_headers,
        )

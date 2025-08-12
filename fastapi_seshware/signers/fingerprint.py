from dataclasses import dataclass, field
import ipaddress
import hashlib
from fastapi import Request


def get_network_prefix(
    ip_address: str,
    *,
    v4_prefix: int = 24,
    v6_prefix: int = 64,
) -> str:
    try:
        addr = ipaddress.ip_address(ip_address)
        if addr.version == 4:
            network = ipaddress.ip_network(f"{ip_address}/{v4_prefix}", strict=False)
        else:
            network = ipaddress.ip_network(f"{ip_address}/{v6_prefix}", strict=False)
    except Exception:
        return "unknown"

    return str(network)


@dataclass(frozen=True)
class FingerprintContext:
    user_agent: str | None
    ip_address: str | None
    extra: dict[str, str | None] = field(default_factory=dict)


class RequestFingerprint:
    def __init__(
        self,
        *,
        ip_address_header: str = "X-Forwarded-For",
        extra_headers: set[str] | None = None,
    ) -> None:
        self.ip_addr_header: str = ip_address_header
        self.extra_headers: set[str] | None = extra_headers

    async def __call__(self, request: Request) -> FingerprintContext:
        user_agent = request.headers.get("User-Agent", None)
        ip_header_val = request.headers.get(self.ip_addr_header, None)

        if ip_header_val is not None:
            ip_header_val = ip_header_val.split(",")[0].strip()
        elif request.client:
            ip_header_val = request.client.host

        context = FingerprintContext(
            user_agent=user_agent,
            ip_address=ip_header_val,
        )

        if self.extra_headers:
            for header in self.extra_headers:
                context.extra[header] = request.headers.get(header, None)

        return context


def default_fingerprint_encoder(context: FingerprintContext) -> bytes:
    hashed = hashlib.blake2b(digest_size=32)
    hashed.update((context.user_agent or "").encode("utf-8"))
    hashed.update(b"|")
    ip_addr = context.ip_address or "unknown"
    hashed.update(get_network_prefix(ip_addr).encode("utf-8"))

    return hashed.digest()

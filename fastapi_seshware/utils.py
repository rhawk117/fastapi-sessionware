import base64
import time


def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_decode(string: str) -> bytes:
    padding = "=" * ((4 - len(string) % 4) % 4)
    return base64.urlsafe_b64decode((string + padding).encode("ascii"))


def utc_seconds() -> int:
    return int(time.time())

from __future__ import annotations

from dataclasses import dataclass

_SESSION_LIKE_MARKERS = ("session", "sess", "sid", "auth", "token", "jwt")
_CSRF_COOKIE_NAMES = frozenset({"csrftoken", "xsrf-token", "csrf-token"})


@dataclass(frozen=True, slots=True)
class ParsedCookie:
    name: str
    has_secure: bool
    has_httponly: bool
    samesite_value: str | None


def parse_cookie(raw_header: str) -> ParsedCookie:
    parts = raw_header.split(";")
    name_value = parts[0].strip()
    name = name_value.split("=", 1)[0].strip()

    has_secure = False
    has_httponly = False
    samesite_value: str | None = None

    for part in parts[1:]:
        attr = part.strip()
        attr_lower = attr.lower()

        if attr_lower == "secure":
            has_secure = True
        elif attr_lower == "httponly":
            has_httponly = True
        elif attr_lower.startswith("samesite="):
            samesite_value = attr.split("=", 1)[1].strip()

    return ParsedCookie(
        name=name,
        has_secure=has_secure,
        has_httponly=has_httponly,
        samesite_value=samesite_value,
    )


def is_session_like_cookie(name: str) -> bool:
    lower_name = name.lower()
    if lower_name in _CSRF_COOKIE_NAMES:
        return False
    return any(marker in lower_name for marker in _SESSION_LIKE_MARKERS)


__all__ = [
    "ParsedCookie",
    "is_session_like_cookie",
    "parse_cookie",
]

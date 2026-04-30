"""Shared scope-phrase helper for Apache rule messages.

Multiple Apache rules embed a short natural-language description of the
context a directive was seen in (``"in the global scope"``, ``"inside a
'<Directory ...>' block"``…) into their ``Finding.description``.  Keeping
one table here avoids per-rule drift when the wording is refined and
makes it obvious which rules should be updated together.
"""

from __future__ import annotations

_SCOPE_PHRASES: dict[str, str] = {
    "global": "in the global scope",
    "virtualhost": "in a VirtualHost scope",
    "directory": "inside a '<Directory ...>' block",
    "location": "inside a '<Location ...>' block",
}


def scope_phrase(context_name: str) -> str:
    """Return the human-readable phrase for *context_name* used in Apache rules."""
    return _SCOPE_PHRASES.get(context_name, "in the effective Apache config")


__all__ = ["scope_phrase"]

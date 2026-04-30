"""Shared helpers for IIS rules."""

from __future__ import annotations

from webconf_audit.local.iis.effective import IISEffectiveSection
from webconf_audit.local.iis.parser import IISConfigDocument, IISSection
from webconf_audit.models import SourceLocation

_MAX_CONTENT_LENGTH_THRESHOLD = 30_000_000  # IIS default (~28.6 MB)

_WEBDAV_MODULES = frozenset({"webdav"})

_DANGEROUS_HANDLERS = frozenset({"cgimodule"})

_EXPOSE_SERVER_HEADERS = ("x-powered-by", "x-aspnetmvc-version")

_OTHER_AUTH_SUFFIXES = (
    ("/basicAuthentication", "basic"),
    ("/windowsAuthentication", "Windows"),
    ("/digestAuthentication", "digest"),
)


def effective_location(section: IISEffectiveSection) -> SourceLocation:
    """Build a SourceLocation from an effective section."""
    src = section.source
    return SourceLocation(
        mode="local",
        kind="xml",
        file_path=src.file_path,
        xml_path=src.xml_path,
    )


def raw_location(section: IISSection) -> SourceLocation:
    """Build a SourceLocation from a raw IISSection."""
    return SourceLocation(
        mode="local",
        kind="xml",
        file_path=section.source.file_path,
        xml_path=section.source.xml_path,
    )


def file_location(doc: IISConfigDocument) -> SourceLocation:
    """Build a file-level SourceLocation from a document."""
    return SourceLocation(mode="local", kind="xml", file_path=doc.file_path)


def location_context(section: IISEffectiveSection) -> str:
    """Return human-readable location context suffix."""
    if section.location_path:
        return f' (at location path "{section.location_path}")'
    return ""


def is_pure_inheritance(section: IISEffectiveSection) -> bool:
    """Return True if this location section purely inherits without override.

    A location-scoped effective section is purely inherited when none of
    its ``origin_chain`` entries come from a ``<location path="...">``
    block.  We detect this by checking whether the XML path contains the
    ``location[@path=`` fragment produced by the IIS parser.

    This is a heuristic tied to the parser's XML-path format.  If the
    path format changes, this check must be updated accordingly.
    """
    if section.location_path is None:
        return False
    return not any(
        origin.xml_path and "location[@path=" in origin.xml_path.lower()
        for origin in section.origin_chain
    )


def has_https_binding(doc: IISConfigDocument) -> bool:
    """Return True if any parsed section contains an HTTPS binding."""
    for section in doc.sections:
        if section.tag != "bindings":
            continue
        for child in section.children:
            if child.tag.lower() != "binding":
                continue
            protocol = child.attributes.get("protocol", "").lower()
            binding_info = child.attributes.get("bindingInformation", "")
            if protocol == "https" or ":443:" in binding_info:
                return True
    return False


__all__ = [
    "_DANGEROUS_HANDLERS",
    "_EXPOSE_SERVER_HEADERS",
    "_MAX_CONTENT_LENGTH_THRESHOLD",
    "_OTHER_AUTH_SUFFIXES",
    "_WEBDAV_MODULES",
    "effective_location",
    "file_location",
    "has_https_binding",
    "is_pure_inheritance",
    "location_context",
    "raw_location",
]

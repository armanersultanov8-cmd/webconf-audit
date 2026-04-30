"""IIS config → NormalizedConfig mapper.

IIS TLS protocol configuration lives in the Windows registry, not in
``web.config`` / ``applicationHost.config``.  The normalizer extracts
``sslFlags`` from ``system.webServer/security/access`` and HTTPS bindings,
but leaves ``protocols`` as ``None`` (unknown).
"""

from __future__ import annotations

import logging

from webconf_audit.local.iis.effective import IISEffectiveConfig, IISEffectiveSection
from webconf_audit.local.iis.parser import IISConfigDocument, IISSourceRef
from webconf_audit.local.normalized import (
    NormalizedAccessPolicy,
    NormalizedConfig,
    NormalizedListenPoint,
    NormalizedScope,
    NormalizedSecurityHeader,
    NormalizedTLS,
    SourceRef,
)

_SECURITY_HEADERS = frozenset({
    "strict-transport-security",
    "x-frame-options",
    "x-content-type-options",
    "x-xss-protection",
    "content-security-policy",
    "referrer-policy",
    "permissions-policy",
})

# Section path suffixes used during extraction.
_ACCESS_SUFFIX = "/access"
_CUSTOM_HEADERS_SUFFIX = "/customHeaders"
_DIR_BROWSE_SUFFIX = "/directoryBrowse"
_HTTP_ERRORS_SUFFIX = "/httpErrors"
_COMPILATION_SUFFIX = "/compilation"
_HTTP_RUNTIME_SUFFIX = "/httpRuntime"

_logger = logging.getLogger(__name__)


def normalize_iis(
    doc: IISConfigDocument,
    effective_config: IISEffectiveConfig | None = None,
) -> NormalizedConfig:
    """Extract normalized entities from IIS config."""
    if effective_config is None:
        _logger.debug(
            "IIS normalizer: effective_config is None for %s, "
            "returning empty NormalizedConfig",
            doc.file_path,
        )
        return NormalizedConfig(server_type="iis")

    scopes: list[NormalizedScope] = []

    # Global scope
    global_scope = _build_scope(
        effective_config.global_sections,
        scope_name="global",
        doc=doc,
    )
    scopes.append(global_scope)

    # Location scopes
    for loc_path, sections in effective_config.location_sections.items():
        scope = _build_scope(sections, scope_name=loc_path, doc=doc)
        scopes.append(scope)

    return NormalizedConfig(server_type="iis", scopes=scopes)


# -- scope builder -----------------------------------------------------------


def _build_scope(
    sections: dict[str, IISEffectiveSection],
    scope_name: str | None,
    doc: IISConfigDocument,
) -> NormalizedScope:
    listen_points = _extract_listen_points(doc)
    tls = _extract_tls(sections)
    headers = _extract_security_headers(sections)
    access_policy = _extract_access_policy(sections)

    return NormalizedScope(
        scope_name=scope_name,
        listen_points=listen_points,
        tls=tls,
        security_headers=headers,
        access_policy=access_policy,
    )


# -- listen points -----------------------------------------------------------


def _extract_listen_points(doc: IISConfigDocument) -> list[NormalizedListenPoint]:
    """Extract listen points from IIS bindings if available.

    Bindings are typically in ``system.applicationHost/sites`` inside
    ``applicationHost.config``.  For ``web.config`` there are usually no
    bindings — return empty list.
    """
    points: list[NormalizedListenPoint] = []
    for section in doc.sections:
        if section.tag != "site":
            continue
        for child in section.children:
            if child.tag != "binding":
                continue
            info = child.attributes.get("bindingInformation", "")
            protocol = child.attributes.get("protocol", "http").lower()
            lp = _parse_binding(info, protocol, child.source)
            if lp is not None:
                points.append(lp)
    return points


def _parse_binding(
    info: str,
    protocol: str,
    source: IISSourceRef,
) -> NormalizedListenPoint | None:
    """Parse ``*:443:hostname`` binding info."""
    parts = info.split(":")
    if len(parts) < 2:
        return None

    address = parts[0] if parts[0] != "*" else None
    try:
        port = int(parts[1])
    except ValueError:
        return None

    is_https = protocol == "https"
    return NormalizedListenPoint(
        port=port,
        protocol=protocol,
        tls=is_https,
        source=_ref(source),
        address=address,
    )


# -- TLS --------------------------------------------------------------------


def _extract_tls(
    sections: dict[str, IISEffectiveSection],
) -> NormalizedTLS | None:
    access = sections.get(_ACCESS_SUFFIX)
    if access is None:
        return None

    ssl_flags = access.attributes.get("sslFlags", "").lower()
    if not ssl_flags:
        return None

    require_ssl = "ssl" in ssl_flags

    return NormalizedTLS(
        source=_ref(access.source),
        protocols=None,  # Unknown — IIS TLS protocols live in the registry
        ciphers=None,
        require_ssl=require_ssl,
    )


# -- security headers -------------------------------------------------------


def _extract_security_headers(
    sections: dict[str, IISEffectiveSection],
) -> list[NormalizedSecurityHeader]:
    custom = sections.get(_CUSTOM_HEADERS_SUFFIX)
    if custom is None:
        return []

    headers: list[NormalizedSecurityHeader] = []
    for child in custom.children:
        if child.tag != "add":
            continue
        name = child.attributes.get("name", "").lower()
        if name in _SECURITY_HEADERS:
            value = child.attributes.get("value")
            headers.append(
                NormalizedSecurityHeader(
                    name=name,
                    value=value,
                    source=_ref(child.source),
                )
            )
    return headers


# -- access policy -----------------------------------------------------------


def _extract_access_policy(
    sections: dict[str, IISEffectiveSection],
) -> NormalizedAccessPolicy | None:
    dir_browse = sections.get(_DIR_BROWSE_SUFFIX)
    compilation = sections.get(_COMPILATION_SUFFIX)
    http_runtime = sections.get(_HTTP_RUNTIME_SUFFIX)

    dir_listing = _boolean_attribute(dir_browse, "enabled")
    debug = _boolean_attribute(compilation, "debug")
    disclosed = _version_header_disclosure(http_runtime)

    if dir_listing is None and debug is None and disclosed is None:
        return None

    anchor = dir_browse or compilation or http_runtime
    if anchor is None:
        return None
    return NormalizedAccessPolicy(
        source=_ref(anchor.source),
        directory_listing=dir_listing,
        server_identification_disclosed=disclosed,
        debug_mode=debug,
    )


def _boolean_attribute(
    section: IISEffectiveSection | None,
    attribute_name: str,
) -> bool | None:
    if section is None:
        return None
    return section.attributes.get(attribute_name, "").strip().lower() == "true"


def _version_header_disclosure(
    section: IISEffectiveSection | None,
) -> bool | None:
    if section is None:
        return None

    value = section.attributes.get("enableVersionHeader", "").strip().lower()
    if not value:
        return None
    return value == "true"


# -- helpers -----------------------------------------------------------------


def _ref(source: IISSourceRef) -> SourceRef:
    return SourceRef(
        server_type="iis",
        file_path=source.file_path or "",
        line=source.line,
        xml_path=source.xml_path,
    )


__all__ = ["normalize_iis"]

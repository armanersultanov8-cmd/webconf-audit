"""Lighttpd AST/effective-config to NormalizedConfig mapper."""

from __future__ import annotations

import re

from webconf_audit.local.lighttpd.effective import (
    LighttpdConditionalScope,
    LighttpdEffectiveConfig,
    LighttpdEffectiveDirective,
)
from webconf_audit.local.lighttpd.parser import (
    LighttpdAssignmentNode,
    LighttpdConfigAst,
    LighttpdSourceSpan,
)
from webconf_audit.local.normalized import (
    NormalizedAccessPolicy,
    NormalizedConfig,
    NormalizedListenPoint,
    NormalizedScope,
    NormalizedSecurityHeader,
    NormalizedTLS,
    SourceRef,
)
from webconf_audit.local.lighttpd.rules.rule_utils import (
    iter_all_nodes,
    unquote,
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


def normalize_lighttpd(
    config_ast: LighttpdConfigAst,
    effective_config: LighttpdEffectiveConfig | None = None,
    merged_directives: dict[str, LighttpdEffectiveDirective] | None = None,
) -> NormalizedConfig:
    """Extract normalized entities from Lighttpd config.

    When *merged_directives* is provided (host-filtered view), normalize
    from that single flat dict instead of walking all conditional scopes.
    """
    scopes: list[NormalizedScope] = []

    if merged_directives is not None:
        # Host-filtered: single merged scope.
        scope = _normalize_merged_directives(merged_directives, config_ast)
        scopes.append(scope)
    elif effective_config is not None:
        global_scope = _normalize_effective_global(effective_config, config_ast)
        scopes.append(global_scope)

        for cond_scope in effective_config.conditional_scopes:
            scope = _normalize_conditional_scope(cond_scope, config_ast)
            scopes.append(scope)
    else:
        # Fallback: scan raw AST.
        global_scope = _normalize_from_ast(config_ast)
        scopes.append(global_scope)

    return NormalizedConfig(server_type="lighttpd", scopes=scopes)


# -- merged directives (host-filtered) --------------------------------------


def _normalize_merged_directives(
    merged: dict[str, LighttpdEffectiveDirective],
    ast: LighttpdConfigAst,
) -> NormalizedScope:
    """Build a single normalized scope from host-filtered merged directives."""
    tls = _tls_from_directives(merged)
    headers = _headers_from_directives(merged)
    access_policy = _access_from_directives(merged)

    # Listen points from merged directives.
    port_dir = merged.get("server.port")
    bind_dir = merged.get("server.bind")
    ssl_dir = merged.get("ssl.engine")

    port = 80
    if port_dir:
        try:
            port = int(unquote(port_dir.value))
        except ValueError:
            pass

    address = unquote(bind_dir.value) if bind_dir else None
    has_ssl = ssl_dir is not None and unquote(ssl_dir.value).lower() == "enable"
    source = _ref_from_span(
        port_dir.source if port_dir else _default_span(ast),
    )

    return NormalizedScope(
        scope_name="merged",
        listen_points=[
            NormalizedListenPoint(
                port=port, protocol="https" if has_ssl else "http",
                tls=has_ssl, source=source, address=address,
            ),
        ],
        tls=tls,
        security_headers=headers,
        access_policy=access_policy,
    )


def _headers_from_directives(
    directives: dict[str, LighttpdEffectiveDirective],
) -> list[NormalizedSecurityHeader]:
    """Extract security headers from setenv.add-response-header in merged directives."""
    d = directives.get("setenv.add-response-header")
    if d is None:
        return []
    raw = unquote(d.value)
    return _parse_header_tuple(raw, d.source)


# -- global scope from effective config -------------------------------------


def _normalize_effective_global(
    eff: LighttpdEffectiveConfig,
    ast: LighttpdConfigAst,
) -> NormalizedScope:
    listen_points = _listen_from_global(eff, ast)
    tls = _tls_from_directives(eff.global_directives)
    headers = _headers_from_ast(ast)
    access_policy = _access_from_directives(eff.global_directives)

    return NormalizedScope(
        scope_name="global",
        listen_points=listen_points,
        tls=tls,
        security_headers=headers,
        access_policy=access_policy,
    )


# -- conditional scope ------------------------------------------------------


def _normalize_conditional_scope(
    cond: LighttpdConditionalScope,
    ast: LighttpdConfigAst,
) -> NormalizedScope:
    tls = _tls_from_directives(cond.directives)
    access_policy = _access_from_directives(cond.directives)

    # Listen point from $SERVER["socket"] == ":443" style conditions.
    listen_points: list[NormalizedListenPoint] = []
    if cond.condition and cond.condition.variable.lower() == '$server["socket"]':
        lp = _parse_socket_condition(cond)
        if lp is not None:
            listen_points.append(lp)

    return NormalizedScope(
        scope_name=cond.header or None,
        listen_points=listen_points,
        tls=tls,
        security_headers=[],  # Headers are global in lighttpd
        access_policy=access_policy,
    )


# -- listen points -----------------------------------------------------------


def _listen_from_global(
    eff: LighttpdEffectiveConfig,
    ast: LighttpdConfigAst,
) -> list[NormalizedListenPoint]:
    port_dir = eff.get_global("server.port")
    bind_dir = eff.get_global("server.bind")
    ssl_dir = eff.get_global("ssl.engine")

    port = 80
    if port_dir:
        try:
            port = int(unquote(port_dir.value))
        except ValueError:
            pass

    address = unquote(bind_dir.value) if bind_dir else None
    has_ssl = ssl_dir is not None and unquote(ssl_dir.value).lower() == "enable"

    source = _ref_from_span(
        port_dir.source if port_dir else _default_span(ast),
    )

    return [
        NormalizedListenPoint(
            port=port,
            protocol="https" if has_ssl else "http",
            tls=has_ssl,
            source=source,
            address=address,
        )
    ]


def _parse_socket_condition(
    cond: LighttpdConditionalScope,
) -> NormalizedListenPoint | None:
    """Parse ``$SERVER["socket"] == ":443"`` into a listen point."""
    if cond.condition is None:
        return None

    raw = unquote(cond.condition.value)
    # Patterns: ":443", "0.0.0.0:443"
    match = re.match(r"^(?:(.*):)?(\d+)$", raw)
    if not match:
        return None

    addr = match.group(1) or None
    port = int(match.group(2))
    # Detect TLS from ssl.engine in this scope.
    ssl_dir = cond.directives.get("ssl.engine")
    has_ssl = ssl_dir is not None and unquote(ssl_dir.value).lower() == "enable"

    source_span = ssl_dir.source if ssl_dir else LighttpdSourceSpan()
    return NormalizedListenPoint(
        port=port,
        protocol="https" if has_ssl else "http",
        tls=has_ssl,
        source=_ref_from_span(source_span),
        address=addr,
    )


# -- TLS --------------------------------------------------------------------


def _tls_from_directives(
    directives: dict[str, LighttpdEffectiveDirective],
) -> NormalizedTLS | None:
    ssl_engine = directives.get("ssl.engine")
    ssl_pemfile = directives.get("ssl.pemfile")
    ssl_cipher = directives.get("ssl.cipher-list")

    if not any([ssl_engine, ssl_pemfile, ssl_cipher]):
        return None

    anchor = ssl_engine or ssl_pemfile or ssl_cipher
    if anchor is None:
        return None

    is_on = ssl_engine is not None and unquote(ssl_engine.value).lower() == "enable"

    # Lighttpd does not have a simple "ssl_protocols" directive.
    # Protocol config is via ssl.openssl.ssl-conf-cmd or legacy ssl.use-sslv* flags.
    # We leave protocols as None (unknown) for best-effort skip.
    ciphers = unquote(ssl_cipher.value) if ssl_cipher else None
    cert = unquote(ssl_pemfile.value) if ssl_pemfile else None

    return NormalizedTLS(
        source=_ref_from_span(anchor.source),
        protocols=None,  # Unknown - best-effort skip in universal rules
        ciphers=ciphers,
        certificate=cert,
        require_ssl=is_on if ssl_engine else None,
    )


# -- security headers -------------------------------------------------------


def _headers_from_ast(ast: LighttpdConfigAst) -> list[NormalizedSecurityHeader]:
    """Extract security headers from setenv.add-response-header assignments."""
    headers: list[NormalizedSecurityHeader] = []

    for node in iter_all_nodes(ast):
        if not isinstance(node, LighttpdAssignmentNode):
            continue
        if node.name != "setenv.add-response-header":
            continue
        raw = unquote(node.value)
        headers.extend(_parse_header_tuple(raw, node.source))

    return headers


def _parse_header_tuple(
    raw: str,
    source: LighttpdSourceSpan,
) -> list[NormalizedSecurityHeader]:
    """Parse ``( "Name" => "Value", ... )`` into NormalizedSecurityHeaders."""
    results: list[NormalizedSecurityHeader] = []
    # Strip outer parens.
    stripped = raw.strip()
    if stripped.startswith("(") and stripped.endswith(")"):
        stripped = stripped[1:-1]

    for pair in _split_tuple_items(stripped):
        if "=>" not in pair:
            continue
        key, _, val = pair.partition("=>")
        name = key.strip().strip('"').strip("'").lower()
        value = val.strip().strip('"').strip("'")
        if name in _SECURITY_HEADERS:
            results.append(
                NormalizedSecurityHeader(
                    name=name,
                    value=value or None,
                    source=_ref_from_span(source),
                )
            )
    return results


def _split_tuple_items(raw: str) -> list[str]:
    items: list[str] = []
    current: list[str] = []
    quote: str | None = None
    escaped = False

    for char in raw:
        if escaped:
            current.append(char)
            escaped = False
            continue
        if char == "\\":
            current.append(char)
            escaped = True
            continue
        if quote is not None:
            current.append(char)
            if char == quote:
                quote = None
            continue
        if char in {'"', "'"}:
            current.append(char)
            quote = char
            continue
        if char == ",":
            items.append("".join(current))
            current = []
            continue
        current.append(char)

    if current or raw.endswith(","):
        items.append("".join(current))

    return items


# -- access policy -----------------------------------------------------------


def _access_from_directives(
    directives: dict[str, LighttpdEffectiveDirective],
) -> NormalizedAccessPolicy | None:
    dir_listing = directives.get("dir-listing.activate")
    server_tag = directives.get("server.tag")

    if dir_listing is None and server_tag is None:
        return None

    listing: bool | None = None
    if dir_listing:
        listing = unquote(dir_listing.value).lower() == "enable"

    disclosed: bool | None = None
    if server_tag:
        tag_val = unquote(server_tag.value)
        # Empty string = blanked out = not disclosed.
        disclosed = bool(tag_val)

    anchor = dir_listing or server_tag
    if anchor is None:
        return None
    return NormalizedAccessPolicy(
        source=_ref_from_span(anchor.source),
        directory_listing=listing,
        server_identification_disclosed=disclosed,
    )


# -- fallback AST scan ------------------------------------------------------


def _normalize_from_ast(ast: LighttpdConfigAst) -> NormalizedScope:
    """Minimal fallback when effective config is not available."""
    headers = _headers_from_ast(ast)
    return NormalizedScope(
        scope_name="global",
        security_headers=headers,
    )


# -- helpers -----------------------------------------------------------------


def _ref_from_span(span: LighttpdSourceSpan) -> SourceRef:
    return SourceRef(
        server_type="lighttpd",
        file_path=span.file_path or "",
        line=span.line,
    )


def _default_span(ast: LighttpdConfigAst) -> LighttpdSourceSpan:
    if ast.main_file_path:
        return LighttpdSourceSpan(file_path=ast.main_file_path, line=1)
    if ast.nodes:
        return ast.nodes[0].source
    return LighttpdSourceSpan()


__all__ = ["normalize_lighttpd"]

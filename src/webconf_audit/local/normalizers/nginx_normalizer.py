"""Nginx AST → NormalizedConfig mapper."""

from __future__ import annotations

import logging

from webconf_audit.local.nginx.parser.ast import (
    BlockNode,
    ConfigAst,
    DirectiveNode,
    find_child_directives,
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

_SECURITY_HEADERS = frozenset({
    "strict-transport-security",
    "x-frame-options",
    "x-content-type-options",
    "x-xss-protection",
    "content-security-policy",
    "referrer-policy",
    "permissions-policy",
})


_logger = logging.getLogger(__name__)


def normalize_nginx(config_ast: ConfigAst) -> NormalizedConfig:
    """Extract normalized entities from Nginx AST."""
    scopes: list[NormalizedScope] = []

    has_http_block = False
    for node in config_ast.nodes:
        if isinstance(node, BlockNode) and node.name == "http":
            has_http_block = True
            for child in node.children:
                if isinstance(child, BlockNode) and child.name == "server":
                    scopes.append(_normalize_server_block(child))

    if not has_http_block:
        _logger.debug(
            "Nginx normalizer: no 'http' block found in config, "
            "returning empty NormalizedConfig",
        )

    return NormalizedConfig(server_type="nginx", scopes=scopes)


# -- server block -----------------------------------------------------------


def _normalize_server_block(server: BlockNode) -> NormalizedScope:
    listen_points = _extract_listen_points(server)
    has_tls = any(lp.tls for lp in listen_points)

    server_names = find_child_directives(server, "server_name")
    scope_name = server_names[0].args[0] if server_names and server_names[0].args else None

    tls = _extract_tls(server) if has_tls else None
    headers = _extract_security_headers(server)
    access_policy = _extract_access_policy(server)

    return NormalizedScope(
        scope_name=scope_name,
        listen_points=listen_points,
        tls=tls,
        security_headers=headers,
        access_policy=access_policy,
    )


# -- listen ------------------------------------------------------------------


def _extract_listen_points(server: BlockNode) -> list[NormalizedListenPoint]:
    points: list[NormalizedListenPoint] = []
    for directive in find_child_directives(server, "listen"):
        lp = _parse_listen_directive(directive)
        if lp is not None:
            points.append(lp)
    return points


def _parse_listen_directive(directive: DirectiveNode) -> NormalizedListenPoint | None:
    if not directive.args:
        return None

    addr_arg = directive.args[0]
    has_ssl = "ssl" in directive.args

    address, port = _parse_listen_address(addr_arg, has_ssl)

    ref = _source_ref(directive)
    return NormalizedListenPoint(
        port=port,
        protocol="https" if has_ssl else "http",
        tls=has_ssl,
        source=ref,
        address=address,
    )


def _parse_listen_address(addr_arg: str, has_ssl: bool) -> tuple[str | None, int]:
    """Parse an addr_arg like '443', '0.0.0.0:443', '[::]:80', '*:8080'."""
    default_port = 443 if has_ssl else 80

    # Pure port number
    if addr_arg.isdigit():
        return None, int(addr_arg)

    # IPv6 [::]:port
    if addr_arg.startswith("["):
        bracket_end = addr_arg.find("]")
        if bracket_end == -1:
            return None, default_port
        ipv6_addr = addr_arg[: bracket_end + 1]
        rest = addr_arg[bracket_end + 1 :]
        if rest.startswith(":") and rest[1:].isdigit():
            return ipv6_addr, int(rest[1:])
        return ipv6_addr, default_port

    # addr:port or just addr
    if ":" in addr_arg:
        parts = addr_arg.rsplit(":", 1)
        if parts[1].isdigit():
            return parts[0] or None, int(parts[1])
        return addr_arg, default_port

    # Could be a bare hostname or unix socket — treat as address, default port
    return addr_arg, default_port


# -- TLS --------------------------------------------------------------------


def _extract_tls(server: BlockNode) -> NormalizedTLS | None:
    protocols_directive, ciphers_directive, cert_directive, key_directive = (
        _tls_directives(server)
    )
    anchor = _first_present_directive(
        protocols_directive,
        ciphers_directive,
        cert_directive,
        key_directive,
    )
    if anchor is None:
        return NormalizedTLS(source=_tls_fallback_source(server))

    return NormalizedTLS(
        source=_source_ref(anchor),
        protocols=_directive_args(protocols_directive),
        ciphers=_directive_first_arg(ciphers_directive),
        certificate=_directive_first_arg(cert_directive),
        certificate_key=_directive_first_arg(key_directive),
    )


# -- security headers -------------------------------------------------------


def _extract_security_headers(server: BlockNode) -> list[NormalizedSecurityHeader]:
    headers: list[NormalizedSecurityHeader] = []
    for directive in find_child_directives(server, "add_header"):
        if not directive.args:
            continue
        name_lower = directive.args[0].lower()
        if name_lower in _SECURITY_HEADERS:
            value = directive.args[1] if len(directive.args) >= 2 else None
            headers.append(
                NormalizedSecurityHeader(
                    name=name_lower,
                    value=value,
                    source=_source_ref(directive),
                )
            )
    return headers


# -- access policy -----------------------------------------------------------


def _extract_access_policy(server: BlockNode) -> NormalizedAccessPolicy | None:
    autoindex = _last_child_directive(server, "autoindex")
    server_tokens = _last_child_directive(server, "server_tokens")

    dir_listing: bool | None = None
    if autoindex and autoindex.args:
        dir_listing = autoindex.args[0].lower() == "on"

    sig_disclosed: bool | None = None
    if server_tokens and server_tokens.args:
        sig_disclosed = server_tokens.args[0].lower() != "off"

    if dir_listing is None and sig_disclosed is None:
        return None

    # Anchor to the most specific triggering directive for traceability.
    anchor = autoindex or server_tokens
    source = _source_ref(anchor) if anchor else _source_ref_block(server)
    return NormalizedAccessPolicy(
        source=source,
        directory_listing=dir_listing,
        server_identification_disclosed=sig_disclosed,
    )


# -- helpers -----------------------------------------------------------------


def _first_ssl_listen(server: BlockNode) -> DirectiveNode | None:
    """Return the first ``listen`` directive that contains ``ssl``."""
    for d in find_child_directives(server, "listen"):
        if "ssl" in d.args:
            return d
    return None


def _tls_directives(
    server: BlockNode,
) -> tuple[
    DirectiveNode | None,
    DirectiveNode | None,
    DirectiveNode | None,
    DirectiveNode | None,
]:
    return (
        _last_child_directive(server, "ssl_protocols"),
        _last_child_directive(server, "ssl_ciphers"),
        _last_child_directive(server, "ssl_certificate"),
        _last_child_directive(server, "ssl_certificate_key"),
    )


def _first_present_directive(
    *directives: DirectiveNode | None,
) -> DirectiveNode | None:
    for directive in directives:
        if directive is not None:
            return directive
    return None


def _tls_fallback_source(server: BlockNode) -> SourceRef:
    ssl_listen = _first_ssl_listen(server)
    if ssl_listen is not None:
        return _source_ref(ssl_listen)
    return _source_ref_block(server)


def _directive_args(directive: DirectiveNode | None) -> list[str] | None:
    if directive is None:
        return None
    return directive.args or None


def _directive_first_arg(directive: DirectiveNode | None) -> str | None:
    if directive is None or not directive.args:
        return None
    return directive.args[0]


def _last_child_directive(block: BlockNode, name: str) -> DirectiveNode | None:
    directives = find_child_directives(block, name)
    return directives[-1] if directives else None


def _source_ref(node: DirectiveNode) -> SourceRef:
    return SourceRef(
        server_type="nginx",
        file_path=node.source.file_path or "",
        line=node.source.line,
    )


def _source_ref_block(block: BlockNode) -> SourceRef:
    return SourceRef(
        server_type="nginx",
        file_path=block.source.file_path or "",
        line=block.source.line,
    )


__all__ = ["normalize_nginx"]

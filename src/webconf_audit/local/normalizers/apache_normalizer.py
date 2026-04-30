"""Apache AST / effective-config -> NormalizedConfig mapper."""

from __future__ import annotations

from pathlib import Path

from webconf_audit.local.apache.effective import (
    ApacheVirtualHostContext,
    DirectiveOrigin,
    EffectiveDirective,
    build_effective_config,
    build_server_effective_config,
    extract_document_root,
    extract_virtualhost_contexts,
)
from webconf_audit.local.apache.parser import (
    ApacheBlockNode,
    ApacheConfigAst,
    ApacheDirectiveNode,
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

_SECURITY_HEADERS = frozenset(
    {
        "strict-transport-security",
        "x-frame-options",
        "x-content-type-options",
        "x-xss-protection",
        "content-security-policy",
        "referrer-policy",
        "permissions-policy",
    }
)

_TRANSPARENT_WRAPPER_BLOCKS = frozenset(
    {"if", "ifdefine", "ifmodule", "ifversion", "else", "elseif"}
)


def normalize_apache(
    config_ast: ApacheConfigAst,
    effective_config: dict[str, object] | None = None,
) -> NormalizedConfig:
    """Extract normalized entities from Apache AST and effective config helpers."""
    config_dir = _config_dir_from_effective_input(effective_config)
    virtualhosts = extract_virtualhost_contexts(config_ast)

    scopes = _server_scopes(config_ast, virtualhosts)
    scopes.extend(_directory_scopes(config_ast, config_dir))
    scopes.extend(_location_scopes(config_ast, virtualhosts, config_dir))
    return NormalizedConfig(server_type="apache", scopes=scopes)


def _server_scopes(
    config_ast: ApacheConfigAst,
    virtualhosts: list[ApacheVirtualHostContext],
) -> list[NormalizedScope]:
    if not virtualhosts:
        return _global_scopes(config_ast)
    return _virtualhost_scopes(config_ast, virtualhosts)


def _global_scopes(config_ast: ApacheConfigAst) -> list[NormalizedScope]:
    global_effective = build_server_effective_config(config_ast)
    global_scope = _normalize_effective_scope(
        global_effective.directives,
        scope_name="global",
        include_listen_points=True,
    )
    return [global_scope] if _scope_has_content(global_scope) else []


def _virtualhost_scopes(
    config_ast: ApacheConfigAst,
    virtualhosts: list[ApacheVirtualHostContext],
) -> list[NormalizedScope]:
    scopes: list[NormalizedScope] = []
    for context in virtualhosts:
        vh_effective = build_server_effective_config(
            config_ast,
            virtualhost_context=context,
        )
        vh_scope = _normalize_effective_scope(
            vh_effective.directives,
            scope_name=_virtualhost_scope_name(context),
            include_listen_points=True,
        )
        if _scope_has_content(vh_scope):
            scopes.append(vh_scope)
    return scopes


def _directory_scopes(
    config_ast: ApacheConfigAst,
    config_dir: Path | None,
) -> list[NormalizedScope]:
    scopes: list[NormalizedScope] = []
    for block, context in _iter_directory_blocks_with_virtualhost(
        config_ast.nodes,
        current_virtualhost=None,
    ):
        directory_path = _resolve_directory_path(block, config_dir)
        if directory_path is None:
            continue

        directory_effective = build_effective_config(
            config_ast,
            str(directory_path),
            config_dir=config_dir,
            virtualhost_context=context,
        )
        scope = _normalize_effective_scope(
            directory_effective.directives,
            scope_name=_directory_scope_name(directory_path, context),
            include_listen_points=False,
            include_access_policy=False,
        )
        if _scope_has_content(scope):
            scopes.append(scope)
    return scopes


def _location_scopes(
    config_ast: ApacheConfigAst,
    virtualhosts: list[ApacheVirtualHostContext],
    config_dir: Path | None,
) -> list[NormalizedScope]:
    if not virtualhosts:
        return _location_scopes_for_context(
            config_ast,
            virtualhost_context=None,
            config_dir=config_dir,
        )

    scopes: list[NormalizedScope] = []
    for context in virtualhosts:
        scopes.extend(
            _location_scopes_for_context(
                config_ast,
                virtualhost_context=context,
                config_dir=config_dir,
            )
        )
    return scopes


def _location_scopes_for_context(
    config_ast: ApacheConfigAst,
    *,
    virtualhost_context: ApacheVirtualHostContext | None,
    config_dir: Path | None,
) -> list[NormalizedScope]:
    base_directory = _location_base_directory(
        config_ast,
        virtualhost_context=virtualhost_context,
        config_dir=config_dir,
    )
    base_effective = build_effective_config(
        config_ast,
        str(base_directory),
        config_dir=config_dir,
        virtualhost_context=virtualhost_context,
    )
    scopes: list[NormalizedScope] = []
    for location_scope in base_effective.location_scopes:
        scope = _normalize_location_scope(
            config_ast,
            location_scope,
            base_directory=base_directory,
            virtualhost_context=virtualhost_context,
            config_dir=config_dir,
        )
        if _scope_has_content(scope):
            scopes.append(scope)
    return scopes


def _location_base_directory(
    config_ast: ApacheConfigAst,
    *,
    virtualhost_context: ApacheVirtualHostContext | None,
    config_dir: Path | None,
) -> Path:
    if virtualhost_context is None:
        return Path("/")
    return (
        extract_document_root(
            config_ast,
            virtualhost_context=virtualhost_context,
            config_dir=config_dir,
        )
        or Path("/")
    )


def _normalize_location_scope(
    config_ast: ApacheConfigAst,
    location_scope,
    *,
    base_directory: Path,
    virtualhost_context: ApacheVirtualHostContext | None,
    config_dir: Path | None,
) -> NormalizedScope:
    if location_scope.match_type == "prefix":
        effective = build_effective_config(
            config_ast,
            str(base_directory),
            config_dir=config_dir,
            virtualhost_context=virtualhost_context,
            location_path=location_scope.path or "/",
        )
        directives = effective.directives
    else:
        base_effective = build_effective_config(
            config_ast,
            str(base_directory),
            config_dir=config_dir,
            virtualhost_context=virtualhost_context,
        )
        directives = {
            key: _clone_directive(value)
            for key, value in base_effective.directives.items()
        }
        _apply_raw_location_scope(directives, location_scope)

    return _normalize_effective_scope(
        directives,
        scope_name=_location_scope_name(location_scope.path, virtualhost_context),
        include_listen_points=False,
        include_access_policy=False,
    )


def _apply_raw_location_scope(
    directives: dict[str, EffectiveDirective],
    location_scope,
) -> None:
    for key, directive in location_scope.directives.items():
        directives[key] = _clone_directive(directive)


def _normalize_effective_scope(
    directives: dict[str, EffectiveDirective],
    *,
    scope_name: str | None,
    include_listen_points: bool,
    include_access_policy: bool = True,
) -> NormalizedScope:
    listen_points = (
        _listen_points_from_directives(directives) if include_listen_points else []
    )
    tls = _tls_from_directives(directives)
    headers = _headers_from_directives(directives)
    access_policy = (
        _access_policy_from_directives(directives) if include_access_policy else None
    )

    return NormalizedScope(
        scope_name=scope_name,
        listen_points=listen_points,
        tls=tls,
        security_headers=headers,
        access_policy=access_policy,
    )


def _scope_has_content(scope: NormalizedScope) -> bool:
    return bool(
        scope.listen_points
        or scope.tls
        or scope.security_headers
        or scope.access_policy
    )


def _listen_points_from_directives(
    directives: dict[str, EffectiveDirective],
) -> list[NormalizedListenPoint]:
    directive = directives.get("listen")
    if directive is None or not _is_simple_args(directive.args):
        return []

    parsed = _parse_listen_args(directive.args, directive.origin)
    return [parsed] if parsed is not None else []


def _parse_listen_args(
    args: list[str],
    origin: DirectiveOrigin,
) -> NormalizedListenPoint | None:
    if not args:
        return None

    addr_arg = args[0]
    protocol_hint = args[1].lower() if len(args) >= 2 else None
    is_https = protocol_hint == "https"
    address, port = _parse_addr(addr_arg, is_https)

    return NormalizedListenPoint(
        port=port,
        protocol="https" if is_https else "http",
        tls=is_https,
        source=_ref_from_origin(origin),
        address=address,
    )


def _parse_addr(addr_arg: str, is_https: bool) -> tuple[str | None, int]:
    default_port = 443 if is_https else 80

    if addr_arg.isdigit():
        return None, int(addr_arg)

    if ":" in addr_arg:
        host, _, port_str = addr_arg.rpartition(":")
        if port_str.isdigit():
            return host or None, int(port_str)

    return addr_arg, default_port


def _tls_from_directives(
    directives: dict[str, EffectiveDirective],
) -> NormalizedTLS | None:
    ssl_engine, ssl_protocol, ssl_cipher, ssl_cert, ssl_key = _tls_directives(
        directives
    )
    anchor = _first_present_directive(
        ssl_engine,
        ssl_protocol,
        ssl_cipher,
        ssl_cert,
        ssl_key,
    )
    if anchor is None:
        return None

    return NormalizedTLS(
        source=_ref_from_origin(anchor.origin),
        protocols=_simple_directive_values(ssl_protocol),
        ciphers=_simple_directive_first_arg(ssl_cipher),
        certificate=_simple_directive_first_arg(ssl_cert),
        certificate_key=_simple_directive_first_arg(ssl_key),
        require_ssl=_ssl_engine_required(ssl_engine),
    )


def _tls_directives(
    directives: dict[str, EffectiveDirective],
) -> tuple[
    EffectiveDirective | None,
    EffectiveDirective | None,
    EffectiveDirective | None,
    EffectiveDirective | None,
    EffectiveDirective | None,
]:
    return (
        directives.get("sslengine"),
        directives.get("sslprotocol"),
        directives.get("sslciphersuite"),
        directives.get("sslcertificatefile"),
        directives.get("sslcertificatekeyfile"),
    )


def _first_present_directive(
    *candidates: EffectiveDirective | None,
) -> EffectiveDirective | None:
    for candidate in candidates:
        if candidate is not None:
            return candidate
    return None


def _ssl_engine_required(directive: EffectiveDirective | None) -> bool | None:
    value = _simple_directive_first_arg(directive)
    if value is None:
        return None
    return value.lower() == "on"


def _simple_directive_values(
    directive: EffectiveDirective | None,
) -> list[str] | None:
    if directive is None or not _is_simple_args(directive.args) or not directive.args:
        return None
    return list(directive.args)


def _simple_directive_first_arg(
    directive: EffectiveDirective | None,
) -> str | None:
    values = _simple_directive_values(directive)
    if not values:
        return None
    return values[0]


def _headers_from_directives(
    directives: dict[str, EffectiveDirective],
) -> list[NormalizedSecurityHeader]:
    directive = directives.get("header")
    if directive is None:
        return []

    headers: list[NormalizedSecurityHeader] = []
    for entry in _iter_header_entries(directive):
        if len(entry) < 2:
            continue

        action = entry[0].lower()
        if action not in ("set", "append", "add", "merge"):
            continue

        header_name = entry[1].lower()
        if header_name not in _SECURITY_HEADERS:
            continue

        value = entry[2] if len(entry) >= 3 else None
        headers.append(
            NormalizedSecurityHeader(
                name=header_name,
                value=value,
                source=_ref_from_origin(directive.origin),
            )
        )

    return headers


def _iter_header_entries(directive: EffectiveDirective) -> list[list[str]]:
    if not directive.args:
        return []

    if isinstance(directive.args[0], list):
        return [list(entry) for entry in directive.args]

    return [list(directive.args)]


def _access_policy_from_directives(
    directives: dict[str, EffectiveDirective],
) -> NormalizedAccessPolicy | None:
    options = directives.get("options")
    server_tokens = directives.get("servertokens")
    server_signature = directives.get("serversignature")

    directory_listing = _directory_listing_from_options(options)
    disclosed = _server_tokens_disclosure(server_tokens)
    disclosed = _merge_server_signature_disclosure(server_signature, disclosed=disclosed)
    if directory_listing is None and disclosed is None:
        return None

    anchor = _first_present_directive(server_signature, server_tokens, options)
    if anchor is None:
        return None

    return NormalizedAccessPolicy(
        source=_ref_from_origin(anchor.origin),
        directory_listing=directory_listing,
        server_identification_disclosed=disclosed,
    )


def _directory_listing_from_options(
    directive: EffectiveDirective | None,
) -> bool | None:
    if directive is None:
        return None
    if not directive.args:
        return False
    values = _simple_directive_values(directive)
    if values is None:
        return None
    return _options_has_indexes(values)


def _server_tokens_disclosure(
    directive: EffectiveDirective | None,
) -> bool | None:
    value = _simple_directive_first_arg(directive)
    if value is None:
        return None
    return value.lower() not in ("prod", "productonly")


def _merge_server_signature_disclosure(
    directive: EffectiveDirective | None,
    *,
    disclosed: bool | None,
) -> bool | None:
    value = _simple_directive_first_arg(directive)
    if value is None:
        return disclosed

    lowered = value.lower()
    if lowered == "off":
        return False
    if lowered in ("on", "email"):
        return True
    if disclosed is None:
        return True
    return disclosed


def _options_has_indexes(args: list[str]) -> bool:
    for arg in args:
        lowered = arg.lower()
        if lowered in ("indexes", "+indexes"):
            return True
        if lowered == "-indexes":
            return False
    return False


def _ref_from_origin(origin: DirectiveOrigin) -> SourceRef:
    return SourceRef(
        server_type="apache",
        file_path=origin.source.file_path or "",
        line=origin.source.line,
    )


def _clone_directive(directive: EffectiveDirective) -> EffectiveDirective:
    if directive.args and isinstance(directive.args[0], list):
        args = [list(entry) for entry in directive.args]
    else:
        args = list(directive.args)
    return EffectiveDirective(
        name=directive.name,
        args=args,
        origin=directive.origin,
        override_chain=list(directive.override_chain),
    )


def _is_simple_args(args) -> bool:
    return not args or not isinstance(args[0], list)


def _config_dir_from_effective_input(
    effective_config: dict[str, object] | None,
) -> Path | None:
    if not effective_config:
        return None
    config_dir = effective_config.get("config_dir")
    if isinstance(config_dir, Path):
        return config_dir
    if isinstance(config_dir, str):
        return Path(config_dir)
    return None


def _iter_directory_blocks_with_virtualhost(
    nodes: list[ApacheDirectiveNode | ApacheBlockNode],
    current_virtualhost: ApacheVirtualHostContext | None,
) -> list[tuple[ApacheBlockNode, ApacheVirtualHostContext | None]]:
    blocks: list[tuple[ApacheBlockNode, ApacheVirtualHostContext | None]] = []
    for node in nodes:
        if not isinstance(node, ApacheBlockNode):
            continue

        node_name = node.name.lower()
        if node_name == "virtualhost":
            child_context = _virtualhost_context_from_block(node)
            blocks.extend(
                _iter_directory_blocks_with_virtualhost(
                    node.children,
                    current_virtualhost=child_context,
                )
            )
            continue

        if node_name == "directory":
            blocks.append((node, current_virtualhost))

        blocks.extend(
            _iter_directory_blocks_with_virtualhost(
                node.children,
                current_virtualhost=current_virtualhost,
            )
        )
    return blocks


def _virtualhost_context_from_block(block: ApacheBlockNode) -> ApacheVirtualHostContext:
    server_name: str | None = None
    server_aliases: list[str] = []
    for child in _iter_scoped_directives(block.children):
        name = child.name.lower()
        if name == "servername" and child.args:
            server_name = child.args[0]
        elif name == "serveralias":
            server_aliases.extend(child.args)
    return ApacheVirtualHostContext(
        server_name=server_name,
        server_aliases=server_aliases,
        listen_address=block.args[0] if block.args else None,
        node=block,
    )


def _iter_scoped_directives(
    nodes: list[ApacheDirectiveNode | ApacheBlockNode],
) -> list[ApacheDirectiveNode]:
    directives: list[ApacheDirectiveNode] = []
    for node in nodes:
        if isinstance(node, ApacheDirectiveNode):
            directives.append(node)
        elif node.name.lower() in _TRANSPARENT_WRAPPER_BLOCKS:
            directives.extend(_iter_scoped_directives(node.children))
    return directives


def _resolve_directory_path(
    block: ApacheBlockNode,
    config_dir: Path | None,
) -> Path | None:
    if not block.args:
        return None
    raw = block.args[0]
    if raw.startswith("~"):
        return None

    path = Path(raw)
    if path.is_absolute():
        return path
    if block.source.file_path:
        return Path(block.source.file_path).parent / path
    if config_dir is not None:
        return config_dir / path
    return path


def _virtualhost_scope_name(context: ApacheVirtualHostContext) -> str:
    return context.server_name or context.listen_address or "virtualhost"


def _directory_scope_name(
    directory_path: Path,
    context: ApacheVirtualHostContext | None,
) -> str:
    normalized_path = str(directory_path).replace("\\", "/")
    label = f"directory:{normalized_path}"
    if context is None:
        return label
    return f"{_virtualhost_scope_name(context)} {label}"


def _location_scope_name(
    location_path: str,
    context: ApacheVirtualHostContext | None,
) -> str:
    label = f"location:{location_path}"
    if context is None:
        return label
    return f"{_virtualhost_scope_name(context)} {label}"


__all__ = ["normalize_apache"]

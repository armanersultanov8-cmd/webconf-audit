from __future__ import annotations

from webconf_audit.local.nginx.parser.ast import BlockNode, DirectiveNode, find_child_directives


def listen_uses_tls(directive: DirectiveNode) -> bool:
    return "ssl" in directive.args


def listen_uses_tls_on_port_443(directive: DirectiveNode) -> bool:
    return listen_uses_tls(directive) and any(_listen_arg_targets_port_443(arg) for arg in directive.args)


def server_uses_tls(server_block: BlockNode) -> bool:
    return any(
        listen_uses_tls(directive)
        for directive in find_child_directives(server_block, "listen")
    )


def _listen_arg_targets_port_443(arg: str) -> bool:
    return arg == "443" or arg.endswith(":443")


__all__ = ["listen_uses_tls", "listen_uses_tls_on_port_443", "server_uses_tls"]

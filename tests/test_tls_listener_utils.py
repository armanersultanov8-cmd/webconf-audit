import pytest

from webconf_audit.local.nginx.parser.ast import BlockNode, DirectiveNode, SourceSpan
from webconf_audit.local.nginx.rules.tls_listener_utils import (
    listen_uses_tls,
    listen_uses_tls_on_port_443,
    server_uses_tls,
)


def _listen_directive(*args: str) -> DirectiveNode:
    return DirectiveNode(
        name="listen",
        args=list(args),
        source=SourceSpan(file_path="nginx.conf", line=1, column=1),
    )


def _server_block(*children: DirectiveNode) -> BlockNode:
    return BlockNode(
        name="server",
        children=list(children),
        source=SourceSpan(file_path="nginx.conf", line=1, column=1),
    )


@pytest.mark.parametrize(
    ("directive", "expected"),
    [
        (_listen_directive("443", "ssl"), True),
        (_listen_directive("443", "ssl", "http2"), True),
        (_listen_directive("127.0.0.1:443", "ssl"), True),
        (_listen_directive("80", "ssl"), True),
        (_listen_directive("8443", "ssl"), True),
        (_listen_directive("80"), False),
        (_listen_directive("443"), False),
    ],
)
def test_listen_uses_tls(directive: DirectiveNode, expected: bool) -> None:
    assert listen_uses_tls(directive) is expected


@pytest.mark.parametrize(
    ("directive", "expected"),
    [
        (_listen_directive("443", "ssl"), True),
        (_listen_directive("443", "ssl", "http2"), True),
        (_listen_directive("127.0.0.1:443", "ssl"), True),
        (_listen_directive("80", "ssl"), False),
        (_listen_directive("8443", "ssl"), False),
        (_listen_directive("80"), False),
        (_listen_directive("443"), False),
    ],
)
def test_listen_uses_tls_on_port_443(directive: DirectiveNode, expected: bool) -> None:
    assert listen_uses_tls_on_port_443(directive) is expected


@pytest.mark.parametrize(
    ("server_block", "expected"),
    [
        (_server_block(_listen_directive("443", "ssl")), True),
        (_server_block(_listen_directive("80", "ssl")), True),
        (_server_block(_listen_directive("80")), False),
        (_server_block(_listen_directive("80"), _listen_directive("127.0.0.1:443", "ssl")), True),
    ],
)
def test_server_uses_tls(server_block: BlockNode, expected: bool) -> None:
    assert server_uses_tls(server_block) is expected

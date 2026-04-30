import pytest

from webconf_audit.local.nginx.parser.ast import BlockNode, DirectiveNode
from webconf_audit.local.nginx.parser.parser import NginxParseError, NginxParser, NginxTokenizer


def test_parse_simple_directive() -> None:
    tokens = NginxTokenizer("worker_processes 1;", file_path="nginx.conf").tokenize()

    ast = NginxParser(tokens).parse()

    assert len(ast.nodes) == 1
    node = ast.nodes[0]
    assert isinstance(node, DirectiveNode)
    assert node.name == "worker_processes"
    assert node.args == ["1"]
    assert node.source.file_path == "nginx.conf"
    assert node.source.line == 1
    assert node.source.column == 1


def test_parse_simple_block_with_nested_block() -> None:
    tokens = NginxTokenizer("http { server { } }", file_path="nginx.conf").tokenize()

    ast = NginxParser(tokens).parse()

    assert len(ast.nodes) == 1
    node = ast.nodes[0]
    assert isinstance(node, BlockNode)
    assert node.name == "http"
    assert node.args == []
    assert node.source.file_path == "nginx.conf"
    assert node.source.line == 1
    assert node.source.column == 1
    assert len(node.children) == 1

    child = node.children[0]
    assert isinstance(child, BlockNode)
    assert child.name == "server"
    assert child.args == []
    assert child.source.file_path == "nginx.conf"
    assert child.source.line == 1
    assert child.source.column == 8
    assert child.children == []


def test_parse_empty_config() -> None:
    tokens = NginxTokenizer("", file_path="nginx.conf").tokenize()

    ast = NginxParser(tokens).parse()

    assert ast.nodes == []


def test_parse_directive_with_quoted_argument() -> None:
    tokens = NginxTokenizer('root "/var/www/html";', file_path="nginx.conf").tokenize()

    ast = NginxParser(tokens).parse()

    assert len(ast.nodes) == 1
    node = ast.nodes[0]
    assert isinstance(node, DirectiveNode)
    assert node.name == "root"
    assert node.args == ["/var/www/html"]
    assert node.source.file_path == "nginx.conf"
    assert node.source.line == 1
    assert node.source.column == 1


def test_parse_directive_with_escaped_quotes_in_quoted_argument() -> None:
    tokens = NginxTokenizer(
        'root "/var/www/\\"quoted\\"";',
        file_path="nginx.conf",
    ).tokenize()

    ast = NginxParser(tokens).parse()

    assert len(ast.nodes) == 1
    node = ast.nodes[0]
    assert isinstance(node, DirectiveNode)
    assert node.args == ['/var/www/"quoted"']


def test_parse_directive_with_common_escape_sequences_in_quoted_argument() -> None:
    tokens = NginxTokenizer(
        'log_format main "line\\n\\tindent\\\\path";',
        file_path="nginx.conf",
    ).tokenize()

    ast = NginxParser(tokens).parse()

    assert len(ast.nodes) == 1
    node = ast.nodes[0]
    assert isinstance(node, DirectiveNode)
    assert node.name == "log_format"
    assert node.args == ["main", "line\n\tindent\\path"]


def test_parse_block_with_quoted_argument() -> None:
    tokens = NginxTokenizer('location "/app path" { }', file_path="nginx.conf").tokenize()

    ast = NginxParser(tokens).parse()

    assert len(ast.nodes) == 1
    node = ast.nodes[0]
    assert isinstance(node, BlockNode)
    assert node.name == "location"
    assert node.args == ["/app path"]
    assert node.children == []
    assert node.source.file_path == "nginx.conf"
    assert node.source.line == 1
    assert node.source.column == 1


def test_parse_include_directive_inside_block_as_regular_directive() -> None:
    tokens = NginxTokenizer("http { include mime.types; server { } }", file_path="nginx.conf").tokenize()

    ast = NginxParser(tokens).parse()

    assert len(ast.nodes) == 1
    http_block = ast.nodes[0]
    assert isinstance(http_block, BlockNode)
    assert http_block.name == "http"
    assert http_block.args == []
    assert len(http_block.children) == 2

    include_directive = http_block.children[0]
    assert isinstance(include_directive, DirectiveNode)
    assert include_directive.name == "include"
    assert include_directive.args == ["mime.types"]
    assert include_directive.source.file_path == "nginx.conf"
    assert include_directive.source.line == 1
    assert include_directive.source.column == 8

    server_block = http_block.children[1]
    assert isinstance(server_block, BlockNode)
    assert server_block.name == "server"
    assert server_block.args == []
    assert server_block.children == []


def test_parse_include_directive_with_quoted_argument() -> None:
    tokens = NginxTokenizer('include "conf.d/*.conf";', file_path="nginx.conf").tokenize()

    ast = NginxParser(tokens).parse()

    assert len(ast.nodes) == 1
    include_directive = ast.nodes[0]
    assert isinstance(include_directive, DirectiveNode)
    assert include_directive.name == "include"
    assert include_directive.args == ["conf.d/*.conf"]
    assert include_directive.source.file_path == "nginx.conf"
    assert include_directive.source.line == 1
    assert include_directive.source.column == 1


def test_parse_config_with_comments_around_constructs() -> None:
    text = "# before\nworker_processes 1; # after directive\n# between\nhttp { }\n# end\n"
    tokens = NginxTokenizer(text, file_path="nginx.conf").tokenize()

    ast = NginxParser(tokens).parse()

    assert len(ast.nodes) == 2

    directive = ast.nodes[0]
    assert isinstance(directive, DirectiveNode)
    assert directive.name == "worker_processes"
    assert directive.args == ["1"]
    assert directive.source.file_path == "nginx.conf"
    assert directive.source.line == 2
    assert directive.source.column == 1

    block = ast.nodes[1]
    assert isinstance(block, BlockNode)
    assert block.name == "http"
    assert block.args == []
    assert block.children == []
    assert block.source.file_path == "nginx.conf"
    assert block.source.line == 4
    assert block.source.column == 1


def test_parse_bare_word_stops_before_comment_start() -> None:
    tokens = NginxTokenizer("root /var/www#comment;", file_path="nginx.conf").tokenize()

    assert [token.value for token in tokens[:-1]] == ["root", "/var/www"]

    with pytest.raises(NginxParseError, match=r"Expected ';' or '\{'"):
        NginxParser(tokens).parse()


def test_parse_mixed_blocks_quoted_directive_and_comments() -> None:
    text = """
# top comment
http {
    # server comment
    server {
        root "/var/www/html"; # inline comment
    }
}
""".lstrip()
    tokens = NginxTokenizer(text, file_path="nginx.conf").tokenize()

    ast = NginxParser(tokens).parse()

    assert len(ast.nodes) == 1

    http_block = ast.nodes[0]
    assert isinstance(http_block, BlockNode)
    assert http_block.name == "http"
    assert http_block.args == []
    assert http_block.source.file_path == "nginx.conf"
    assert http_block.source.line == 2
    assert http_block.source.column == 1
    assert len(http_block.children) == 1

    server_block = http_block.children[0]
    assert isinstance(server_block, BlockNode)
    assert server_block.name == "server"
    assert server_block.args == []
    assert server_block.source.file_path == "nginx.conf"
    assert server_block.source.line == 4
    assert server_block.source.column == 5
    assert len(server_block.children) == 1

    root_directive = server_block.children[0]
    assert isinstance(root_directive, DirectiveNode)
    assert root_directive.name == "root"
    assert root_directive.args == ["/var/www/html"]
    assert root_directive.source.file_path == "nginx.conf"
    assert root_directive.source.line == 5
    assert root_directive.source.column == 9


def test_parse_raises_specialized_error_for_missing_statement_terminator() -> None:
    tokens = NginxTokenizer("worker_processes 1", file_path="nginx.conf").tokenize()

    with pytest.raises(NginxParseError, match=r"Expected ';' or '\{'"):
        NginxParser(tokens).parse()

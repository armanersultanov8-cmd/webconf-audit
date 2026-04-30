from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(slots=True)
class ApacheSourceSpan:
    file_path: str | None = None
    line: int | None = None


@dataclass(slots=True)
class ApacheDirectiveNode:
    name: str
    args: list[str] = field(default_factory=list)
    source: ApacheSourceSpan = field(default_factory=ApacheSourceSpan)


@dataclass(slots=True)
class ApacheBlockNode:
    name: str
    args: list[str] = field(default_factory=list)
    children: list[ApacheDirectiveNode | ApacheBlockNode] = field(default_factory=list)
    source: ApacheSourceSpan = field(default_factory=ApacheSourceSpan)


@dataclass(slots=True)
class ApacheConfigAst:
    nodes: list[ApacheDirectiveNode | ApacheBlockNode] = field(default_factory=list)


@dataclass(slots=True)
class ApacheToken:
    kind: str
    name: str
    args: list[str] = field(default_factory=list)
    file_path: str | None = None
    line: int | None = None


class ApacheParseError(ValueError):
    def __init__(
        self,
        message: str,
        *,
        line: int | None = None,
        file_path: str | None = None,
    ) -> None:
        full_message = message if line is None else f"Line {line}: {message}"
        super().__init__(full_message)
        self.line = line
        self.file_path = file_path


class ApacheTokenizer:
    def __init__(self, text: str, file_path: str | None = None) -> None:
        self.text = text
        self.file_path = file_path

    def tokenize(self) -> list[ApacheToken]:
        tokens: list[ApacheToken] = []
        lines = self.text.splitlines()

        for line_number, raw_line in enumerate(lines, start=1):
            content = _strip_comment(raw_line).strip()

            if not content:
                continue

            if content.startswith("<"):
                if not content.endswith(">"):
                    raise ApacheParseError(
                        "Unterminated block tag",
                        line=line_number,
                        file_path=self.file_path,
                    )

                if content.startswith("</"):
                    tokens.append(self._tokenize_block_end(content, line_number))
                else:
                    tokens.append(self._tokenize_block_start(content, line_number))
                continue

            tokens.append(self._tokenize_directive(content, line_number))

        tokens.append(
            ApacheToken(
                kind="eof",
                name="",
                file_path=self.file_path,
                line=len(lines) + 1 if lines else 1,
            )
        )
        return tokens

    def _tokenize_directive(self, content: str, line_number: int) -> ApacheToken:
        parts = _split_arguments(content, line_number, self.file_path)

        if not parts:
            raise ApacheParseError(
                "Directive name is required",
                line=line_number,
                file_path=self.file_path,
            )

        return ApacheToken(
            kind="directive",
            name=parts[0],
            args=parts[1:],
            file_path=self.file_path,
            line=line_number,
        )

    def _tokenize_block_start(self, content: str, line_number: int) -> ApacheToken:
        inner = content[1:-1].strip()
        parts = _split_arguments(inner, line_number, self.file_path)

        if not parts:
            raise ApacheParseError(
                "Block name is required",
                line=line_number,
                file_path=self.file_path,
            )

        block_name = parts[0]

        return ApacheToken(
            kind="block_start",
            name=block_name,
            args=parts[1:],
            file_path=self.file_path,
            line=line_number,
        )

    def _tokenize_block_end(self, content: str, line_number: int) -> ApacheToken:
        inner = content[2:-1].strip()
        parts = _split_arguments(inner, line_number, self.file_path)

        if not parts:
            raise ApacheParseError(
                "Closing block name is required",
                line=line_number,
                file_path=self.file_path,
            )

        if len(parts) != 1:
            raise ApacheParseError(
                "Closing block tags must not have arguments",
                line=line_number,
                file_path=self.file_path,
            )

        block_name = parts[0]

        return ApacheToken(
            kind="block_end",
            name=block_name,
            file_path=self.file_path,
            line=line_number,
        )


class ApacheParser:
    def __init__(self, tokens: list[ApacheToken]) -> None:
        self.tokens = tokens
        self.position = 0

    def parse(self) -> ApacheConfigAst:
        nodes = self._parse_nodes(expected_block_name=None)
        self._expect("eof")
        return ApacheConfigAst(nodes=nodes)

    def _parse_nodes(
        self,
        expected_block_name: str | None,
    ) -> list[ApacheDirectiveNode | ApacheBlockNode]:
        nodes: list[ApacheDirectiveNode | ApacheBlockNode] = []

        while True:
            token = self._current()

            if token.kind == "eof":
                if expected_block_name is not None:
                    raise ApacheParseError(
                        f"Unexpected end of input inside <{expected_block_name}>",
                        line=token.line,
                        file_path=token.file_path,
                    )
                break

            if token.kind == "block_end":
                if expected_block_name is None:
                    raise ApacheParseError(
                        f"Unexpected closing block </{token.name}>",
                        line=token.line,
                        file_path=token.file_path,
                    )

                if token.name.lower() != expected_block_name.lower():
                    raise ApacheParseError(
                        f"Mismatched closing block </{token.name}> for <{expected_block_name}>",
                        line=token.line,
                        file_path=token.file_path,
                    )
                break

            if token.kind == "directive":
                nodes.append(self._parse_directive())
                continue

            if token.kind == "block_start":
                nodes.append(self._parse_block())
                continue

            raise ApacheParseError(
                f"Unexpected token kind {token.kind}",
                line=token.line,
                file_path=token.file_path,
            )

        return nodes

    def _parse_directive(self) -> ApacheDirectiveNode:
        token = self._expect("directive")
        return ApacheDirectiveNode(
            name=token.name,
            args=token.args,
            source=ApacheSourceSpan(file_path=token.file_path, line=token.line),
        )

    def _parse_block(self) -> ApacheBlockNode:
        start_token = self._expect("block_start")
        children = self._parse_nodes(expected_block_name=start_token.name)
        end_token = self._expect("block_end")

        if end_token.name.lower() != start_token.name.lower():
            raise ApacheParseError(
                f"Mismatched closing block </{end_token.name}> for <{start_token.name}>",
                line=end_token.line,
                file_path=end_token.file_path,
            )

        return ApacheBlockNode(
            name=start_token.name,
            args=start_token.args,
            children=children,
            source=ApacheSourceSpan(file_path=start_token.file_path, line=start_token.line),
        )

    def _current(self) -> ApacheToken:
        return self.tokens[self.position]

    def _advance(self) -> ApacheToken:
        token = self.tokens[self.position]
        self.position += 1
        return token

    def _expect(self, kind: str) -> ApacheToken:
        token = self._current()

        if token.kind != kind:
            raise ApacheParseError(
                f"Expected {kind}, got {token.kind}",
                line=token.line,
                file_path=token.file_path,
            )

        return self._advance()


def parse_apache_config(text: str, file_path: str | None = None) -> ApacheConfigAst:
    tokens = ApacheTokenizer(text, file_path=file_path).tokenize()
    return ApacheParser(tokens).parse()


def _strip_comment(line: str) -> str:
    result: list[str] = []
    quote_char: str | None = None
    index = 0

    while index < len(line):
        char = line[index]

        if quote_char is not None:
            if char == "\\" and index + 1 < len(line):
                result.append(char)
                result.append(line[index + 1])
                index += 2
                continue

            if char == quote_char:
                quote_char = None

            result.append(char)
            index += 1
            continue

        if char in {"'", '"'}:
            quote_char = char
            result.append(char)
            index += 1
            continue

        if char == "#":
            break

        result.append(char)
        index += 1

    return "".join(result)


def _split_arguments(text: str, line: int, file_path: str | None) -> list[str]:
    parts: list[str] = []
    current: list[str] = []
    quote_char: str | None = None
    index = 0

    while index < len(text):
        char = text[index]

        if quote_char is not None:
            index, quote_char = _consume_quoted_argument(
                text,
                index,
                current,
                quote_char,
            )
            continue

        if char in {"'", '"'}:
            quote_char = char
            index += 1
            continue

        if char.isspace():
            current = _flush_argument(current, parts)
            index += 1
            continue

        current.append(char)
        index += 1

    if quote_char is not None:
        raise ApacheParseError(
            "Unterminated quoted string",
            line=line,
            file_path=file_path,
        )

    _flush_argument(current, parts)

    return parts


def _consume_quoted_argument(
    text: str,
    index: int,
    current: list[str],
    quote_char: str,
) -> tuple[int, str | None]:
    char = text[index]
    if char == "\\" and index + 1 < len(text):
        current.append(text[index + 1])
        return index + 2, quote_char
    if char == quote_char:
        return index + 1, None
    current.append(char)
    return index + 1, quote_char


def _flush_argument(current: list[str], parts: list[str]) -> list[str]:
    if current:
        parts.append("".join(current))
    return []


__all__ = [
    "ApacheBlockNode",
    "ApacheConfigAst",
    "ApacheDirectiveNode",
    "ApacheParseError",
    "ApacheParser",
    "ApacheSourceSpan",
    "ApacheToken",
    "ApacheTokenizer",
    "parse_apache_config",
]

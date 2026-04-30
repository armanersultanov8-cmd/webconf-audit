from __future__ import annotations

from webconf_audit.local.nginx.parser.ast import BlockNode, ConfigAst, DirectiveNode, SourceSpan
from webconf_audit.local.nginx.parser.tokens import Token, TokenType

_MSG_SINGLE_QUOTE_NOT_SUPPORTED = "Single-quoted strings are not supported in nginx config"
_MSG_UNTERMINATED_QUOTED_STRING = "Unterminated quoted string"


class NginxParseError(ValueError):
    """Raised when nginx config tokenization or parsing fails due to syntax errors."""

    def __init__(
        self,
        message: str,
        *,
        file_path: str | None = None,
        line: int | None = None,
        column: int | None = None,
    ) -> None:
        super().__init__(message)
        self.file_path = file_path
        self.line = line
        self.column = column


class NginxTokenizer:
    def __init__(self, text: str, file_path: str | None = None) -> None:
        self.text = text
        self.file_path = file_path

    def tokenize(self) -> list[Token]:
        tokens: list[Token] = []
        line = 1
        column = 1
        i = 0
        length = len(self.text)

        while i < length:
            char = self.text[i]

            if char in {" ", "\t", "\r"}:
                i, column = _advance_inline_position(i, column)
                continue

            if char == "\n":
                i, line, column = _advance_newline(i, line)
                continue

            if char == "#":
                i, column = _skip_comment(self.text, i, column, length)
                continue

            if char == "'":
                _raise_single_quote_error(self.file_path, line, column)

            if char == '"':
                token, i, line, column = _read_quoted_word(
                    self.text,
                    i,
                    line,
                    column,
                    length,
                    self.file_path,
                )
                tokens.append(token)
                continue

            single_char_token = _single_char_token(
                char,
                self.file_path,
                line,
                column,
            )
            if single_char_token is not None:
                tokens.append(single_char_token)
                i, column = _advance_inline_position(i, column)
                continue

            token, i, column = _read_bare_word(
                self.text,
                i,
                column,
                length,
                self.file_path,
                line,
            )
            tokens.append(token)

        tokens.append(
            Token(
                token_type=TokenType.EOF,
                value="",
                file_path=self.file_path,
                line=line,
                column=column,
            )
        )
        return tokens


def _advance_inline_position(index: int, column: int) -> tuple[int, int]:
    return index + 1, column + 1


def _advance_newline(index: int, line: int) -> tuple[int, int, int]:
    return index + 1, line + 1, 1


def _skip_comment(
    text: str,
    index: int,
    column: int,
    length: int,
) -> tuple[int, int]:
    while index < length and text[index] != "\n":
        index, column = _advance_inline_position(index, column)
    return index, column


def _raise_single_quote_error(
    file_path: str | None,
    line: int,
    column: int,
) -> None:
    raise NginxParseError(
        _MSG_SINGLE_QUOTE_NOT_SUPPORTED,
        file_path=file_path,
        line=line,
        column=column,
    )


def _read_quoted_word(
    text: str,
    index: int,
    line: int,
    column: int,
    length: int,
    file_path: str | None,
) -> tuple[Token, int, int, int]:
    start_line = line
    start_column = column
    index, column = _advance_inline_position(index, column)
    value_chars: list[str] = []

    while index < length and text[index] != '"':
        if text[index] == "\\" and index + 1 < length:
            index, line, column = _consume_quoted_escape(
                text,
                index,
                line,
                column,
                value_chars,
            )
            continue
        if text[index] == "\n":
            value_chars.append("\n")
            index, line, column = _advance_newline(index, line)
            continue
        value_chars.append(text[index])
        index, column = _advance_inline_position(index, column)

    if index >= length:
        raise NginxParseError(
            _MSG_UNTERMINATED_QUOTED_STRING,
            file_path=file_path,
            line=start_line,
            column=start_column,
        )

    token = Token(
        token_type=TokenType.WORD,
        value="".join(value_chars),
        file_path=file_path,
        line=start_line,
        column=start_column,
    )
    index, column = _advance_inline_position(index, column)
    return token, index, line, column


def _consume_quoted_escape(
    text: str,
    index: int,
    line: int,
    column: int,
    value_chars: list[str],
) -> tuple[int, int, int]:
    next_char = text[index + 1]
    value_chars.append(
        {
            '"': '"',
            "'": "'",
            "\\": "\\",
            "t": "\t",
            "r": "\r",
            "n": "\n",
        }.get(next_char, next_char)
    )
    if next_char == "\n":
        return index + 2, line + 1, 1
    return index + 2, line, column + 2


def _single_char_token(
    char: str,
    file_path: str | None,
    line: int,
    column: int,
) -> Token | None:
    token_type = {
        "{": TokenType.LBRACE,
        "}": TokenType.RBRACE,
        ";": TokenType.SEMICOLON,
    }.get(char)
    if token_type is None:
        return None
    return Token(
        token_type=token_type,
        value=char,
        file_path=file_path,
        line=line,
        column=column,
    )


def _read_bare_word(
    text: str,
    index: int,
    column: int,
    length: int,
    file_path: str | None,
    line: int,
) -> tuple[Token, int, int]:
    start = index
    start_column = column
    delimiters = {" ", "\t", "\r", "\n", "{", "}", ";", '"', "'", "#"}
    while index < length and text[index] not in delimiters:
        index, column = _advance_inline_position(index, column)

    return (
        Token(
            token_type=TokenType.WORD,
            value=text[start:index],
            file_path=file_path,
            line=line,
            column=start_column,
        ),
        index,
        column,
    )


class NginxParser:
    def __init__(self, tokens: list[Token]) -> None:
        self.tokens = tokens
        self.position = 0

    def parse(self) -> ConfigAst:
        nodes = self._parse_nodes(in_block=False)
        self._expect(TokenType.EOF)
        return ConfigAst(nodes=nodes)

    def _parse_nodes(self, in_block: bool) -> list[DirectiveNode | BlockNode]:
        nodes: list[DirectiveNode | BlockNode] = []

        while True:
            token = self._current()

            if token.token_type == TokenType.EOF:
                if in_block:
                    raise NginxParseError(
                        "Unexpected end of input inside block",
                        file_path=token.file_path,
                        line=token.line,
                        column=token.column,
                    )
                break

            if token.token_type == TokenType.RBRACE:
                if not in_block:
                    raise NginxParseError(
                        "Unexpected '}'",
                        file_path=token.file_path,
                        line=token.line,
                        column=token.column,
                    )
                break

            nodes.append(self._parse_statement())

        return nodes

    def _parse_statement(self) -> DirectiveNode | BlockNode:
        name_token = self._expect(TokenType.WORD)
        args: list[str] = []

        while self._current().token_type == TokenType.WORD:
            args.append(self._advance().value)

        source = SourceSpan(
            file_path=name_token.file_path,
            line=name_token.line,
            column=name_token.column,
        )
        token = self._current()

        if token.token_type == TokenType.SEMICOLON:
            self._advance()
            return DirectiveNode(name=name_token.value, args=args, source=source)

        if token.token_type == TokenType.LBRACE:
            self._advance()
            children = self._parse_nodes(in_block=True)
            self._expect(TokenType.RBRACE)
            return BlockNode(name=name_token.value, args=args, children=children, source=source)

        error_line = name_token.line if token.token_type == TokenType.EOF else token.line
        error_column = name_token.column if token.token_type == TokenType.EOF else token.column
        raise NginxParseError(
            "Expected ';' or '{'",
            file_path=token.file_path,
            line=error_line,
            column=error_column,
        )

    def _current(self) -> Token:
        return self.tokens[self.position]

    def _advance(self) -> Token:
        token = self.tokens[self.position]
        self.position += 1
        return token

    def _expect(self, token_type: TokenType) -> Token:
        token = self._current()

        if token.token_type != token_type:
            raise NginxParseError(
                f"Expected {token_type.value}, got {token.token_type.value}",
                file_path=token.file_path,
                line=token.line,
                column=token.column,
            )

        return self._advance()

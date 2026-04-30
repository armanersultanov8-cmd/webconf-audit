from __future__ import annotations

import re
from collections.abc import Iterator
from dataclasses import dataclass, field


@dataclass(slots=True)
class LighttpdSourceSpan:
    file_path: str | None = None
    line: int | None = None


@dataclass(frozen=True, slots=True)
class LighttpdCondition:
    variable: str
    operator: str
    value: str


@dataclass(slots=True)
class LighttpdDirectiveNode:
    name: str
    args: list[str] = field(default_factory=list)
    source: LighttpdSourceSpan = field(default_factory=LighttpdSourceSpan)


@dataclass(slots=True)
class LighttpdAssignmentNode:
    name: str
    operator: str
    value: str
    source: LighttpdSourceSpan = field(default_factory=LighttpdSourceSpan)


@dataclass(slots=True)
class LighttpdBlockNode:
    header: str
    children: list["LighttpdAstNode"] = field(default_factory=list)
    source: LighttpdSourceSpan = field(default_factory=LighttpdSourceSpan)
    condition: LighttpdCondition | None = None


LighttpdAstNode = LighttpdDirectiveNode | LighttpdAssignmentNode | LighttpdBlockNode


@dataclass(slots=True)
class LighttpdConfigAst:
    nodes: list[LighttpdAstNode] = field(default_factory=list)
    main_file_path: str | None = None


class LighttpdParseError(ValueError):
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


@dataclass(slots=True)
class _LogicalStatement:
    text: str
    line: int


@dataclass(slots=True)
class _StatementScanState:
    paren_depth: int = 0
    bracket_depth: int = 0
    quote_char: str | None = None


class LighttpdParser:
    def __init__(self, text: str, file_path: str | None = None) -> None:
        self.text = text[1:] if text.startswith("\ufeff") else text
        self.file_path = file_path
        self.statements = self._read_logical_statements()
        self.position = 0

    def parse(self) -> LighttpdConfigAst:
        return LighttpdConfigAst(
            nodes=self._parse_nodes(in_block=False),
            main_file_path=self.file_path,
        )

    def _parse_nodes(self, *, in_block: bool) -> list[LighttpdAstNode]:
        nodes: list[LighttpdAstNode] = []

        while self.position < len(self.statements):
            statement = self.statements[self.position]

            if statement.text == "}":
                if not in_block:
                    raise LighttpdParseError(
                        "Unexpected closing brace",
                        line=statement.line,
                        file_path=self.file_path,
                    )

                self.position += 1
                return nodes

            if _is_block_start(statement.text):
                self.position += 1
                header = statement.text[:-1].strip()

                if not header:
                    raise LighttpdParseError(
                        "Block header is required",
                        line=statement.line,
                        file_path=self.file_path,
                    )

                children = self._parse_nodes(in_block=True)
                nodes.append(
                    LighttpdBlockNode(
                        header=header,
                        children=children,
                        source=LighttpdSourceSpan(file_path=self.file_path, line=statement.line),
                        condition=_parse_condition(header),
                    )
                )
                continue

            if _contains_unquoted_brace(statement.text):
                raise LighttpdParseError(
                    "Unsupported inline brace usage",
                    line=statement.line,
                    file_path=self.file_path,
                )

            self.position += 1
            nodes.append(self._parse_statement(statement))

        if in_block:
            line = self.statements[-1].line if self.statements else 1
            raise LighttpdParseError(
                "Unexpected end of input inside block",
                line=line,
                file_path=self.file_path,
            )

        return nodes

    def _parse_statement(self, statement: _LogicalStatement) -> LighttpdAstNode:
        operator_info = _find_assignment_operator(statement.text)

        if operator_info is not None:
            operator, operator_index = operator_info
            name = statement.text[:operator_index].strip()
            value = statement.text[operator_index + len(operator) :].strip()

            if not name:
                raise LighttpdParseError(
                    "Assignment target is required",
                    line=statement.line,
                    file_path=self.file_path,
                )

            return LighttpdAssignmentNode(
                name=name,
                operator=operator,
                value=value,
                source=LighttpdSourceSpan(file_path=self.file_path, line=statement.line),
            )

        parts = _split_arguments(statement.text, statement.line, self.file_path)
        if not parts:
            raise LighttpdParseError(
                "Directive name is required",
                line=statement.line,
                file_path=self.file_path,
            )

        return LighttpdDirectiveNode(
            name=parts[0],
            args=parts[1:],
            source=LighttpdSourceSpan(file_path=self.file_path, line=statement.line),
        )

    def _read_logical_statements(self) -> list[_LogicalStatement]:
        statements: list[_LogicalStatement] = []
        buffer: list[str] = []
        start_line: int | None = None
        state = _StatementScanState()

        for line_number, raw_line in enumerate(self.text.splitlines(), start=1):
            content = _strip_comment(raw_line).strip()

            if not content and start_line is None:
                continue

            if start_line is None:
                start_line = line_number

            if content:
                buffer.append(content)

            state = _scan_logical_line_state(
                content,
                line_number,
                self.file_path,
                state,
            )
            if _logical_statement_complete(state, buffer):
                statements.append(
                    _LogicalStatement(
                        text=_logical_statement_text(buffer),
                        line=start_line,
                    )
                )
                buffer = []
                start_line = None

        _ensure_balanced_statement_state(state, self.file_path, start_line)

        if buffer:
            statements.append(
                _LogicalStatement(
                    text=_logical_statement_text(buffer),
                    line=start_line or 1,
                )
            )

        return statements


def parse_lighttpd_config(text: str, file_path: str | None = None) -> LighttpdConfigAst:
    return LighttpdParser(text, file_path=file_path).parse()


def _strip_comment(line: str) -> str:
    result: list[str] = []
    quote_char: str | None = None
    index = 0

    while index < len(line):
        char = line[index]

        if quote_char is not None:
            if char == "\\" and index + 1 < len(line) and line[index + 1] in {quote_char, "\\"}:
                result.append(char)
                result.append(line[index + 1])
                index += 2
                continue

            if char == quote_char:
                quote_char = None

            result.append(char)
            index += 1
            continue

        if char in {'"', "'"}:
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

        if char in {'"', "'"}:
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
        raise LighttpdParseError(
            "Unterminated quoted string",
            line=line,
            file_path=file_path,
        )

    _flush_argument(current, parts)

    return parts


def _contains_unquoted_brace(text: str) -> bool:
    return any(char in "{}" for char in _iter_unquoted_chars(text))


def _is_block_start(text: str) -> bool:
    positions = [
        index
        for index, char in _iter_unquoted_char_positions(text)
        if char in "{}"
    ]

    if not positions:
        return False

    return len(positions) == 1 and positions[0] == len(text.rstrip()) - 1 and text.rstrip().endswith("{")


def _find_assignment_operator(text: str) -> tuple[str, int] | None:
    quote_char: str | None = None
    escaped = False
    paren_depth = 0
    bracket_depth = 0
    index = 0

    while index < len(text):
        char = text[index]

        if quote_char is not None:
            quote_char, escaped = _quoted_scan_state(
                char,
                quote_char,
                escaped=escaped,
            )
            index += 1
            continue

        if char in {'"', "'"}:
            quote_char = char
            index += 1
            continue

        paren_depth, bracket_depth = _updated_delimiter_depths(
            char,
            paren_depth,
            bracket_depth,
        )
        operator = _assignment_operator_at(text, index, char, paren_depth, bracket_depth)
        if operator is not None:
            return operator, index

        index += 1

    return None


def _scan_logical_line_state(
    content: str,
    line_number: int,
    file_path: str | None,
    state: _StatementScanState,
) -> _StatementScanState:
    index = 0
    while index < len(content):
        char = content[index]

        if state.quote_char is not None:
            index = _scan_quoted_logical_char(content, index, state)
            continue

        if char in {'"', "'"}:
            state.quote_char = char
            index += 1
            continue
        _update_logical_delimiter_state(char, line_number, file_path, state)
        index += 1

    return state


def _scan_quoted_logical_char(
    content: str,
    index: int,
    state: _StatementScanState,
) -> int:
    char = content[index]
    if (
        char == "\\"
        and index + 1 < len(content)
        and content[index + 1] in {state.quote_char, "\\"}
    ):
        return index + 2
    if char == state.quote_char:
        state.quote_char = None
    return index + 1


def _update_logical_delimiter_state(
    char: str,
    line_number: int,
    file_path: str | None,
    state: _StatementScanState,
) -> None:
    if char == "(":
        state.paren_depth += 1
        return
    if char == ")":
        state.paren_depth -= 1
        if state.paren_depth < 0:
            raise LighttpdParseError(
                "Unexpected closing parenthesis",
                line=line_number,
                file_path=file_path,
            )
        return
    if char == "[":
        state.bracket_depth += 1
        return
    if char == "]":
        state.bracket_depth -= 1
        if state.bracket_depth < 0:
            raise LighttpdParseError(
                "Unexpected closing bracket",
                line=line_number,
                file_path=file_path,
            )


def _logical_statement_complete(
    state: _StatementScanState,
    buffer: list[str],
) -> bool:
    return (
        state.quote_char is None
        and state.paren_depth == 0
        and state.bracket_depth == 0
        and bool(buffer)
    )


def _logical_statement_text(buffer: list[str]) -> str:
    return " ".join(part for part in buffer if part).strip()


def _ensure_balanced_statement_state(
    state: _StatementScanState,
    file_path: str | None,
    line: int | None,
) -> None:
    if state.quote_char is not None:
        raise LighttpdParseError(
            "Unterminated quoted string",
            line=line,
            file_path=file_path,
        )
    if state.paren_depth != 0:
        raise LighttpdParseError(
            "Unterminated parenthesized value",
            line=line,
            file_path=file_path,
        )
    if state.bracket_depth != 0:
        raise LighttpdParseError(
            "Unterminated bracketed value",
            line=line,
            file_path=file_path,
        )


def _consume_quoted_argument(
    text: str,
    index: int,
    current: list[str],
    quote_char: str,
) -> tuple[int, str | None]:
    char = text[index]
    if char == "\\" and index + 1 < len(text) and text[index + 1] in {quote_char, "\\"}:
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


def _quoted_scan_state(
    char: str,
    quote_char: str,
    *,
    escaped: bool,
) -> tuple[str | None, bool]:
    if escaped:
        return quote_char, False
    if char == "\\":
        return quote_char, True
    if char == quote_char:
        return None, False
    return quote_char, False


def _updated_delimiter_depths(
    char: str,
    paren_depth: int,
    bracket_depth: int,
) -> tuple[int, int]:
    # ``max(depth - 1, 0)`` silently clamps negative depths rather than
    # raising — unlike ``_update_logical_delimiter_state`` above, which
    # treats an unbalanced closer as a hard parse error.  The asymmetry
    # is intentional: this helper is only ever called from
    # ``_find_assignment_operator``, which walks a *statement that has
    # already been validated* looking for ``=`` / ``+=`` / ``:=``
    # operators.  Any syntax issue has been surfaced earlier, so here we
    # just want the operator scan to stay inside valid ranges even if
    # an earlier rebalancing rounded off a depth we cannot recover from.
    if char == "(":
        return paren_depth + 1, bracket_depth
    if char == ")":
        return max(paren_depth - 1, 0), bracket_depth
    if char == "[":
        return paren_depth, bracket_depth + 1
    if char == "]":
        return paren_depth, max(bracket_depth - 1, 0)
    return paren_depth, bracket_depth


def _assignment_operator_at(
    text: str,
    index: int,
    char: str,
    paren_depth: int,
    bracket_depth: int,
) -> str | None:
    if paren_depth != 0 or bracket_depth != 0:
        return None
    if text.startswith("+=", index):
        return "+="
    if text.startswith(":=", index):
        return ":="
    if char == "=" and not text.startswith("=>", index):
        return "="
    return None


def _iter_unquoted_chars(text: str) -> Iterator[str]:
    for _, char in _iter_unquoted_char_positions(text):
        yield char


def _iter_unquoted_char_positions(text: str) -> Iterator[tuple[int, str]]:
    quote_char: str | None = None
    index = 0

    while index < len(text):
        char = text[index]

        if quote_char is not None:
            if char == "\\" and index + 1 < len(text) and text[index + 1] in {quote_char, "\\"}:
                index += 2
                continue

            if char == quote_char:
                quote_char = None

            index += 1
            continue

        if char in {'"', "'"}:
            quote_char = char
            index += 1
            continue

        yield index, char
        index += 1


_CONDITION_PATTERN = re.compile(
    r"""
    ^
    (\$[A-Z_]+\["[^"]*"\])   # variable: $HTTP["host"], $SERVER["socket"], etc.
    \s*
    (==|!=|=~|!~)             # operator
    \s*
    "([^"]*)"                 # value (unquoted)
    $
    """,
    re.VERBOSE,
)


def _parse_condition(header: str) -> LighttpdCondition | None:
    match = _CONDITION_PATTERN.match(header.strip())
    if match is None:
        return None
    return LighttpdCondition(
        variable=match.group(1),
        operator=match.group(2),
        value=match.group(3),
    )


__all__ = [
    "LighttpdAssignmentNode",
    "LighttpdAstNode",
    "LighttpdBlockNode",
    "LighttpdCondition",
    "LighttpdConfigAst",
    "LighttpdDirectiveNode",
    "LighttpdParseError",
    "LighttpdParser",
    "LighttpdSourceSpan",
    "parse_lighttpd_config",
]

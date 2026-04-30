from __future__ import annotations

from enum import Enum

from pydantic import BaseModel


class TokenType(str, Enum):
    WORD = "WORD"
    LBRACE = "LBRACE"
    RBRACE = "RBRACE"
    SEMICOLON = "SEMICOLON"
    EOF = "EOF"


class Token(BaseModel):
    token_type: TokenType
    value: str
    file_path: str | None = None
    line: int
    column: int

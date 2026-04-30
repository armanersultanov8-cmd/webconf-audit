from __future__ import annotations

from collections.abc import Iterator
from typing import Literal

from pydantic import BaseModel, Field


class SourceSpan(BaseModel):
    file_path: str | None = None
    line: int
    column: int


class DirectiveNode(BaseModel):
    node_type: Literal["directive"] = "directive"
    name: str
    args: list[str] = Field(default_factory=list)
    source: SourceSpan


class BlockNode(BaseModel):
    node_type: Literal["block"] = "block"
    name: str
    args: list[str] = Field(default_factory=list)
    children: list["AstNode"] = Field(default_factory=list)
    source: SourceSpan


AstNode = DirectiveNode | BlockNode


class ConfigAst(BaseModel):
    nodes: list[AstNode] = Field(default_factory=list)


def iter_nodes(nodes: list[AstNode]) -> Iterator[AstNode]:
    for node in nodes:
        yield node

        if isinstance(node, BlockNode):
            yield from iter_nodes(node.children)


def find_child_directives(block: BlockNode, name: str) -> list[DirectiveNode]:
    return [
        child
        for child in block.children
        if isinstance(child, DirectiveNode) and child.name == name
    ]

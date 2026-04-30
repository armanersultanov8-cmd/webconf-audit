"""Load context: captures the file graph produced during include resolution.

Tracks which files were loaded and the include edges between them,
providing a complete picture of configuration sources for reporting
and traceability.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True, slots=True)
class IncludeEdge:
    """An edge in the include graph: source_file includes target_file."""

    source_file: str
    source_line: int | None
    target_file: str


@dataclass(slots=True)
class LoadContext:
    """All files and include relationships discovered during config loading."""

    root_file: str
    files: set[str] = field(default_factory=set)
    edges: list[IncludeEdge] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.files.add(self.root_file)

    def add_edge(self, source: str, source_line: int | None, target: str) -> None:
        """Record an include edge and register both files."""
        self.files.add(source)
        self.files.add(target)
        self.edges.append(IncludeEdge(source, source_line, target))

    def to_dict(self) -> dict[str, object]:
        """Serialize for storage in AnalysisResult.metadata."""
        return {
            "root_file": self.root_file,
            "files": sorted(self.files),
            "edges": [
                {
                    "source_file": e.source_file,
                    "source_line": e.source_line,
                    "target_file": e.target_file,
                }
                for e in self.edges
            ],
        }


__all__ = [
    "IncludeEdge",
    "LoadContext",
]

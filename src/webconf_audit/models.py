from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field

AnalysisMode = Literal["local", "external"]
Severity = Literal["info", "low", "medium", "high", "critical"]
IssueLevel = Literal["warning", "error"]
ResultKind = Literal["finding", "analysis_issue"]
LocationKind = Literal["file", "xml", "endpoint", "url", "header", "tls", "check"]


class SourceLocation(BaseModel):
    mode: AnalysisMode
    kind: LocationKind
    file_path: str | None = None
    line: int | None = None
    xml_path: str | None = None
    target: str | None = None
    details: str | None = None


class _BaseResultEntry(BaseModel):
    location: SourceLocation | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class Finding(_BaseResultEntry):
    kind: Literal["finding"] = "finding"
    rule_id: str
    title: str
    severity: Severity
    description: str
    recommendation: str


class AnalysisIssue(_BaseResultEntry):
    kind: Literal["analysis_issue"] = "analysis_issue"
    code: str
    level: IssueLevel = "warning"
    message: str
    details: str | None = None


class AnalysisResult(BaseModel):
    mode: AnalysisMode
    target: str
    server_type: str | None = None
    findings: list[Finding] = Field(default_factory=list)
    issues: list[AnalysisIssue] = Field(default_factory=list)
    diagnostics: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)

    @property
    def has_findings(self) -> bool:
        return bool(self.findings)

    @property
    def has_issues(self) -> bool:
        return bool(self.issues)


__all__ = [
    "AnalysisIssue",
    "AnalysisMode",
    "AnalysisResult",
    "Finding",
    "IssueLevel",
    "LocationKind",
    "ResultKind",
    "Severity",
    "SourceLocation",
]

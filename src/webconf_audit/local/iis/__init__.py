from __future__ import annotations

from pathlib import Path

from webconf_audit.local.iis.discovery import discover_iis_sites, locate_machine_config
from webconf_audit.local.iis.effective import (
    IISEffectiveConfig,
    build_effective_config,
    merge_effective_configs,
)
from webconf_audit.local.iis.parser import (
    IISConfigDocument,
    IISParseError,
    parse_iis_config,
)
from webconf_audit.local.iis.rules_runner import run_iis_rules
from webconf_audit.local.normalizers import normalize_config
from webconf_audit.local.universal_rules import run_universal_rules
from webconf_audit.models import AnalysisIssue, AnalysisResult, Finding, SourceLocation


def analyze_iis_config(
    config_path: str,
    machine_config_path: str | None = None,
) -> AnalysisResult:
    path = Path(config_path)

    if path.is_dir():
        app_host = path / "applicationHost.config"
        if app_host.is_file():
            path = app_host
        else:
            web_config = path / "web.config"
            if web_config.is_file():
                path = web_config
            else:
                return AnalysisResult(
                    mode="local",
                    target=config_path,
                    server_type="iis",
                    issues=[
                        AnalysisIssue(
                            code="config_not_found",
                            level="error",
                            message=f"No IIS config found in directory: {config_path}",
                            location=SourceLocation(
                                mode="local",
                                kind="file",
                                file_path=config_path,
                            ),
                        )
                    ],
                )

    if not path.is_file():
        return AnalysisResult(
            mode="local",
            target=config_path,
            server_type="iis",
            issues=[
                AnalysisIssue(
                    code="config_not_found",
                    level="error",
                    message=f"Config file not found: {config_path}",
                    location=SourceLocation(
                        mode="local",
                        kind="file",
                        file_path=config_path,
                    ),
                )
            ],
        )

    try:
        text = path.read_text(encoding="utf-8-sig")
    except OSError as exc:
        return AnalysisResult(
            mode="local",
            target=config_path,
            server_type="iis",
            issues=[
                AnalysisIssue(
                    code="iis_config_read_error",
                    level="error",
                    message=f"Cannot read config file: {exc}",
                    location=SourceLocation(
                        mode="local",
                        kind="file",
                        file_path=str(path),
                    ),
                )
            ],
        )

    try:
        doc = parse_iis_config(text, file_path=str(path))
    except IISParseError as exc:
        return AnalysisResult(
            mode="local",
            target=config_path,
            server_type="iis",
            issues=[
                AnalysisIssue(
                    code="iis_parse_error",
                    level="error",
                    message=str(exc),
                    location=SourceLocation(
                        mode="local",
                        kind="xml",
                        file_path=exc.file_path or str(path),
                        line=exc.line,
                    ),
                )
            ],
        )

    if doc.config_kind == "applicationHost":
        return _analyze_application_host(
            doc,
            config_path,
            machine_config_path=machine_config_path,
        )

    return _analyze_single_config(
        doc,
        config_path,
        machine_config_path=machine_config_path,
    )


def _analyze_single_config(
    doc: IISConfigDocument,
    config_path: str,
    *,
    machine_config_path: str | None = None,
) -> AnalysisResult:
    """Analyze a single IIS config file (web.config, machine.config, standalone)."""
    issues: list[AnalysisIssue] = []
    effective = build_effective_config(doc)

    inheritance_chain = [doc.file_path or config_path]
    loaded_machine_config_path: str | None = None
    if doc.config_kind != "machine" and machine_config_path is not None:
        machine_doc, machine_issues, loaded_machine_config_path = _load_optional_machine_config(
            machine_config_path
        )
        issues.extend(machine_issues)
        if machine_doc is not None:
            machine_effective = build_effective_config(machine_doc)
            effective = merge_effective_configs(machine_effective, effective)
            inheritance_chain = [loaded_machine_config_path, *inheritance_chain]
    elif doc.config_kind == "machine":
        loaded_machine_config_path = doc.file_path or config_path

    metadata: dict[str, object] = {
        "config_kind": doc.config_kind,
        "root_tag": doc.root_tag,
        "section_count": len(doc.sections),
        "top_level_sections": [
            s.tag for s in doc.sections if s.xml_path.count("/") == 1
        ],
        "machine_config_path": loaded_machine_config_path,
        "inheritance_chain": inheritance_chain,
    }

    findings = run_iis_rules(doc, effective_config=effective, issues=issues)
    normalized = normalize_config("iis", doc=doc, effective_config=effective)
    findings.extend(run_universal_rules(normalized, issues=issues))

    return AnalysisResult(
        mode="local",
        target=config_path,
        server_type="iis",
        findings=findings,
        issues=issues,
        metadata=metadata,
    )


def _analyze_application_host(
    doc: IISConfigDocument,
    config_path: str,
    *,
    machine_config_path: str | None = None,
) -> AnalysisResult:
    """Analyze applicationHost.config with discovered sites/apps and optional machine.config."""
    all_findings: list[Finding] = []
    all_issues: list[AnalysisIssue] = []

    discovery = discover_iis_sites(doc, machine_config_path=machine_config_path)
    all_issues.extend(discovery.issues)

    base_effective = build_effective_config(doc)
    base_chain = [doc.file_path or config_path]

    machine_doc: IISConfigDocument | None = None
    if discovery.machine_config_path is not None:
        machine_doc, machine_issues = _try_parse_iis_config_path(
            discovery.machine_config_path,
            issue_level="warning",
            read_error_message="Cannot read machine.config",
            parse_error_prefix="Parse error in machine.config",
        )
        all_issues.extend(machine_issues)
        if machine_doc is not None:
            machine_effective = build_effective_config(machine_doc)
            base_effective = merge_effective_configs(machine_effective, base_effective)
            base_chain = [discovery.machine_config_path, *base_chain]

    all_findings.extend(run_iis_rules(doc, effective_config=base_effective, issues=all_issues))
    normalized = normalize_config("iis", doc=doc, effective_config=base_effective)
    all_findings.extend(run_universal_rules(normalized, issues=all_issues))

    site_details: list[dict[str, object]] = []
    inheritance_chains: list[list[str]] = []

    for site in discovery.sites:
        site_info: dict[str, object] = {
            "name": site.name,
            "id": site.site_id,
            "applications": [],
        }
        for app in site.applications:
            for vdir in app.virtual_directories:
                if vdir.web_config_path is None:
                    continue

                site_findings, site_issues = _analyze_web_config_with_base(
                    vdir.web_config_path,
                    base_effective,
                )
                all_findings.extend(site_findings)
                all_issues.extend(site_issues)

                chain = [*base_chain, vdir.web_config_path]
                inheritance_chains.append(chain)

                app_info = {
                    "app_path": app.app_path,
                    "physical_path": vdir.physical_path,
                    "web_config": vdir.web_config_path,
                    "findings_count": len(site_findings),
                    "inheritance_chain": chain,
                }
                apps_list = site_info["applications"]
                if isinstance(apps_list, list):
                    apps_list.append(app_info)

        site_details.append(site_info)

    metadata: dict[str, object] = {
        "config_kind": doc.config_kind,
        "root_tag": doc.root_tag,
        "section_count": len(doc.sections),
        "sites_discovered": len(discovery.sites),
        "web_configs_found": len(discovery.all_web_configs),
        "sites": site_details,
        "machine_config_path": discovery.machine_config_path,
        "inheritance_chain": inheritance_chains[0] if len(inheritance_chains) == 1 else base_chain,
        "inheritance_chains": inheritance_chains,
    }

    return AnalysisResult(
        mode="local",
        target=config_path,
        server_type="iis",
        findings=all_findings,
        issues=all_issues,
        metadata=metadata,
    )


def _analyze_web_config_with_base(
    web_config_path: str,
    base_effective: IISEffectiveConfig,
) -> tuple[list[Finding], list[AnalysisIssue]]:
    """Parse and analyze a web.config, merging with base effective config."""
    findings: list[Finding] = []
    issues: list[AnalysisIssue] = []

    site_doc, parse_issues = _try_parse_iis_config_path(
        web_config_path,
        issue_level="warning",
        read_error_message="Cannot read web.config",
        parse_error_prefix=f"Parse error in {web_config_path}",
    )
    issues.extend(parse_issues)
    if site_doc is None:
        return findings, issues

    site_effective = build_effective_config(site_doc)
    merged = merge_effective_configs(base_effective, site_effective)

    findings.extend(run_iis_rules(site_doc, effective_config=merged, issues=issues))
    normalized = normalize_config("iis", doc=site_doc, effective_config=merged)
    findings.extend(run_universal_rules(normalized, issues=issues))

    return findings, issues


def _load_optional_machine_config(
    machine_config_path: str,
) -> tuple[IISConfigDocument | None, list[AnalysisIssue], str | None]:
    resolved = locate_machine_config(machine_config_path)
    if resolved is None:
        return None, [], None

    doc, issues = _try_parse_iis_config_path(
        resolved,
        issue_level="warning",
        read_error_message="Cannot read machine.config",
        parse_error_prefix="Parse error in machine.config",
    )
    return doc, issues, str(resolved)


def _try_parse_iis_config_path(
    config_path: str | Path,
    *,
    issue_level: str,
    read_error_message: str,
    parse_error_prefix: str,
) -> tuple[IISConfigDocument | None, list[AnalysisIssue]]:
    path = Path(config_path)

    try:
        # Mirror ``analyze_iis_config`` and use ``utf-8-sig`` so the
        # UTF-8 BOM that IIS commonly writes into ``applicationHost.config``
        # / ``machine.config`` / site ``web.config`` on Windows is stripped
        # before the XML parser sees it — otherwise a leading ``\ufeff``
        # makes ``ET.fromstring`` raise ``XML or text declaration not at
        # start of entity`` and the helper fails where the primary path
        # would have succeeded.
        text = path.read_text(encoding="utf-8-sig")
    except OSError as exc:
        return None, [
            AnalysisIssue(
                code="iis_config_read_error",
                level=issue_level,
                message=f"{read_error_message}: {exc}",
                location=SourceLocation(
                    mode="local",
                    kind="file",
                    file_path=str(path),
                ),
            )
        ]

    try:
        return parse_iis_config(text, file_path=str(path)), []
    except IISParseError as exc:
        return None, [
            AnalysisIssue(
                code="iis_parse_error",
                level=issue_level,
                message=f"{parse_error_prefix}: {exc}",
                location=SourceLocation(
                    mode="local",
                    kind="xml",
                    file_path=exc.file_path or str(path),
                    line=exc.line,
                ),
            )
        ]


__all__ = ["analyze_iis_config"]

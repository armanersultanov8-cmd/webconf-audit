"""IIS multi-file discovery: extract sites/apps from applicationHost.config.

Given a parsed applicationHost.config, discovers all ``<site>`` elements,
their ``<application>`` children, ``<virtualDirectory>`` physical paths,
and probes for ``web.config`` files at those locations.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

from webconf_audit.local.iis.parser import IISConfigDocument, IISSection
from webconf_audit.models import AnalysisIssue, SourceLocation


@dataclass(frozen=True, slots=True)
class IISVirtualDirectory:
    """A virtual directory within an application."""

    vdir_path: str  # e.g. "/"
    physical_path: str  # e.g. "C:/inetpub/wwwroot"
    web_config_path: str | None  # resolved path if web.config exists


@dataclass(frozen=True, slots=True)
class IISSiteApplication:
    """One application within a site."""

    app_path: str  # e.g. "/" or "/api"
    application_pool: str | None
    virtual_directories: list[IISVirtualDirectory]


@dataclass(frozen=True, slots=True)
class IISSiteInfo:
    """A site discovered from applicationHost.config."""

    name: str
    site_id: str
    applications: list[IISSiteApplication]
    bindings: list[dict[str, str]]  # raw binding attributes


@dataclass(slots=True)
class IISDiscoveryResult:
    """Result of multi-file discovery from applicationHost.config."""

    sites: list[IISSiteInfo] = field(default_factory=list)
    issues: list[AnalysisIssue] = field(default_factory=list)
    machine_config_path: str | None = None

    @property
    def all_web_configs(self) -> list[str]:
        """Flat list of all discovered web.config paths."""
        result: list[str] = []
        for site in self.sites:
            for app in site.applications:
                for vdir in app.virtual_directories:
                    if vdir.web_config_path is not None:
                        result.append(vdir.web_config_path)
        return result


def locate_machine_config(
    framework_hint: str | Path | None = None,
) -> Path | None:
    """Locate machine.config using common .NET Framework installation paths."""
    explicit = _coerce_explicit_machine_config(framework_hint)
    if explicit is not None:
        return explicit if explicit.is_file() else None

    windir = os.environ.get("WINDIR")
    if not windir:
        return None

    framework_roots = _ordered_framework_roots(framework_hint)
    for framework_root in framework_roots:
        candidate = (
            Path(windir)
            / "Microsoft.NET"
            / framework_root
            / "v4.0.30319"
            / "Config"
            / "machine.config"
        )
        if candidate.is_file():
            return candidate

    return None


def discover_iis_sites(
    doc: IISConfigDocument,
    *,
    machine_config_path: str | None = None,
) -> IISDiscoveryResult:
    """Extract sites, applications, and web.config paths from applicationHost.config."""
    machine_path = locate_machine_config(machine_config_path)
    result = IISDiscoveryResult(
        machine_config_path=str(machine_path) if machine_path is not None else None,
    )

    if doc.config_kind != "applicationHost":
        return result

    # The parser produces a flat list of sections.  Site/application/
    # virtualDirectory hierarchy must be reconstructed from ordering:
    # each "site" section is followed by its children until the next "site".
    site_groups = _group_site_sections(doc.sections)

    for site_section, child_sections in site_groups:
        site_name = site_section.attributes.get("name", "<unnamed>")
        site_id = site_section.attributes.get("id", "")

        applications = _extract_applications(child_sections, site_name, result)
        bindings = _extract_bindings(child_sections)

        result.sites.append(
            IISSiteInfo(
                name=site_name,
                site_id=site_id,
                applications=applications,
                bindings=bindings,
            )
        )

    return result


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

_SITES_PREFIX = "configuration/system.applicationHost/sites/site"


def _group_site_sections(
    sections: list[IISSection],
) -> list[tuple[IISSection, list[IISSection]]]:
    """Group flat section list into (site_section, child_sections) pairs.

    The parser emits sections depth-first.  Each ``<site>`` section is
    followed by its nested elements (application, virtualDirectory,
    bindings) until the next ``<site>`` at the same xml_path depth.
    """
    groups: list[tuple[IISSection, list[IISSection]]] = []
    current_site: IISSection | None = None
    current_children: list[IISSection] = []

    for section in sections:
        if section.tag == "site" and section.xml_path == _SITES_PREFIX:
            if current_site is not None:
                groups.append((current_site, current_children))
            current_site = section
            current_children = []
        elif current_site is not None and section.xml_path.startswith(
            _SITES_PREFIX + "/"
        ):
            current_children.append(section)

    if current_site is not None:
        groups.append((current_site, current_children))

    return groups


def _extract_applications(
    child_sections: list[IISSection],
    site_name: str,
    result: IISDiscoveryResult,
) -> list[IISSiteApplication]:
    """Extract application→virtualDirectory hierarchy from child sections."""
    apps: list[IISSiteApplication] = []
    current_app: IISSection | None = None
    current_vdirs: list[IISSection] = []

    for section in child_sections:
        if section.tag == "application":
            if current_app is not None:
                apps.append(
                    _build_application(current_app, current_vdirs, site_name, result)
                )
            current_app = section
            current_vdirs = []
        elif section.tag == "virtualDirectory" and current_app is not None:
            current_vdirs.append(section)

    if current_app is not None:
        apps.append(
            _build_application(current_app, current_vdirs, site_name, result)
        )

    return apps


def _build_application(
    app_section: IISSection,
    vdir_sections: list[IISSection],
    site_name: str,
    result: IISDiscoveryResult,
) -> IISSiteApplication:
    app_path = app_section.attributes.get("path", "/")
    app_pool = app_section.attributes.get("applicationPool")

    virtual_dirs: list[IISVirtualDirectory] = []
    for vdir in vdir_sections:
        physical_path = vdir.attributes.get("physicalPath")
        if physical_path is None:
            result.issues.append(
                AnalysisIssue(
                    code="iis_vdir_no_physical_path",
                    level="warning",
                    message=(
                        f"virtualDirectory in site '{site_name}' app '{app_path}' "
                        f"has no physicalPath attribute"
                    ),
                    location=SourceLocation(
                        mode="local",
                        kind="xml",
                        file_path=vdir.source.file_path,
                        xml_path=vdir.source.xml_path,
                    ),
                )
            )
            continue

        web_config = _probe_web_config(physical_path)
        if web_config is None and Path(physical_path).is_dir():
            # Directory exists but no web.config — not an error, just no override.
            pass
        elif not Path(physical_path).is_dir():
            result.issues.append(
                AnalysisIssue(
                    code="iis_physical_path_not_found",
                    level="warning",
                    message=(
                        f"physicalPath '{physical_path}' for site '{site_name}' "
                        f"app '{app_path}' does not exist or is not a directory"
                    ),
                    location=SourceLocation(
                        mode="local",
                        kind="xml",
                        file_path=vdir.source.file_path,
                        xml_path=vdir.source.xml_path,
                    ),
                )
            )

        virtual_dirs.append(
            IISVirtualDirectory(
                vdir_path=vdir.attributes.get("path", "/"),
                physical_path=physical_path,
                web_config_path=web_config,
            )
        )

    return IISSiteApplication(
        app_path=app_path,
        application_pool=app_pool,
        virtual_directories=virtual_dirs,
    )


def _extract_bindings(child_sections: list[IISSection]) -> list[dict[str, str]]:
    """Extract binding attributes from bindings section children."""
    bindings: list[dict[str, str]] = []
    for section in child_sections:
        if section.tag == "bindings":
            for child in section.children:
                if child.tag == "binding":
                    bindings.append(dict(child.attributes))
    return bindings


def _probe_web_config(physical_path: str) -> str | None:
    """Return web.config path if it exists under the given directory."""
    candidate = Path(physical_path) / "web.config"
    if candidate.is_file():
        return str(candidate)
    return None


def _coerce_explicit_machine_config(
    framework_hint: str | Path | None,
) -> Path | None:
    if framework_hint is None:
        return None
    if isinstance(framework_hint, Path):
        return framework_hint

    lowered = framework_hint.lower()
    if lowered in {"framework", "framework64", "32", "64"}:
        return None

    if lowered.endswith(".config") or "/" in framework_hint or "\\" in framework_hint:
        return Path(framework_hint)

    return None


def _ordered_framework_roots(
    framework_hint: str | Path | None,
) -> tuple[str, ...]:
    if isinstance(framework_hint, str):
        lowered = framework_hint.lower()
        if lowered in {"framework64", "64"}:
            return ("Framework64", "Framework")
        if lowered in {"framework", "32"}:
            return ("Framework", "Framework64")

    return ("Framework64", "Framework")


__all__ = [
    "IISDiscoveryResult",
    "IISSiteApplication",
    "IISSiteInfo",
    "IISVirtualDirectory",
    "discover_iis_sites",
    "locate_machine_config",
]

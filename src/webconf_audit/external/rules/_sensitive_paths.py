from __future__ import annotations

from typing import TYPE_CHECKING

from webconf_audit.external.rules._helpers import (
    _is_accessible_status,
    _is_apache_conditional_applicable,
    _is_lighttpd_conditional_applicable,
    _probe_body_contains,
    _probe_body_looks_like_env_file,
)
from webconf_audit.models import Finding, SourceLocation

if TYPE_CHECKING:
    from webconf_audit.external.recon import SensitivePathProbe, ServerIdentification


def _find_git_metadata_exposed(
    path_probes: list["SensitivePathProbe"],
) -> list[Finding]:
    findings: list[Finding] = []

    for probe in path_probes:
        if probe.path != "/.git/HEAD":
            continue
        if not _is_accessible_status(probe.status_code):
            continue
        if probe.body_snippet is None or "ref:" not in probe.body_snippet:
            continue

        findings.append(
            Finding(
                rule_id="external.git_metadata_exposed",
                title="Git metadata exposed",
                severity="high",
                description=(
                    "The /.git/HEAD file is externally accessible and contains "
                    "Git metadata. This may allow attackers to reconstruct "
                    "source code or discover sensitive information."
                ),
                recommendation=("Block external access to the /.git/ directory on the web server."),
                location=SourceLocation(
                    mode="external",
                    kind="url",
                    target=probe.url,
                    details="/.git/HEAD",
                ),
            )
        )

    return findings


def _find_server_status_exposed(
    path_probes: list["SensitivePathProbe"],
    server_identification: "ServerIdentification | None" = None,
) -> list[Finding]:
    findings: list[Finding] = []

    for probe in path_probes:
        if probe.path not in {"/server-status", "/server-status?auto"}:
            continue
        if not _is_accessible_status(probe.status_code):
            continue
        if _is_apache_conditional_applicable(server_identification):
            continue
        if probe.path == "/server-status" and _is_lighttpd_conditional_applicable(
            server_identification
        ):
            continue

        findings.append(
            Finding(
                rule_id="external.server_status_exposed",
                title="Server status page exposed",
                severity="medium",
                description=(
                    "The /server-status endpoint is externally accessible. "
                    "This page can disclose internal server metrics, client IPs, "
                    "and request details to unauthenticated users."
                ),
                recommendation=(
                    "Restrict access to /server-status to trusted networks "
                    "or disable it in the server configuration."
                ),
                location=SourceLocation(
                    mode="external",
                    kind="url",
                    target=probe.url,
                    details=probe.path,
                ),
            )
        )

    return findings


def _find_server_info_exposed(
    path_probes: list["SensitivePathProbe"],
) -> list[Finding]:
    findings: list[Finding] = []

    for probe in path_probes:
        if probe.path != "/server-info":
            continue
        if not _is_accessible_status(probe.status_code):
            continue

        findings.append(
            Finding(
                rule_id="external.server_info_exposed",
                title="Server info page exposed",
                severity="medium",
                description=(
                    "The /server-info endpoint is externally accessible. "
                    "This page can disclose detailed server configuration, "
                    "loaded modules, and internal settings."
                ),
                recommendation=(
                    "Restrict access to /server-info to trusted networks "
                    "or disable it in the server configuration."
                ),
                location=SourceLocation(
                    mode="external",
                    kind="url",
                    target=probe.url,
                    details="/server-info",
                ),
            )
        )

    return findings


def _find_nginx_status_exposed(
    path_probes: list["SensitivePathProbe"],
) -> list[Finding]:
    findings: list[Finding] = []

    for probe in path_probes:
        if probe.path != "/nginx_status":
            continue
        if not _is_accessible_status(probe.status_code):
            continue

        findings.append(
            Finding(
                rule_id="external.nginx_status_exposed",
                title="Nginx status page exposed",
                severity="low",
                description=(
                    "The /nginx_status endpoint is externally accessible. "
                    "This stub status page discloses connection and request "
                    "counters that may aid reconnaissance."
                ),
                recommendation=(
                    "Restrict access to the nginx stub_status endpoint "
                    "to trusted networks or disable it."
                ),
                location=SourceLocation(
                    mode="external",
                    kind="url",
                    target=probe.url,
                    details="/nginx_status",
                ),
            )
        )

    return findings


def _find_env_file_exposed(
    path_probes: list["SensitivePathProbe"],
) -> list[Finding]:
    findings: list[Finding] = []

    for probe in path_probes:
        if probe.path != "/.env":
            continue
        if not _is_accessible_status(probe.status_code):
            continue
        if not _probe_body_looks_like_env_file(probe):
            continue

        findings.append(
            Finding(
                rule_id="external.env_file_exposed",
                title=".env file exposed",
                severity="high",
                description=(
                    "The /.env file is externally accessible and appears to contain "
                    "environment variable assignments. This can expose secrets and "
                    "deployment configuration."
                ),
                recommendation=(
                    "Block public access to /.env files and move secrets to a "
                    "secure secret-management mechanism."
                ),
                location=SourceLocation(
                    mode="external",
                    kind="url",
                    target=probe.url,
                    details="/.env",
                ),
            )
        )

    return findings


def _find_htaccess_exposed(
    path_probes: list["SensitivePathProbe"],
) -> list[Finding]:
    findings: list[Finding] = []

    for probe in path_probes:
        if probe.path != "/.htaccess":
            continue
        if not _is_accessible_status(probe.status_code):
            continue

        findings.append(
            Finding(
                rule_id="external.htaccess_exposed",
                title=".htaccess file exposed",
                severity="medium",
                description=(
                    "The /.htaccess file is externally accessible. It can disclose "
                    "Apache rewrite rules, access-control directives, and internal "
                    "application structure."
                ),
                recommendation=(
                    "Deny external access to Apache configuration files such as .htaccess."
                ),
                location=SourceLocation(
                    mode="external",
                    kind="url",
                    target=probe.url,
                    details="/.htaccess",
                ),
            )
        )

    return findings


def _find_htpasswd_exposed(
    path_probes: list["SensitivePathProbe"],
) -> list[Finding]:
    findings: list[Finding] = []

    for probe in path_probes:
        if probe.path != "/.htpasswd":
            continue
        if not _is_accessible_status(probe.status_code):
            continue

        findings.append(
            Finding(
                rule_id="external.htpasswd_exposed",
                title=".htpasswd file exposed",
                severity="high",
                description=(
                    "The /.htpasswd file is externally accessible. It can expose "
                    "password hashes or account names used for HTTP "
                    "authentication."
                ),
                recommendation=(
                    "Block public access to .htpasswd files and rotate any "
                    "credentials that may have been exposed."
                ),
                location=SourceLocation(
                    mode="external",
                    kind="url",
                    target=probe.url,
                    details="/.htpasswd",
                ),
            )
        )

    return findings


def _find_wordpress_admin_panel_exposed(
    path_probes: list["SensitivePathProbe"],
) -> list[Finding]:
    findings: list[Finding] = []

    for probe in path_probes:
        if probe.path != "/wp-admin/":
            continue
        if not _is_accessible_status(probe.status_code):
            continue

        findings.append(
            Finding(
                rule_id="external.wordpress_admin_panel_exposed",
                title="WordPress admin panel exposed",
                severity="low",
                description=(
                    "The /wp-admin/ endpoint is externally reachable. Public access "
                    "to the administrative login surface increases enumeration and "
                    "brute-force exposure."
                ),
                recommendation=(
                    "Restrict access to the WordPress admin panel with additional "
                    "network or identity controls where practical."
                ),
                location=SourceLocation(
                    mode="external",
                    kind="url",
                    target=probe.url,
                    details="/wp-admin/",
                ),
            )
        )

    return findings


def _find_phpinfo_exposed(
    path_probes: list["SensitivePathProbe"],
) -> list[Finding]:
    findings: list[Finding] = []

    for probe in path_probes:
        if probe.path != "/phpinfo.php":
            continue
        if not _is_accessible_status(probe.status_code):
            continue
        if not _probe_body_contains(probe, "phpinfo()"):
            continue

        findings.append(
            Finding(
                rule_id="external.phpinfo_exposed",
                title="phpinfo page exposed",
                severity="medium",
                description=(
                    "The /phpinfo.php page is externally accessible and appears to "
                    "disclose PHP runtime and environment details."
                ),
                recommendation=(
                    "Remove phpinfo pages from production systems or restrict them "
                    "to trusted administrators."
                ),
                location=SourceLocation(
                    mode="external",
                    kind="url",
                    target=probe.url,
                    details="/phpinfo.php",
                ),
            )
        )

    return findings


def _find_elmah_axd_exposed(
    path_probes: list["SensitivePathProbe"],
) -> list[Finding]:
    findings: list[Finding] = []

    for probe in path_probes:
        if probe.path != "/elmah.axd":
            continue
        if not _is_accessible_status(probe.status_code):
            continue

        findings.append(
            Finding(
                rule_id="external.elmah_axd_exposed",
                title="ELMAH error log endpoint exposed",
                severity="medium",
                description=(
                    "The /elmah.axd endpoint is externally accessible. It can expose "
                    "application errors, stack traces, request data, and sensitive "
                    "operational details."
                ),
                recommendation=(
                    "Restrict ELMAH access to trusted users or disable the endpoint in production."
                ),
                location=SourceLocation(
                    mode="external",
                    kind="url",
                    target=probe.url,
                    details="/elmah.axd",
                ),
            )
        )

    return findings


def _find_trace_axd_exposed(
    path_probes: list["SensitivePathProbe"],
) -> list[Finding]:
    findings: list[Finding] = []

    for probe in path_probes:
        if probe.path != "/trace.axd":
            continue
        if not _is_accessible_status(probe.status_code):
            continue

        findings.append(
            Finding(
                rule_id="external.trace_axd_exposed",
                title="ASP.NET trace endpoint exposed",
                severity="high",
                description=(
                    "The /trace.axd endpoint is externally accessible. ASP.NET "
                    "trace output can expose requests, headers, session data, and "
                    "internal application behavior."
                ),
                recommendation=(
                    "Disable ASP.NET tracing in production or restrict access to "
                    "trusted administrators."
                ),
                location=SourceLocation(
                    mode="external",
                    kind="url",
                    target=probe.url,
                    details="/trace.axd",
                ),
            )
        )

    return findings


def _find_web_config_exposed(
    path_probes: list["SensitivePathProbe"],
) -> list[Finding]:
    findings: list[Finding] = []

    for probe in path_probes:
        if probe.path != "/web.config":
            continue
        if not _is_accessible_status(probe.status_code):
            continue
        if not _probe_body_contains(probe, "<configuration"):
            continue

        findings.append(
            Finding(
                rule_id="external.web_config_exposed",
                title="web.config exposed",
                severity="high",
                description=(
                    "The /web.config file is externally accessible and appears to "
                    "contain IIS or ASP.NET configuration data."
                ),
                recommendation=(
                    "Block direct access to web.config and rotate any secrets that "
                    "may have been disclosed."
                ),
                location=SourceLocation(
                    mode="external",
                    kind="url",
                    target=probe.url,
                    details="/web.config",
                ),
            )
        )

    return findings


def _find_robots_txt_exposed(
    path_probes: list["SensitivePathProbe"],
) -> list[Finding]:
    findings: list[Finding] = []

    for probe in path_probes:
        if probe.path != "/robots.txt":
            continue
        if not _is_accessible_status(probe.status_code):
            continue

        findings.append(
            Finding(
                rule_id="external.robots_txt_exposed",
                title="robots.txt exposed",
                severity="info",
                description=(
                    "The /robots.txt file is externally accessible. It may reveal "
                    "administrative or non-indexed paths that are useful during "
                    "reconnaissance."
                ),
                recommendation=(
                    "Review robots.txt contents to avoid disclosing sensitive or "
                    "unnecessary internal paths."
                ),
                location=SourceLocation(
                    mode="external",
                    kind="url",
                    target=probe.url,
                    details="/robots.txt",
                ),
            )
        )

    return findings


def _find_sitemap_xml_exposed(
    path_probes: list["SensitivePathProbe"],
) -> list[Finding]:
    findings: list[Finding] = []

    for probe in path_probes:
        if probe.path != "/sitemap.xml":
            continue
        if not _is_accessible_status(probe.status_code):
            continue

        findings.append(
            Finding(
                rule_id="external.sitemap_xml_exposed",
                title="sitemap.xml exposed",
                severity="info",
                description=(
                    "The /sitemap.xml file is externally accessible. It may reveal "
                    "site structure and endpoints that aid reconnaissance."
                ),
                recommendation=(
                    "Review sitemap contents to ensure they do not advertise "
                    "sensitive or unnecessary endpoints."
                ),
                location=SourceLocation(
                    mode="external",
                    kind="url",
                    target=probe.url,
                    details="/sitemap.xml",
                ),
            )
        )

    return findings


def _find_svn_metadata_exposed(
    path_probes: list["SensitivePathProbe"],
) -> list[Finding]:
    findings: list[Finding] = []

    for probe in path_probes:
        if probe.path != "/.svn/entries":
            continue
        if not _is_accessible_status(probe.status_code):
            continue

        findings.append(
            Finding(
                rule_id="external.svn_metadata_exposed",
                title="SVN metadata exposed",
                severity="medium",
                description=(
                    "The /.svn/entries file is externally accessible. Subversion "
                    "metadata can disclose repository structure and historical "
                    "project details."
                ),
                recommendation=(
                    "Block public access to .svn directories and remove any "
                    "version-control metadata from deployed web roots."
                ),
                location=SourceLocation(
                    mode="external",
                    kind="url",
                    target=probe.url,
                    details="/.svn/entries",
                ),
            )
        )

    return findings


def collect_sensitive_path_findings(
    path_probes: list["SensitivePathProbe"],
    server_identification: "ServerIdentification | None" = None,
) -> list[Finding]:
    findings: list[Finding] = []
    findings.extend(_find_git_metadata_exposed(path_probes))
    findings.extend(
        _find_server_status_exposed(
            path_probes,
            server_identification=server_identification,
        )
    )
    findings.extend(_find_server_info_exposed(path_probes))
    findings.extend(_find_nginx_status_exposed(path_probes))
    findings.extend(_find_env_file_exposed(path_probes))
    findings.extend(_find_htaccess_exposed(path_probes))
    findings.extend(_find_htpasswd_exposed(path_probes))
    findings.extend(_find_wordpress_admin_panel_exposed(path_probes))
    findings.extend(_find_phpinfo_exposed(path_probes))
    findings.extend(_find_elmah_axd_exposed(path_probes))
    findings.extend(_find_trace_axd_exposed(path_probes))
    findings.extend(_find_web_config_exposed(path_probes))
    findings.extend(_find_robots_txt_exposed(path_probes))
    findings.extend(_find_sitemap_xml_exposed(path_probes))
    findings.extend(_find_svn_metadata_exposed(path_probes))
    return findings


__all__ = [
    "collect_sensitive_path_findings",
]

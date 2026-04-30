from pathlib import Path

from webconf_audit.local.iis import analyze_iis_config
from webconf_audit.local.iis.discovery import discover_iis_sites, locate_machine_config
from webconf_audit.local.iis.effective import (
    IISEffectiveConfig,
    build_effective_config,
    merge_effective_configs,
)
from webconf_audit.local.iis.parser import parse_iis_config


def _write(path: Path, content: str) -> Path:
    path.write_text(content, encoding="utf-8")
    return path


def _application_host_config(site_root: Path) -> str:
    physical_path = site_root.as_posix()
    return f"""\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.applicationHost>
        <sites>
            <site name="Default Web Site" id="1">
                <application path="/" applicationPool="DefaultAppPool">
                    <virtualDirectory path="/" physicalPath="{physical_path}" />
                </application>
                <bindings>
                    <binding protocol="http" bindingInformation="*:80:example.test" />
                </bindings>
            </site>
        </sites>
    </system.applicationHost>
    <system.webServer>
        <directoryBrowse enabled="false" />
    </system.webServer>
    <system.web>
        <customErrors mode="RemoteOnly" />
    </system.web>
</configuration>
"""


def test_discover_iis_sites_finds_site_application_and_web_config(tmp_path: Path) -> None:
    site_root = tmp_path / "site"
    site_root.mkdir()
    web_config = _write(
        site_root / "web.config",
        "<?xml version='1.0'?><configuration />",
    )
    app_host_path = tmp_path / "applicationHost.config"
    app_host_doc = parse_iis_config(
        _application_host_config(site_root),
        file_path=str(app_host_path),
    )

    result = discover_iis_sites(app_host_doc)

    assert result.issues == []
    assert len(result.sites) == 1
    site = result.sites[0]
    assert site.name == "Default Web Site"
    assert site.site_id == "1"
    assert site.bindings == [{"protocol": "http", "bindingInformation": "*:80:example.test"}]
    assert len(site.applications) == 1
    app = site.applications[0]
    assert app.app_path == "/"
    assert app.application_pool == "DefaultAppPool"
    assert len(app.virtual_directories) == 1
    vdir = app.virtual_directories[0]
    assert vdir.vdir_path == "/"
    assert vdir.physical_path == site_root.as_posix()
    assert vdir.web_config_path == str(web_config)
    assert result.all_web_configs == [str(web_config)]


def test_locate_machine_config_finds_framework64_first(tmp_path: Path, monkeypatch) -> None:
    windir = tmp_path / "Windows"
    machine = windir / "Microsoft.NET" / "Framework64" / "v4.0.30319" / "Config" / "machine.config"
    machine.parent.mkdir(parents=True)
    machine.write_text("<configuration />", encoding="utf-8")
    monkeypatch.setenv("WINDIR", str(windir))

    result = locate_machine_config()

    assert result == machine


def test_locate_machine_config_returns_none_when_missing(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("WINDIR", str(tmp_path / "Windows"))

    result = locate_machine_config()

    assert result is None


def test_locate_machine_config_accepts_explicit_path(tmp_path: Path) -> None:
    machine = tmp_path / "custom-machine.config"
    machine.write_text("<configuration />", encoding="utf-8")

    result = locate_machine_config(str(machine))

    assert result == machine


def test_discover_iis_sites_reports_missing_physical_path_attribute(tmp_path: Path) -> None:
    app_host_path = tmp_path / "applicationHost.config"
    doc = parse_iis_config(
        """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.applicationHost>
        <sites>
            <site name="Default Web Site" id="1">
                <application path="/">
                    <virtualDirectory path="/" />
                </application>
            </site>
        </sites>
    </system.applicationHost>
</configuration>
""",
        file_path=str(app_host_path),
    )

    result = discover_iis_sites(doc)

    assert len(result.issues) == 1
    issue = result.issues[0]
    assert issue.code == "iis_vdir_no_physical_path"
    assert issue.location is not None
    assert issue.location.kind == "xml"


def test_discover_iis_sites_populates_machine_config_path(tmp_path: Path, monkeypatch) -> None:
    site_root = tmp_path / "site"
    site_root.mkdir()
    app_host_path = tmp_path / "applicationHost.config"
    doc = parse_iis_config(
        _application_host_config(site_root),
        file_path=str(app_host_path),
    )
    windir = tmp_path / "Windows"
    machine = windir / "Microsoft.NET" / "Framework" / "v4.0.30319" / "Config" / "machine.config"
    machine.parent.mkdir(parents=True)
    machine.write_text("<configuration />", encoding="utf-8")
    monkeypatch.setenv("WINDIR", str(windir))

    result = discover_iis_sites(doc)

    assert result.machine_config_path == str(machine)


def test_merge_effective_configs_applies_override_attrs_and_children() -> None:
    base_doc = parse_iis_config(
        """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.webServer>
        <directoryBrowse enabled="false" />
        <handlers>
            <add name="BaseHandler" path="*.php" verb="*" modules="CgiModule" />
        </handlers>
    </system.webServer>
</configuration>
""",
        file_path="applicationHost.config",
    )
    override_doc = parse_iis_config(
        """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.webServer>
        <directoryBrowse enabled="true" />
        <handlers>
            <clear />
            <add name="OverrideHandler" path="*.aspx" verb="*" modules="IsapiModule" />
        </handlers>
    </system.webServer>
</configuration>
""",
        file_path="web.config",
    )

    merged = merge_effective_configs(
        build_effective_config(base_doc),
        build_effective_config(override_doc),
    )

    directory_browse = merged.get_effective_section("/directoryBrowse")
    handlers = merged.get_effective_section("/handlers")

    assert directory_browse is not None
    assert directory_browse.attributes["enabled"] == "true"
    assert len(directory_browse.origin_chain) == 2
    assert handlers is not None
    assert [child.attributes.get("name") for child in handlers.children] == ["OverrideHandler"]


def test_merge_effective_configs_three_levels_preserve_origin_chain() -> None:
    machine_doc = parse_iis_config(
        """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <configSections />
    <system.web>
        <customErrors mode="On" />
    </system.web>
</configuration>
""",
        file_path="machine.config",
    )
    app_host_doc = parse_iis_config(
        """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.web>
        <customErrors mode="RemoteOnly" />
    </system.web>
</configuration>
""",
        file_path="applicationHost.config",
    )
    web_doc = parse_iis_config(
        """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.web>
        <customErrors mode="Off" />
    </system.web>
</configuration>
""",
        file_path="web.config",
    )

    merged = merge_effective_configs(
        merge_effective_configs(
            build_effective_config(machine_doc),
            build_effective_config(app_host_doc),
        ),
        build_effective_config(web_doc),
    )

    custom_errors = merged.get_effective_section("/customErrors")
    assert custom_errors is not None
    assert custom_errors.attributes["mode"] == "Off"
    assert [origin.file_path for origin in custom_errors.origin_chain] == [
        "machine.config",
        "applicationHost.config",
        "web.config",
    ]


def test_merge_effective_configs_three_levels_clear_resets_collection() -> None:
    machine_doc = parse_iis_config(
        """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <configSections />
    <system.webServer>
        <handlers>
            <add name="MachineHandler" path="*.axd" verb="*" modules="ManagedPipelineHandler" />
        </handlers>
    </system.webServer>
</configuration>
""",
        file_path="machine.config",
    )
    app_host_doc = parse_iis_config(
        """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.webServer>
        <handlers>
            <add name="AppHostHandler" path="*.php" verb="*" modules="CgiModule" />
        </handlers>
    </system.webServer>
</configuration>
""",
        file_path="applicationHost.config",
    )
    web_doc = parse_iis_config(
        """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.webServer>
        <handlers>
            <clear />
        </handlers>
    </system.webServer>
</configuration>
""",
        file_path="web.config",
    )

    merged = merge_effective_configs(
        merge_effective_configs(
            build_effective_config(machine_doc),
            build_effective_config(app_host_doc),
        ),
        build_effective_config(web_doc),
    )

    handlers = merged.get_effective_section("/handlers")
    assert handlers is not None
    assert handlers.children == []


def test_build_effective_config_location_remove_matches_all_attributes() -> None:
    doc = parse_iis_config(
        """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.webServer>
        <handlers>
            <add name="SharedHandler" path="*.php" verb="GET" modules="CgiModule" />
            <add name="SharedHandler" path="*.php" verb="POST" modules="CgiModule" />
        </handlers>
    </system.webServer>
    <location path="api">
        <system.webServer>
            <handlers>
                <remove name="SharedHandler" path="*.php" verb="GET" />
            </handlers>
        </system.webServer>
    </location>
</configuration>
""",
        file_path="applicationHost.config",
    )

    effective = build_effective_config(doc)
    handlers = effective.get_effective_section("/handlers", location_path="api")

    assert handlers is not None
    assert [child.attributes.get("verb") for child in handlers.children] == ["POST"]


def test_build_effective_config_location_remove_matches_ip_security_key_groups() -> None:
    doc = parse_iis_config(
        """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.webServer>
        <security>
            <ipSecurity>
                <add ipAddress="10.0.0.1" subnetMask="255.255.255.0" allowed="false" />
                <add ipAddress="10.0.0.2" allowed="false" />
            </ipSecurity>
        </security>
    </system.webServer>
    <location path="api">
        <system.webServer>
            <security>
                <ipSecurity>
                    <remove ipAddress="10.0.0.1" subnetMask="255.255.255.0" />
                    <remove ipAddress="10.0.0.2" />
                </ipSecurity>
            </security>
        </system.webServer>
    </location>
</configuration>
""",
        file_path="applicationHost.config",
    )

    effective = build_effective_config(doc)
    ip_security = effective.get_effective_section("/ipSecurity", location_path="api")

    assert ip_security is not None
    assert ip_security.children == []


def test_analyze_iis_config_application_host_discovers_and_merges_site_web_config(
    tmp_path: Path,
) -> None:
    site_root = tmp_path / "site"
    site_root.mkdir()
    _write(
        site_root / "web.config",
        """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.webServer>
        <directoryBrowse enabled="true" />
    </system.webServer>
    <system.web>
        <customErrors mode="Off" />
    </system.web>
</configuration>
""",
    )
    app_host_path = _write(
        tmp_path / "applicationHost.config",
        _application_host_config(site_root),
    )

    result = analyze_iis_config(str(app_host_path))

    assert result.metadata["config_kind"] == "applicationHost"
    assert result.metadata["sites_discovered"] == 1
    assert result.metadata["web_configs_found"] == 1
    rule_ids = {finding.rule_id for finding in result.findings}
    assert "iis.directory_browse_enabled" in rule_ids
    assert "iis.custom_errors_off" in rule_ids
    web_config_findings = [
        finding for finding in result.findings
        if finding.location is not None and finding.location.file_path == str(site_root / "web.config")
    ]
    assert web_config_findings, "expected findings sourced from discovered web.config"


def test_analyze_iis_config_application_host_with_machine_config_chain(
    tmp_path: Path,
) -> None:
    site_root = tmp_path / "site"
    site_root.mkdir()
    web_config_path = _write(
        site_root / "web.config",
        """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.web>
        <customErrors mode="Off" />
    </system.web>
</configuration>
""",
    )
    app_host_path = _write(
        tmp_path / "applicationHost.config",
        _application_host_config(site_root),
    )
    machine_config_path = _write(
        tmp_path / "machine.config",
        """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <configSections />
    <system.web>
        <customErrors mode="On" />
    </system.web>
</configuration>
""",
    )

    result = analyze_iis_config(
        str(app_host_path),
        machine_config_path=str(machine_config_path),
    )

    assert result.issues == []
    assert result.metadata["machine_config_path"] == str(machine_config_path)
    assert result.metadata["inheritance_chain"] == [
        str(machine_config_path),
        str(app_host_path),
        str(web_config_path),
    ]
    findings = [
        finding for finding in result.findings if finding.rule_id == "iis.custom_errors_off"
    ]
    assert findings
    assert findings[0].location is not None
    assert findings[0].location.file_path == str(web_config_path)


def test_discover_iis_sites_multiple_sites_multiple_apps(tmp_path: Path) -> None:
    site1_root = tmp_path / "site1"
    site1_api_root = tmp_path / "site1-api"
    site2_root = tmp_path / "site2"
    for root in (site1_root, site1_api_root, site2_root):
        root.mkdir()
        _write(root / "web.config", "<?xml version='1.0'?><configuration />")

    app_host_path = tmp_path / "applicationHost.config"
    doc = parse_iis_config(
        f"""\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.applicationHost>
        <sites>
            <site name="Site 1" id="1">
                <application path="/" applicationPool="Pool1">
                    <virtualDirectory path="/" physicalPath="{site1_root.as_posix()}" />
                </application>
                <application path="/api" applicationPool="ApiPool">
                    <virtualDirectory path="/" physicalPath="{site1_api_root.as_posix()}" />
                </application>
            </site>
            <site name="Site 2" id="2">
                <application path="/" applicationPool="Pool2">
                    <virtualDirectory path="/" physicalPath="{site2_root.as_posix()}" />
                </application>
            </site>
        </sites>
    </system.applicationHost>
</configuration>
""",
        file_path=str(app_host_path),
    )

    result = discover_iis_sites(doc)

    assert result.issues == []
    assert len(result.sites) == 2
    assert [site.name for site in result.sites] == ["Site 1", "Site 2"]
    assert [app.app_path for app in result.sites[0].applications] == ["/", "/api"]
    assert [app.app_path for app in result.sites[1].applications] == ["/"]
    assert set(result.all_web_configs) == {
        str(site1_root / "web.config"),
        str(site1_api_root / "web.config"),
        str(site2_root / "web.config"),
    }


def test_discover_iis_sites_no_web_config_no_error(tmp_path: Path) -> None:
    site_root = tmp_path / "site"
    site_root.mkdir()
    app_host_path = tmp_path / "applicationHost.config"
    doc = parse_iis_config(
        _application_host_config(site_root),
        file_path=str(app_host_path),
    )

    result = discover_iis_sites(doc)

    assert result.issues == []
    assert len(result.sites) == 1
    app = result.sites[0].applications[0]
    assert len(app.virtual_directories) == 1
    assert app.virtual_directories[0].web_config_path is None
    assert result.all_web_configs == []


def test_discover_iis_sites_nonexistent_physical_path(tmp_path: Path) -> None:
    missing_root = tmp_path / "missing-site"
    app_host_path = tmp_path / "applicationHost.config"
    doc = parse_iis_config(
        _application_host_config(missing_root),
        file_path=str(app_host_path),
    )

    result = discover_iis_sites(doc)

    assert len(result.sites) == 1
    assert len(result.issues) == 1
    issue = result.issues[0]
    assert issue.code == "iis_physical_path_not_found"
    assert issue.location is not None
    assert issue.location.kind == "xml"
    assert result.sites[0].applications[0].virtual_directories[0].web_config_path is None


def test_discover_iis_sites_ignores_non_application_host(tmp_path: Path) -> None:
    web_config_path = tmp_path / "web.config"
    doc = parse_iis_config(
        "<?xml version='1.0'?><configuration><system.webServer /></configuration>",
        file_path=str(web_config_path),
    )

    result = discover_iis_sites(doc)

    assert result.sites == []
    assert result.issues == []
    assert result.all_web_configs == []


def test_discover_iis_sites_site_without_applications(tmp_path: Path) -> None:
    app_host_path = tmp_path / "applicationHost.config"
    doc = parse_iis_config(
        """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.applicationHost>
        <sites>
            <site name="No Apps" id="7">
                <bindings>
                    <binding protocol="http" bindingInformation="*:80:noapps.test" />
                </bindings>
            </site>
        </sites>
    </system.applicationHost>
</configuration>
""",
        file_path=str(app_host_path),
    )

    result = discover_iis_sites(doc)

    assert result.issues == []
    assert len(result.sites) == 1
    assert result.sites[0].name == "No Apps"
    assert result.sites[0].applications == []
    assert result.sites[0].bindings == [
        {"protocol": "http", "bindingInformation": "*:80:noapps.test"}
    ]


def test_merge_effective_configs_base_only_section_preserved() -> None:
    base_doc = parse_iis_config(
        """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.webServer>
        <directoryBrowse enabled="false" />
    </system.webServer>
</configuration>
""",
        file_path="applicationHost.config",
    )
    override_doc = parse_iis_config(
        """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.web>
        <customErrors mode="RemoteOnly" />
    </system.web>
</configuration>
""",
        file_path="web.config",
    )

    merged = merge_effective_configs(
        build_effective_config(base_doc),
        build_effective_config(override_doc),
    )

    directory_browse = merged.get_effective_section("/directoryBrowse")
    assert directory_browse is not None
    assert directory_browse.attributes["enabled"] == "false"


def test_merge_effective_configs_override_only_section_preserved() -> None:
    base_doc = parse_iis_config(
        """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.webServer>
        <directoryBrowse enabled="false" />
    </system.webServer>
</configuration>
""",
        file_path="applicationHost.config",
    )
    override_doc = parse_iis_config(
        """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.webServer>
        <httpErrors errorMode="Detailed" />
    </system.webServer>
</configuration>
""",
        file_path="web.config",
    )

    merged = merge_effective_configs(
        build_effective_config(base_doc),
        build_effective_config(override_doc),
    )

    http_errors = merged.get_effective_section("/httpErrors")
    assert http_errors is not None
    assert http_errors.attributes["errorMode"] == "Detailed"


def test_merge_effective_configs_location_sections_merged() -> None:
    base_doc = parse_iis_config(
        """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <location path="api">
        <system.webServer>
            <directoryBrowse enabled="false" />
        </system.webServer>
    </location>
</configuration>
""",
        file_path="applicationHost.config",
    )
    override_doc = parse_iis_config(
        """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <location path="api">
        <system.webServer>
            <directoryBrowse enabled="true" />
        </system.webServer>
    </location>
</configuration>
""",
        file_path="web.config",
    )

    merged = merge_effective_configs(
        build_effective_config(base_doc),
        build_effective_config(override_doc),
    )

    directory_browse = merged.get_effective_section("/directoryBrowse", location_path="api")
    assert directory_browse is not None
    assert directory_browse.location_path == "api"
    assert directory_browse.attributes["enabled"] == "true"


def test_merge_effective_configs_origin_chain_concatenated() -> None:
    base_doc = parse_iis_config(
        """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.webServer>
        <directoryBrowse enabled="false" />
    </system.webServer>
</configuration>
""",
        file_path="applicationHost.config",
    )
    override_doc = parse_iis_config(
        """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.webServer>
        <directoryBrowse enabled="true" />
    </system.webServer>
</configuration>
""",
        file_path="web.config",
    )

    merged = merge_effective_configs(
        build_effective_config(base_doc),
        build_effective_config(override_doc),
    )

    directory_browse = merged.get_effective_section("/directoryBrowse")
    assert directory_browse is not None
    assert [origin.file_path for origin in directory_browse.origin_chain] == [
        "applicationHost.config",
        "web.config",
    ]


def test_merge_effective_configs_clear_only_override_empties_children() -> None:
    """<clear/> with no subsequent <add> must produce empty children, not inherit base."""
    base_doc = parse_iis_config(
        """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.webServer>
        <handlers>
            <add name="BaseHandler" path="*.php" verb="*" modules="CgiModule" />
        </handlers>
    </system.webServer>
</configuration>
""",
        file_path="applicationHost.config",
    )
    override_doc = parse_iis_config(
        """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.webServer>
        <handlers>
            <clear />
        </handlers>
    </system.webServer>
</configuration>
""",
        file_path="web.config",
    )

    merged = merge_effective_configs(
        build_effective_config(base_doc),
        build_effective_config(override_doc),
    )

    handlers = merged.get_effective_section("/handlers")
    assert handlers is not None
    assert handlers.children == []


def test_analyze_web_config_with_base_warns_on_unreadable_file(tmp_path: Path) -> None:
    """Warning branch when web.config cannot be read."""
    from webconf_audit.local.iis import _analyze_web_config_with_base

    missing_path = str(tmp_path / "nonexistent" / "web.config")
    findings, issues = _analyze_web_config_with_base(missing_path, IISEffectiveConfig())

    assert findings == []
    assert len(issues) == 1
    assert issues[0].code == "iis_config_read_error"
    assert issues[0].level == "warning"
    assert issues[0].location is not None
    assert issues[0].location.file_path == missing_path


def test_analyze_web_config_with_base_warns_on_malformed_xml(tmp_path: Path) -> None:
    """Warning branch when web.config has invalid XML."""
    from webconf_audit.local.iis import _analyze_web_config_with_base

    bad_config = _write(tmp_path / "web.config", "<<<not xml at all>>>")
    findings, issues = _analyze_web_config_with_base(str(bad_config), IISEffectiveConfig())

    assert findings == []
    assert len(issues) == 1
    assert issues[0].code == "iis_parse_error"
    assert issues[0].level == "warning"


def test_analyze_iis_config_web_config_uses_single_file_path(tmp_path: Path) -> None:
    web_config_path = _write(
        tmp_path / "web.config",
        """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.webServer>
        <directoryBrowse enabled="true" />
    </system.webServer>
</configuration>
""",
    )

    result = analyze_iis_config(str(web_config_path))

    assert result.metadata["config_kind"] == "web"
    assert "sites_discovered" not in result.metadata
    assert "iis.directory_browse_enabled" in {finding.rule_id for finding in result.findings}


def test_analyze_iis_config_application_host_no_sites_still_analyzes_base(tmp_path: Path) -> None:
    app_host_path = _write(
        tmp_path / "applicationHost.config",
        """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.applicationHost />
    <system.webServer>
        <directoryBrowse enabled="true" />
    </system.webServer>
</configuration>
""",
    )

    result = analyze_iis_config(str(app_host_path))

    assert result.metadata["config_kind"] == "applicationHost"
    assert result.metadata["sites_discovered"] == 0
    assert result.metadata["web_configs_found"] == 0
    assert "iis.directory_browse_enabled" in {finding.rule_id for finding in result.findings}


def test_analyze_iis_config_dir_with_application_host(tmp_path: Path) -> None:
    site_root = tmp_path / "site"
    site_root.mkdir()
    _write(
        site_root / "web.config",
        """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.webServer>
        <directoryBrowse enabled="true" />
    </system.webServer>
</configuration>
""",
    )
    _write(
        tmp_path / "applicationHost.config",
        _application_host_config(site_root),
    )

    result = analyze_iis_config(str(tmp_path))

    assert result.metadata["config_kind"] == "applicationHost"
    assert result.metadata["sites_discovered"] == 1
    assert result.metadata["web_configs_found"] == 1
    assert "iis.directory_browse_enabled" in {finding.rule_id for finding in result.findings}

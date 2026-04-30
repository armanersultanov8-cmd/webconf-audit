from pathlib import Path

import pytest

from webconf_audit.local.iis import analyze_iis_config
from webconf_audit.local.iis.effective import build_effective_config
from webconf_audit.local.iis.parser import (
    IISParseError,
    parse_iis_config,
)
from webconf_audit.models import AnalysisResult

_ABSENCE_RULE_IDS = {
    "iis.missing_hsts_header",
    "iis.logging_not_configured",
    "iis.max_allowed_content_length_missing",
}

MINIMAL_APPLICATION_HOST_CONFIG = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.applicationHost>
        <sites>
            <site name="Default Web Site" id="1">
                <bindings>
                    <binding protocol="http" bindingInformation="*:80:" />
                </bindings>
            </site>
        </sites>
    </system.applicationHost>
    <system.webServer>
        <security>
            <requestFiltering>
                <requestLimits maxAllowedContentLength="30000000" />
            </requestFiltering>
        </security>
    </system.webServer>
</configuration>
"""

MINIMAL_WEB_CONFIG = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.webServer>
        <httpErrors errorMode="Custom" />
        <security>
            <requestFiltering>
                <requestLimits maxAllowedContentLength="4194304" />
            </requestFiltering>
        </security>
    </system.webServer>
    <system.web>
        <compilation debug="false" />
        <customErrors mode="RemoteOnly" />
    </system.web>
</configuration>
"""


# --- Parser happy path ---


def test_parse_application_host_config() -> None:
    doc = parse_iis_config(
        MINIMAL_APPLICATION_HOST_CONFIG,
        file_path="C:/Windows/System32/inetsrv/config/applicationHost.config",
    )

    assert doc.root_tag == "configuration"
    assert doc.config_kind == "applicationHost"
    assert doc.file_path is not None
    assert len(doc.sections) > 0

    top_level_tags = [s.tag for s in doc.sections if s.xml_path.count("/") == 1]
    assert "system.applicationHost" in top_level_tags
    assert "system.webServer" in top_level_tags


def test_parse_web_config() -> None:
    doc = parse_iis_config(MINIMAL_WEB_CONFIG, file_path="C:/inetpub/wwwroot/web.config")

    assert doc.root_tag == "configuration"
    assert doc.config_kind == "web"
    assert len(doc.sections) > 0

    top_level_tags = [s.tag for s in doc.sections if s.xml_path.count("/") == 1]
    assert "system.webServer" in top_level_tags
    assert "system.web" in top_level_tags


def test_parse_machine_config() -> None:
    doc = parse_iis_config(
        """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <configSections />
    <system.web>
        <customErrors mode="RemoteOnly" />
    </system.web>
</configuration>
""",
        file_path="C:/Windows/Microsoft.NET/Framework64/v4.0.30319/Config/machine.config",
    )

    assert doc.root_tag == "configuration"
    assert doc.config_kind == "machine"
    assert len(doc.sections) > 0


def test_parse_preserves_xml_paths() -> None:
    doc = parse_iis_config(MINIMAL_WEB_CONFIG, file_path="web.config")

    xml_paths = [s.xml_path for s in doc.sections]
    assert "configuration/system.webServer" in xml_paths
    assert "configuration/system.webServer/httpErrors" in xml_paths
    assert "configuration/system.webServer/security" in xml_paths
    assert "configuration/system.webServer/security/requestFiltering" in xml_paths
    assert "configuration/system.webServer/security/requestFiltering/requestLimits" in xml_paths


def test_parse_preserves_attributes() -> None:
    doc = parse_iis_config(MINIMAL_WEB_CONFIG, file_path="web.config")

    http_errors = [s for s in doc.sections if s.tag == "httpErrors"]
    assert len(http_errors) == 1
    assert http_errors[0].attributes.get("errorMode") == "Custom"


def test_parse_preserves_source_ref() -> None:
    doc = parse_iis_config(MINIMAL_WEB_CONFIG, file_path="web.config")

    for section in doc.sections:
        assert section.source.file_path == "web.config"
        assert section.source.xml_path == section.xml_path


def test_parse_unknown_config_kind_for_generic_path() -> None:
    doc = parse_iis_config(
        '<?xml version="1.0"?>\n<configuration></configuration>',
        file_path="custom.config",
    )

    assert doc.config_kind == "unknown"
    assert doc.root_tag == "configuration"


def test_parse_generic_machine_like_config_detected_by_structure() -> None:
    doc = parse_iis_config(
        """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <configSections />
    <system.web>
        <trace enabled="false" />
    </system.web>
</configuration>
""",
        file_path="custom.config",
    )

    assert doc.config_kind == "machine"


# --- Parser error handling ---


def test_parse_malformed_xml_raises_parse_error() -> None:
    with pytest.raises(IISParseError) as exc_info:
        parse_iis_config("<configuration><broken>", file_path="web.config")
    assert exc_info.value.file_path == "web.config"
    assert "XML parse error" in str(exc_info.value)


def test_parse_empty_input_raises_parse_error() -> None:
    with pytest.raises(IISParseError):
        parse_iis_config("", file_path="web.config")


# --- Analyzer happy path ---


def test_analyze_valid_application_host_config(tmp_path: Path) -> None:
    config_path = tmp_path / "applicationHost.config"
    config_path.write_text(MINIMAL_APPLICATION_HOST_CONFIG, encoding="utf-8")

    result = analyze_iis_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.mode == "local"
    assert result.server_type == "iis"
    assert result.target == str(config_path)
    # Absence rules (HSTS, logging) may fire on minimal configs; no *insecure* findings.
    insecure = [f for f in result.findings if f.rule_id not in _ABSENCE_RULE_IDS]
    assert insecure == []
    assert result.issues == []
    assert result.metadata["config_kind"] == "applicationHost"
    assert result.metadata["root_tag"] == "configuration"
    assert isinstance(result.metadata["section_count"], int)
    assert result.metadata["section_count"] > 0


def test_analyze_valid_web_config(tmp_path: Path) -> None:
    config_path = tmp_path / "web.config"
    config_path.write_text(MINIMAL_WEB_CONFIG, encoding="utf-8")

    result = analyze_iis_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.mode == "local"
    assert result.server_type == "iis"
    insecure = [f for f in result.findings if f.rule_id not in _ABSENCE_RULE_IDS]
    assert insecure == []
    assert result.issues == []
    assert result.metadata["config_kind"] == "web"
    assert result.metadata["machine_config_path"] is None
    assert result.metadata["inheritance_chain"] == [str(config_path)]


def test_analyze_iis_config_accepts_utf8_bom(tmp_path: Path) -> None:
    config_path = tmp_path / "web.config"
    config_path.write_text(MINIMAL_WEB_CONFIG, encoding="utf-8-sig")

    result = analyze_iis_config(str(config_path))

    assert result.issues == []
    assert result.metadata["config_kind"] == "web"


def test_analyze_machine_config_as_single_file(tmp_path: Path) -> None:
    config_path = tmp_path / "machine.config"
    config_path.write_text(
        """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <configSections />
    <system.web>
        <customErrors mode="RemoteOnly" />
    </system.web>
</configuration>
""",
        encoding="utf-8",
    )

    result = analyze_iis_config(str(config_path))

    assert result.issues == []
    assert result.metadata["config_kind"] == "machine"
    assert result.metadata["machine_config_path"] == str(config_path)
    assert result.metadata["inheritance_chain"] == [str(config_path)]


def test_analyze_reports_top_level_sections_in_metadata(tmp_path: Path) -> None:
    config_path = tmp_path / "web.config"
    config_path.write_text(MINIMAL_WEB_CONFIG, encoding="utf-8")

    result = analyze_iis_config(str(config_path))

    top_sections = result.metadata["top_level_sections"]
    assert "system.webServer" in top_sections
    assert "system.web" in top_sections


# --- Analyzer failure handling ---


def test_analyze_missing_file_returns_issue() -> None:
    result = analyze_iis_config("/nonexistent/web.config")

    assert isinstance(result, AnalysisResult)
    assert result.mode == "local"
    assert result.server_type == "iis"
    assert result.findings == []
    assert len(result.issues) == 1
    assert result.issues[0].code == "config_not_found"
    assert result.issues[0].level == "error"
    assert result.issues[0].location is not None
    assert result.issues[0].location.kind == "file"


def test_analyze_malformed_xml_returns_issue(tmp_path: Path) -> None:
    config_path = tmp_path / "web.config"
    config_path.write_text("<configuration><broken>", encoding="utf-8")

    result = analyze_iis_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.mode == "local"
    assert result.server_type == "iis"
    assert result.findings == []
    assert len(result.issues) == 1
    assert result.issues[0].code == "iis_parse_error"
    assert result.issues[0].level == "error"
    assert result.issues[0].location is not None
    assert result.issues[0].location.kind == "xml"
    assert result.issues[0].location.file_path == str(config_path)


# --- Directory discovery ---


def test_analyze_directory_with_web_config(tmp_path: Path) -> None:
    web_config = tmp_path / "web.config"
    web_config.write_text(MINIMAL_WEB_CONFIG, encoding="utf-8")

    result = analyze_iis_config(str(tmp_path))

    assert isinstance(result, AnalysisResult)
    assert result.mode == "local"
    assert result.server_type == "iis"
    assert result.issues == []
    assert result.metadata["config_kind"] == "web"


def test_analyze_directory_without_web_config_returns_issue(tmp_path: Path) -> None:
    result = analyze_iis_config(str(tmp_path))

    assert isinstance(result, AnalysisResult)
    assert result.mode == "local"
    assert result.server_type == "iis"
    assert len(result.issues) == 1
    assert result.issues[0].code == "config_not_found"


# --- IIS rules: iis.directory_browse_enabled ---


def test_directory_browse_enabled_fires(tmp_path: Path) -> None:
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.webServer>
        <directoryBrowse enabled="true" />
    </system.webServer>
</configuration>
"""
    (tmp_path / "web.config").write_text(config, encoding="utf-8")
    result = analyze_iis_config(str(tmp_path / "web.config"))
    rule_ids = {f.rule_id for f in result.findings}
    assert "iis.directory_browse_enabled" in rule_ids
    finding = [f for f in result.findings if f.rule_id == "iis.directory_browse_enabled"][0]
    assert finding.location is not None
    assert finding.location.kind == "xml"
    assert finding.location.xml_path is not None
    assert "directoryBrowse" in finding.location.xml_path


def test_directory_browse_enabled_does_not_fire_when_false(tmp_path: Path) -> None:
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.webServer>
        <directoryBrowse enabled="false" />
    </system.webServer>
</configuration>
"""
    (tmp_path / "web.config").write_text(config, encoding="utf-8")
    result = analyze_iis_config(str(tmp_path / "web.config"))
    assert "iis.directory_browse_enabled" not in {f.rule_id for f in result.findings}


def test_directory_browse_enabled_does_not_fire_when_section_missing(tmp_path: Path) -> None:
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.webServer>
        <security />
    </system.webServer>
</configuration>
"""
    (tmp_path / "web.config").write_text(config, encoding="utf-8")
    result = analyze_iis_config(str(tmp_path / "web.config"))
    assert "iis.directory_browse_enabled" not in {f.rule_id for f in result.findings}


def test_directory_browse_enabled_case_insensitive(tmp_path: Path) -> None:
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.webServer>
        <directoryBrowse enabled="True" />
    </system.webServer>
</configuration>
"""
    (tmp_path / "web.config").write_text(config, encoding="utf-8")
    result = analyze_iis_config(str(tmp_path / "web.config"))
    assert "iis.directory_browse_enabled" in {f.rule_id for f in result.findings}


# --- IIS rules: iis.http_errors_detailed ---


def test_http_errors_detailed_fires(tmp_path: Path) -> None:
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.webServer>
        <httpErrors errorMode="Detailed" />
    </system.webServer>
</configuration>
"""
    (tmp_path / "web.config").write_text(config, encoding="utf-8")
    result = analyze_iis_config(str(tmp_path / "web.config"))
    rule_ids = {f.rule_id for f in result.findings}
    assert "iis.http_errors_detailed" in rule_ids
    finding = [f for f in result.findings if f.rule_id == "iis.http_errors_detailed"][0]
    assert finding.location is not None
    assert finding.location.kind == "xml"
    assert "httpErrors" in (finding.location.xml_path or "")


def test_http_errors_detailed_does_not_fire_when_custom(tmp_path: Path) -> None:
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.webServer>
        <httpErrors errorMode="Custom" />
    </system.webServer>
</configuration>
"""
    (tmp_path / "web.config").write_text(config, encoding="utf-8")
    result = analyze_iis_config(str(tmp_path / "web.config"))
    assert "iis.http_errors_detailed" not in {f.rule_id for f in result.findings}


def test_http_errors_detailed_does_not_fire_when_detailed_local_only(tmp_path: Path) -> None:
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.webServer>
        <httpErrors errorMode="DetailedLocalOnly" />
    </system.webServer>
</configuration>
"""
    (tmp_path / "web.config").write_text(config, encoding="utf-8")
    result = analyze_iis_config(str(tmp_path / "web.config"))
    assert "iis.http_errors_detailed" not in {f.rule_id for f in result.findings}


def test_http_errors_detailed_does_not_fire_when_section_missing(tmp_path: Path) -> None:
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.webServer>
        <security />
    </system.webServer>
</configuration>
"""
    (tmp_path / "web.config").write_text(config, encoding="utf-8")
    result = analyze_iis_config(str(tmp_path / "web.config"))
    assert "iis.http_errors_detailed" not in {f.rule_id for f in result.findings}


# --- IIS rules: iis.custom_errors_off ---


def test_custom_errors_off_fires(tmp_path: Path) -> None:
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.web>
        <customErrors mode="Off" />
    </system.web>
</configuration>
"""
    (tmp_path / "web.config").write_text(config, encoding="utf-8")
    result = analyze_iis_config(str(tmp_path / "web.config"))
    rule_ids = {f.rule_id for f in result.findings}
    assert "iis.custom_errors_off" in rule_ids
    finding = [f for f in result.findings if f.rule_id == "iis.custom_errors_off"][0]
    assert finding.location is not None
    assert finding.location.kind == "xml"
    assert "customErrors" in (finding.location.xml_path or "")


def test_custom_errors_off_does_not_fire_when_remote_only(tmp_path: Path) -> None:
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.web>
        <customErrors mode="RemoteOnly" />
    </system.web>
</configuration>
"""
    (tmp_path / "web.config").write_text(config, encoding="utf-8")
    result = analyze_iis_config(str(tmp_path / "web.config"))
    assert "iis.custom_errors_off" not in {f.rule_id for f in result.findings}


def test_custom_errors_off_does_not_fire_when_on(tmp_path: Path) -> None:
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.web>
        <customErrors mode="On" />
    </system.web>
</configuration>
"""
    (tmp_path / "web.config").write_text(config, encoding="utf-8")
    result = analyze_iis_config(str(tmp_path / "web.config"))
    assert "iis.custom_errors_off" not in {f.rule_id for f in result.findings}


def test_custom_errors_off_case_insensitive(tmp_path: Path) -> None:
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.web>
        <customErrors mode="off" />
    </system.web>
</configuration>
"""
    (tmp_path / "web.config").write_text(config, encoding="utf-8")
    result = analyze_iis_config(str(tmp_path / "web.config"))
    assert "iis.custom_errors_off" in {f.rule_id for f in result.findings}


# --- IIS rules: iis.asp_script_error_sent_to_browser ---


def test_asp_script_error_sent_to_browser_fires(tmp_path: Path) -> None:
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.webServer>
        <asp scriptErrorSentToBrowser="true" />
    </system.webServer>
</configuration>
"""
    (tmp_path / "web.config").write_text(config, encoding="utf-8")
    result = analyze_iis_config(str(tmp_path / "web.config"))
    rule_ids = {f.rule_id for f in result.findings}
    assert "iis.asp_script_error_sent_to_browser" in rule_ids
    finding = [f for f in result.findings if f.rule_id == "iis.asp_script_error_sent_to_browser"][0]
    assert finding.location is not None
    assert finding.location.kind == "xml"
    assert "asp" in (finding.location.xml_path or "")


def test_asp_script_error_sent_to_browser_does_not_fire_when_false(tmp_path: Path) -> None:
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.webServer>
        <asp scriptErrorSentToBrowser="false" />
    </system.webServer>
</configuration>
"""
    (tmp_path / "web.config").write_text(config, encoding="utf-8")
    result = analyze_iis_config(str(tmp_path / "web.config"))
    assert "iis.asp_script_error_sent_to_browser" not in {f.rule_id for f in result.findings}


def test_asp_script_error_sent_to_browser_does_not_fire_when_section_missing(tmp_path: Path) -> None:
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.webServer>
        <security />
    </system.webServer>
</configuration>
"""
    (tmp_path / "web.config").write_text(config, encoding="utf-8")
    result = analyze_iis_config(str(tmp_path / "web.config"))
    assert "iis.asp_script_error_sent_to_browser" not in {f.rule_id for f in result.findings}


# --- IIS rules: no false positives on safe baseline ---


# --- IIS rules: iis.compilation_debug_enabled ---


def test_compilation_debug_enabled_fires(tmp_path: Path) -> None:
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.web>
        <compilation debug="true" />
    </system.web>
</configuration>
"""
    (tmp_path / "web.config").write_text(config, encoding="utf-8")
    result = analyze_iis_config(str(tmp_path / "web.config"))
    rule_ids = {f.rule_id for f in result.findings}
    assert "iis.compilation_debug_enabled" in rule_ids
    finding = [f for f in result.findings if f.rule_id == "iis.compilation_debug_enabled"][0]
    assert finding.location is not None
    assert finding.location.kind == "xml"
    assert "compilation" in (finding.location.xml_path or "")


def test_compilation_debug_enabled_does_not_fire_when_false(tmp_path: Path) -> None:
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.web>
        <compilation debug="false" />
    </system.web>
</configuration>
"""
    (tmp_path / "web.config").write_text(config, encoding="utf-8")
    result = analyze_iis_config(str(tmp_path / "web.config"))
    assert "iis.compilation_debug_enabled" not in {f.rule_id for f in result.findings}


def test_compilation_debug_enabled_does_not_fire_when_missing(tmp_path: Path) -> None:
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.web>
        <compilation targetFramework="4.8" />
    </system.web>
</configuration>
"""
    (tmp_path / "web.config").write_text(config, encoding="utf-8")
    result = analyze_iis_config(str(tmp_path / "web.config"))
    assert "iis.compilation_debug_enabled" not in {f.rule_id for f in result.findings}


def test_compilation_debug_enabled_handles_empty_debug_value(tmp_path: Path) -> None:
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.web>
        <compilation debug="" />
    </system.web>
</configuration>
"""
    (tmp_path / "web.config").write_text(config, encoding="utf-8")
    result = analyze_iis_config(str(tmp_path / "web.config"))
    assert "iis.compilation_debug_enabled" not in {f.rule_id for f in result.findings}


# --- IIS rules: iis.trace_enabled ---


def test_trace_enabled_fires(tmp_path: Path) -> None:
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.web>
        <trace enabled="true" />
    </system.web>
</configuration>
"""
    (tmp_path / "web.config").write_text(config, encoding="utf-8")
    result = analyze_iis_config(str(tmp_path / "web.config"))
    rule_ids = {f.rule_id for f in result.findings}
    assert "iis.trace_enabled" in rule_ids
    finding = [f for f in result.findings if f.rule_id == "iis.trace_enabled"][0]
    assert finding.location is not None
    assert finding.location.kind == "xml"
    assert "trace" in (finding.location.xml_path or "")


def test_trace_enabled_does_not_fire_when_false(tmp_path: Path) -> None:
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.web>
        <trace enabled="false" />
    </system.web>
</configuration>
"""
    (tmp_path / "web.config").write_text(config, encoding="utf-8")
    result = analyze_iis_config(str(tmp_path / "web.config"))
    assert "iis.trace_enabled" not in {f.rule_id for f in result.findings}


def test_trace_enabled_does_not_fire_when_section_missing(tmp_path: Path) -> None:
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.web>
        <compilation debug="false" />
    </system.web>
</configuration>
"""
    (tmp_path / "web.config").write_text(config, encoding="utf-8")
    result = analyze_iis_config(str(tmp_path / "web.config"))
    assert "iis.trace_enabled" not in {f.rule_id for f in result.findings}


# --- IIS rules: iis.http_runtime_version_header_enabled ---


def test_http_runtime_version_header_enabled_fires(tmp_path: Path) -> None:
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.web>
        <httpRuntime enableVersionHeader="true" />
    </system.web>
</configuration>
"""
    (tmp_path / "web.config").write_text(config, encoding="utf-8")
    result = analyze_iis_config(str(tmp_path / "web.config"))
    rule_ids = {f.rule_id for f in result.findings}
    assert "iis.http_runtime_version_header_enabled" in rule_ids
    finding = [f for f in result.findings if f.rule_id == "iis.http_runtime_version_header_enabled"][0]
    assert finding.location is not None
    assert finding.location.kind == "xml"
    assert "httpRuntime" in (finding.location.xml_path or "")


def test_http_runtime_version_header_does_not_fire_when_false(tmp_path: Path) -> None:
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.web>
        <httpRuntime enableVersionHeader="false" />
    </system.web>
</configuration>
"""
    (tmp_path / "web.config").write_text(config, encoding="utf-8")
    result = analyze_iis_config(str(tmp_path / "web.config"))
    assert "iis.http_runtime_version_header_enabled" not in {f.rule_id for f in result.findings}


def test_http_runtime_version_header_does_not_fire_when_absent(tmp_path: Path) -> None:
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.web>
        <httpRuntime targetFramework="4.8" />
    </system.web>
</configuration>
"""
    (tmp_path / "web.config").write_text(config, encoding="utf-8")
    result = analyze_iis_config(str(tmp_path / "web.config"))
    assert "iis.http_runtime_version_header_enabled" not in {f.rule_id for f in result.findings}


# --- IIS rules: iis.request_filtering_allow_double_escaping ---


def test_request_filtering_allow_double_escaping_fires(tmp_path: Path) -> None:
    # requestFiltering at depth 2 (direct child of system.webServer)
    # so it is visible to the current 2-level parser.
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.webServer>
        <requestFiltering allowDoubleEscaping="true" />
    </system.webServer>
</configuration>
"""
    (tmp_path / "web.config").write_text(config, encoding="utf-8")
    result = analyze_iis_config(str(tmp_path / "web.config"))
    rule_ids = {f.rule_id for f in result.findings}
    assert "iis.request_filtering_allow_double_escaping" in rule_ids
    finding = [f for f in result.findings if f.rule_id == "iis.request_filtering_allow_double_escaping"][0]
    assert finding.location is not None
    assert finding.location.kind == "xml"
    assert "requestFiltering" in (finding.location.xml_path or "")


def test_request_filtering_allow_double_escaping_does_not_fire_when_false(tmp_path: Path) -> None:
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.webServer>
        <requestFiltering allowDoubleEscaping="false" />
    </system.webServer>
</configuration>
"""
    (tmp_path / "web.config").write_text(config, encoding="utf-8")
    result = analyze_iis_config(str(tmp_path / "web.config"))
    assert "iis.request_filtering_allow_double_escaping" not in {f.rule_id for f in result.findings}


def test_request_filtering_allow_double_escaping_does_not_fire_when_missing(tmp_path: Path) -> None:
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.webServer>
        <requestFiltering>
            <requestLimits maxAllowedContentLength="4194304" />
        </requestFiltering>
    </system.webServer>
</configuration>
"""
    (tmp_path / "web.config").write_text(config, encoding="utf-8")
    result = analyze_iis_config(str(tmp_path / "web.config"))
    assert "iis.request_filtering_allow_double_escaping" not in {f.rule_id for f in result.findings}


def test_request_filtering_under_security_fires_for_canonical_iis_path(tmp_path: Path) -> None:
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.webServer>
        <security>
            <requestFiltering allowDoubleEscaping="true" />
        </security>
    </system.webServer>
</configuration>
"""
    (tmp_path / "web.config").write_text(config, encoding="utf-8")
    result = analyze_iis_config(str(tmp_path / "web.config"))
    rule_ids = {f.rule_id for f in result.findings}
    assert "iis.request_filtering_allow_double_escaping" in rule_ids
    finding = [f for f in result.findings if f.rule_id == "iis.request_filtering_allow_double_escaping"][0]
    assert finding.location is not None
    assert finding.location.xml_path == "configuration/system.webServer/security/requestFiltering"


# --- IIS rules: no false positives on safe baseline (all rules) ---


def test_no_iis_rule_findings_on_safe_baseline(tmp_path: Path) -> None:
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.webServer>
        <directoryBrowse enabled="false" />
        <httpErrors errorMode="DetailedLocalOnly" />
        <httpLogging dontLog="false" />
        <asp scriptErrorSentToBrowser="false" />
        <requestFiltering allowDoubleEscaping="false">
            <requestLimits maxAllowedContentLength="4194304" />
        </requestFiltering>
        <httpProtocol>
            <customHeaders>
                <remove name="X-Powered-By" />
                <add name="Strict-Transport-Security"
                     value="max-age=31536000; includeSubDomains" />
            </customHeaders>
        </httpProtocol>
    </system.webServer>
    <system.web>
        <customErrors mode="RemoteOnly" />
        <compilation debug="false" />
        <trace enabled="false" />
        <httpRuntime enableVersionHeader="false" />
    </system.web>
</configuration>
"""
    (tmp_path / "web.config").write_text(config, encoding="utf-8")
    result = analyze_iis_config(str(tmp_path / "web.config"))
    server_findings = [f for f in result.findings if not f.rule_id.startswith("universal.")]
    assert server_findings == []


def test_malformed_xml_still_returns_parse_error_not_rule_findings(tmp_path: Path) -> None:
    (tmp_path / "web.config").write_text("<configuration><broken>", encoding="utf-8")
    result = analyze_iis_config(str(tmp_path / "web.config"))
    assert result.findings == []
    assert len(result.issues) == 1
    assert result.issues[0].code == "iis_parse_error"


# ---------------------------------------------------------------------------
# Child element extraction (4.1)
# ---------------------------------------------------------------------------


def test_child_add_elements_extracted_into_section_children() -> None:
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.webServer>
        <httpErrors errorMode="DetailedLocalOnly">
            <remove statusCode="404" />
            <error statusCode="404" path="/custom-404.htm" responseMode="File" />
        </httpErrors>
    </system.webServer>
</configuration>
"""
    doc = parse_iis_config(config, file_path="web.config")
    http_errors = [s for s in doc.sections if s.tag == "httpErrors"]
    assert len(http_errors) == 1
    section = http_errors[0]
    assert section.attributes.get("errorMode") == "DetailedLocalOnly"
    assert len(section.children) == 2
    assert section.children[0].tag == "remove"
    assert section.children[0].attributes.get("statusCode") == "404"
    assert section.children[1].tag == "error"
    assert section.children[1].attributes.get("path") == "/custom-404.htm"


def test_child_clear_element_extracted() -> None:
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.webServer>
        <modules>
            <clear />
            <add name="MyModule" type="MyHandler" />
        </modules>
    </system.webServer>
</configuration>
"""
    doc = parse_iis_config(config, file_path="web.config")
    modules = [s for s in doc.sections if s.tag == "modules"]
    assert len(modules) == 1
    assert len(modules[0].children) == 2
    assert modules[0].children[0].tag == "clear"
    assert modules[0].children[1].tag == "add"
    assert modules[0].children[1].attributes.get("name") == "MyModule"


def test_child_deny_allow_elements_extracted() -> None:
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.webServer>
        <security>
            <ipSecurity>
                <deny ipAddress="192.168.1.100" />
                <allow ipAddress="10.0.0.0" subnetMask="255.0.0.0" />
            </ipSecurity>
        </security>
    </system.webServer>
</configuration>
"""
    doc = parse_iis_config(config, file_path="web.config")
    ip_security = [s for s in doc.sections if s.tag == "ipSecurity"]
    assert len(ip_security) == 1
    assert len(ip_security[0].children) == 2
    assert ip_security[0].children[0].tag == "deny"
    assert ip_security[0].children[1].tag == "allow"


def test_child_elements_do_not_appear_as_separate_sections() -> None:
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.webServer>
        <httpErrors>
            <remove statusCode="500" />
            <error statusCode="500" path="/err.htm" responseMode="File" />
        </httpErrors>
    </system.webServer>
</configuration>
"""
    doc = parse_iis_config(config, file_path="web.config")
    tags = [s.tag for s in doc.sections]
    assert "remove" not in tags
    assert "error" not in tags


def test_child_elements_have_source_refs() -> None:
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.webServer>
        <modules>
            <add name="Mod1" />
        </modules>
    </system.webServer>
</configuration>
"""
    doc = parse_iis_config(config, file_path="web.config")
    modules = [s for s in doc.sections if s.tag == "modules"]
    assert len(modules) == 1
    child = modules[0].children[0]
    assert child.source.file_path == "web.config"
    assert child.source.xml_path == "configuration/system.webServer/modules/add"


def test_non_child_leaf_sections_remain_as_sections() -> None:
    """Leaf elements that are NOT in the child-directive tag set stay as IISSection."""
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.webServer>
        <directoryBrowse enabled="true" />
        <httpErrors errorMode="Detailed" />
    </system.webServer>
</configuration>
"""
    doc = parse_iis_config(config, file_path="web.config")
    tags = [s.tag for s in doc.sections]
    assert "directoryBrowse" in tags
    assert "httpErrors" in tags


def test_binding_elements_extracted_as_children() -> None:
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.applicationHost>
        <sites>
            <site name="Default" id="1">
                <bindings>
                    <binding protocol="http" bindingInformation="*:80:" />
                    <binding protocol="https" bindingInformation="*:443:" />
                </bindings>
            </site>
        </sites>
    </system.applicationHost>
</configuration>
"""
    doc = parse_iis_config(config, file_path="applicationHost.config")
    bindings = [s for s in doc.sections if s.tag == "bindings"]
    assert len(bindings) == 1
    assert len(bindings[0].children) == 2
    assert bindings[0].children[0].tag == "binding"
    assert bindings[0].children[0].attributes.get("protocol") == "http"
    assert bindings[0].children[1].attributes.get("protocol") == "https"


# ---------------------------------------------------------------------------
# Location path awareness (4.2)
# ---------------------------------------------------------------------------


def test_location_path_propagated_to_sections() -> None:
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.webServer>
        <directoryBrowse enabled="false" />
    </system.webServer>
    <location path="uploads">
        <system.webServer>
            <directoryBrowse enabled="true" />
        </system.webServer>
    </location>
</configuration>
"""
    doc = parse_iis_config(config, file_path="web.config")
    dir_browse = [s for s in doc.sections if s.tag == "directoryBrowse"]
    assert len(dir_browse) == 2

    global_section = [s for s in dir_browse if s.location_path is None]
    assert len(global_section) == 1
    assert global_section[0].attributes.get("enabled") == "false"

    scoped_section = [s for s in dir_browse if s.location_path == "uploads"]
    assert len(scoped_section) == 1
    assert scoped_section[0].attributes.get("enabled") == "true"


def test_location_path_xml_path_format() -> None:
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <location path="api">
        <system.webServer>
            <httpErrors errorMode="Detailed" />
        </system.webServer>
    </location>
</configuration>
"""
    doc = parse_iis_config(config, file_path="web.config")
    http_errors = [s for s in doc.sections if s.tag == "httpErrors"]
    assert len(http_errors) == 1
    assert http_errors[0].location_path == "api"
    assert http_errors[0].xml_path == "configuration/location[@path='api']/system.webServer/httpErrors"


def test_location_path_none_for_global_sections() -> None:
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.webServer>
        <directoryBrowse enabled="false" />
    </system.webServer>
</configuration>
"""
    doc = parse_iis_config(config, file_path="web.config")
    for section in doc.sections:
        assert section.location_path is None


def test_multiple_location_blocks() -> None:
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <location path="uploads">
        <system.webServer>
            <directoryBrowse enabled="true" />
        </system.webServer>
    </location>
    <location path="admin">
        <system.webServer>
            <directoryBrowse enabled="false" />
        </system.webServer>
    </location>
</configuration>
"""
    doc = parse_iis_config(config, file_path="web.config")
    dir_browse = [s for s in doc.sections if s.tag == "directoryBrowse"]
    assert len(dir_browse) == 2
    paths = {s.location_path for s in dir_browse}
    assert paths == {"uploads", "admin"}


def test_location_path_empty_string_becomes_none() -> None:
    """<location path=""> is treated as global (location_path=None)."""
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <location path="">
        <system.webServer>
            <directoryBrowse enabled="true" />
        </system.webServer>
    </location>
</configuration>
"""
    doc = parse_iis_config(config, file_path="web.config")
    dir_browse = [s for s in doc.sections if s.tag == "directoryBrowse"]
    assert len(dir_browse) == 1
    assert dir_browse[0].location_path is None


def test_location_path_with_child_elements() -> None:
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <location path="secure">
        <system.webServer>
            <httpErrors>
                <remove statusCode="404" />
            </httpErrors>
        </system.webServer>
    </location>
</configuration>
"""
    doc = parse_iis_config(config, file_path="web.config")
    http_errors = [s for s in doc.sections if s.tag == "httpErrors"]
    assert len(http_errors) == 1
    assert http_errors[0].location_path == "secure"
    assert len(http_errors[0].children) == 1
    assert http_errors[0].children[0].tag == "remove"


def test_location_without_path_attribute() -> None:
    """<location> without path attr → location_path is None."""
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <location>
        <system.webServer>
            <directoryBrowse enabled="true" />
        </system.webServer>
    </location>
</configuration>
"""
    doc = parse_iis_config(config, file_path="web.config")
    dir_browse = [s for s in doc.sections if s.tag == "directoryBrowse"]
    assert len(dir_browse) == 1
    assert dir_browse[0].location_path is None


def test_existing_rules_still_fire_for_location_scoped_sections(tmp_path: Path) -> None:
    """directoryBrowse inside <location> still triggers the existing rule."""
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <location path="uploads">
        <system.webServer>
            <directoryBrowse enabled="true" />
        </system.webServer>
    </location>
</configuration>
"""
    (tmp_path / "web.config").write_text(config, encoding="utf-8")
    result = analyze_iis_config(str(tmp_path / "web.config"))
    rule_ids = {f.rule_id for f in result.findings}
    assert "iis.directory_browse_enabled" in rule_ids


# ---------------------------------------------------------------------------
# Location-aware finding tests (4.4)
# ---------------------------------------------------------------------------


def test_location_finding_includes_location_context_in_description(tmp_path: Path) -> None:
    """Findings from location-scoped sections mention the location path."""
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <location path="uploads">
        <system.webServer>
            <directoryBrowse enabled="true" />
        </system.webServer>
    </location>
</configuration>
"""
    (tmp_path / "web.config").write_text(config, encoding="utf-8")
    result = analyze_iis_config(str(tmp_path / "web.config"))
    finding = [f for f in result.findings if f.rule_id == "iis.directory_browse_enabled"][0]
    assert "uploads" in finding.description


def test_global_safe_location_unsafe_fires(tmp_path: Path) -> None:
    """Global directoryBrowse=false, but location overrides to true → finding."""
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.webServer>
        <directoryBrowse enabled="false" />
    </system.webServer>
    <location path="uploads">
        <system.webServer>
            <directoryBrowse enabled="true" />
        </system.webServer>
    </location>
</configuration>
"""
    (tmp_path / "web.config").write_text(config, encoding="utf-8")
    result = analyze_iis_config(str(tmp_path / "web.config"))
    findings = [f for f in result.findings if f.rule_id == "iis.directory_browse_enabled"]
    # Only the location-scoped one should fire, not the global.
    assert len(findings) == 1
    assert "uploads" in findings[0].description


def test_global_unsafe_location_overrides_to_safe(tmp_path: Path) -> None:
    """Global directoryBrowse=true fires, location overrides to false → no location finding."""
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.webServer>
        <directoryBrowse enabled="true" />
    </system.webServer>
    <location path="secure">
        <system.webServer>
            <directoryBrowse enabled="false" />
        </system.webServer>
    </location>
</configuration>
"""
    (tmp_path / "web.config").write_text(config, encoding="utf-8")
    result = analyze_iis_config(str(tmp_path / "web.config"))
    findings = [f for f in result.findings if f.rule_id == "iis.directory_browse_enabled"]
    # Global fires, location does not.
    assert len(findings) == 1
    assert "secure" not in findings[0].description


def test_multiple_locations_each_produce_findings(tmp_path: Path) -> None:
    """Two unsafe locations produce two separate findings."""
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <location path="uploads">
        <system.webServer>
            <directoryBrowse enabled="true" />
        </system.webServer>
    </location>
    <location path="public">
        <system.webServer>
            <directoryBrowse enabled="true" />
        </system.webServer>
    </location>
</configuration>
"""
    (tmp_path / "web.config").write_text(config, encoding="utf-8")
    result = analyze_iis_config(str(tmp_path / "web.config"))
    findings = [f for f in result.findings if f.rule_id == "iis.directory_browse_enabled"]
    assert len(findings) == 2
    descriptions = {f.description for f in findings}
    assert any("uploads" in d for d in descriptions)
    assert any("public" in d for d in descriptions)


def test_location_httpErrors_detailed_includes_context(tmp_path: Path) -> None:
    """httpErrors errorMode=Detailed at a location mentions the path."""
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <location path="api">
        <system.webServer>
            <httpErrors errorMode="Detailed" />
        </system.webServer>
    </location>
</configuration>
"""
    (tmp_path / "web.config").write_text(config, encoding="utf-8")
    result = analyze_iis_config(str(tmp_path / "web.config"))
    finding = [f for f in result.findings if f.rule_id == "iis.http_errors_detailed"][0]
    assert "api" in finding.description


def test_pure_inheritance_does_not_duplicate_finding(tmp_path: Path) -> None:
    """A location that purely inherits an unsafe global should NOT produce a duplicate."""
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.webServer>
        <directoryBrowse enabled="true" />
    </system.webServer>
    <location path="app">
        <system.webServer>
            <httpErrors errorMode="Custom" />
        </system.webServer>
    </location>
</configuration>
"""
    (tmp_path / "web.config").write_text(config, encoding="utf-8")
    result = analyze_iis_config(str(tmp_path / "web.config"))
    findings = [f for f in result.findings if f.rule_id == "iis.directory_browse_enabled"]
    # Only global fires; the inherited copy at "app" is suppressed.
    assert len(findings) == 1
    assert "app" not in findings[0].description


# ---------------------------------------------------------------------------
# Effective config reconstruction (4.3)
# ---------------------------------------------------------------------------


def _build(xml: str):
    doc = parse_iis_config(xml, file_path="web.config")
    return build_effective_config(doc)


def test_effective_global_section_attributes() -> None:
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.webServer>
        <directoryBrowse enabled="false" />
    </system.webServer>
</configuration>
"""
    eff = _build(config)
    section = eff.get_effective_section("/directoryBrowse")
    assert section is not None
    assert section.attributes["enabled"] == "false"
    assert section.location_path is None


def test_effective_location_overrides_global_attribute() -> None:
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.webServer>
        <directoryBrowse enabled="false" />
    </system.webServer>
    <location path="uploads">
        <system.webServer>
            <directoryBrowse enabled="true" />
        </system.webServer>
    </location>
</configuration>
"""
    eff = _build(config)

    g = eff.get_effective_section("/directoryBrowse")
    assert g is not None
    assert g.attributes["enabled"] == "false"

    loc = eff.get_effective_section("/directoryBrowse", location_path="uploads")
    assert loc is not None
    assert loc.attributes["enabled"] == "true"
    assert loc.location_path == "uploads"


def test_effective_location_inherits_global_when_no_override() -> None:
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.webServer>
        <directoryBrowse enabled="false" />
        <httpErrors errorMode="Custom" />
    </system.webServer>
    <location path="api">
        <system.webServer>
            <httpErrors errorMode="Detailed" />
        </system.webServer>
    </location>
</configuration>
"""
    eff = _build(config)

    loc_dir = eff.get_effective_section("/directoryBrowse", location_path="api")
    assert loc_dir is not None
    assert loc_dir.attributes["enabled"] == "false"
    assert loc_dir.location_path == "api"

    loc_err = eff.get_effective_section("/httpErrors", location_path="api")
    assert loc_err is not None
    assert loc_err.attributes["errorMode"] == "Detailed"


def test_effective_last_wins_for_duplicate_global_sections() -> None:
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.webServer>
        <httpErrors errorMode="Custom" />
    </system.webServer>
    <system.webServer>
        <httpErrors errorMode="Detailed" />
    </system.webServer>
</configuration>
"""
    eff = _build(config)
    section = eff.get_effective_section("/httpErrors")
    assert section is not None
    assert section.attributes["errorMode"] == "Detailed"


def test_effective_child_clear_removes_inherited() -> None:
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.webServer>
        <modules>
            <add name="Mod1" />
            <add name="Mod2" />
        </modules>
    </system.webServer>
    <location path="api">
        <system.webServer>
            <modules>
                <clear />
                <add name="Mod3" />
            </modules>
        </system.webServer>
    </location>
</configuration>
"""
    eff = _build(config)

    g = eff.get_effective_section("/modules")
    assert g is not None
    assert len(g.children) == 2

    loc = eff.get_effective_section("/modules", location_path="api")
    assert loc is not None
    assert len(loc.children) == 1
    assert loc.children[0].attributes.get("name") == "Mod3"


def test_effective_child_remove_deletes_by_key() -> None:
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.webServer>
        <modules>
            <add name="Mod1" />
            <add name="Mod2" />
            <add name="Mod3" />
        </modules>
    </system.webServer>
    <location path="api">
        <system.webServer>
            <modules>
                <remove name="Mod2" />
            </modules>
        </system.webServer>
    </location>
</configuration>
"""
    eff = _build(config)

    loc = eff.get_effective_section("/modules", location_path="api")
    assert loc is not None
    names = [c.attributes.get("name") for c in loc.children]
    assert names == ["Mod1", "Mod3"]


def test_effective_child_remove_prefers_known_key_attribute() -> None:
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.webServer>
        <httpErrors>
            <error statusCode="404" path="/not-found.htm" responseMode="File" />
            <error statusCode="500" path="/server-error.htm" responseMode="File" />
        </httpErrors>
    </system.webServer>
    <location path="api">
        <system.webServer>
            <httpErrors>
                <remove path="/wrong-key.htm" statusCode="404" />
            </httpErrors>
        </system.webServer>
    </location>
</configuration>
"""
    eff = _build(config)

    loc = eff.get_effective_section("/httpErrors", location_path="api")
    assert loc is not None
    status_codes = [c.attributes.get("statusCode") for c in loc.children]
    assert status_codes == ["500"]


def test_effective_child_add_appends() -> None:
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.webServer>
        <modules>
            <add name="Mod1" />
        </modules>
    </system.webServer>
    <location path="api">
        <system.webServer>
            <modules>
                <add name="Mod2" />
            </modules>
        </system.webServer>
    </location>
</configuration>
"""
    eff = _build(config)

    loc = eff.get_effective_section("/modules", location_path="api")
    assert loc is not None
    names = [c.attributes.get("name") for c in loc.children]
    assert names == ["Mod1", "Mod2"]


def test_effective_all_sections_includes_global_and_locations() -> None:
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.webServer>
        <directoryBrowse enabled="false" />
    </system.webServer>
    <location path="uploads">
        <system.webServer>
            <directoryBrowse enabled="true" />
        </system.webServer>
    </location>
</configuration>
"""
    eff = _build(config)
    all_s = eff.all_sections
    dir_browse = [s for s in all_s if s.tag == "directoryBrowse"]
    assert len(dir_browse) == 2


def test_effective_multiple_locations() -> None:
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.webServer>
        <directoryBrowse enabled="false" />
    </system.webServer>
    <location path="uploads">
        <system.webServer>
            <directoryBrowse enabled="true" />
        </system.webServer>
    </location>
    <location path="admin">
        <system.webServer>
            <directoryBrowse enabled="false" />
        </system.webServer>
    </location>
</configuration>
"""
    eff = _build(config)

    uploads = eff.get_effective_section("/directoryBrowse", location_path="uploads")
    assert uploads is not None
    assert uploads.attributes["enabled"] == "true"

    admin = eff.get_effective_section("/directoryBrowse", location_path="admin")
    assert admin is not None
    assert admin.attributes["enabled"] == "false"


def test_effective_location_merges_attributes_from_global() -> None:
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.webServer>
        <httpErrors errorMode="Custom" existingResponse="PassThrough" />
    </system.webServer>
    <location path="api">
        <system.webServer>
            <httpErrors errorMode="Detailed" />
        </system.webServer>
    </location>
</configuration>
"""
    eff = _build(config)
    loc = eff.get_effective_section("/httpErrors", location_path="api")
    assert loc is not None
    assert loc.attributes["errorMode"] == "Detailed"
    assert loc.attributes["existingResponse"] == "PassThrough"


def test_effective_empty_config() -> None:
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
</configuration>
"""
    eff = _build(config)
    assert eff.global_sections == {}
    assert eff.location_sections == {}


def test_effective_global_child_collection_merge() -> None:
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.webServer>
        <modules>
            <add name="Mod1" />
        </modules>
    </system.webServer>
    <system.webServer>
        <modules>
            <add name="Mod2" />
        </modules>
    </system.webServer>
</configuration>
"""
    eff = _build(config)
    g = eff.get_effective_section("/modules")
    assert g is not None
    names = [c.attributes.get("name") for c in g.children]
    assert names == ["Mod1", "Mod2"]


def test_effective_nested_location_inherits_from_parent_location() -> None:
    """api/v1 inherits from api, not just from global."""
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.webServer>
        <directoryBrowse enabled="false" />
    </system.webServer>
    <location path="api">
        <system.webServer>
            <httpErrors errorMode="Detailed" />
            <directoryBrowse enabled="true" />
        </system.webServer>
    </location>
    <location path="api/v1">
        <system.webServer>
            <directoryBrowse enabled="false" />
        </system.webServer>
    </location>
</configuration>
"""
    eff = _build(config)

    # api/v1 overrides directoryBrowse back to false.
    v1_dir = eff.get_effective_section("/directoryBrowse", location_path="api/v1")
    assert v1_dir is not None
    assert v1_dir.attributes["enabled"] == "false"

    # api/v1 inherits httpErrors from api (not from global which has none).
    v1_err = eff.get_effective_section("/httpErrors", location_path="api/v1")
    assert v1_err is not None
    assert v1_err.attributes["errorMode"] == "Detailed"
    assert v1_err.location_path == "api/v1"


def test_effective_deep_nested_location_inheritance() -> None:
    """api/v1/admin inherits through api/v1 → api → global."""
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.webServer>
        <directoryBrowse enabled="false" />
    </system.webServer>
    <location path="api">
        <system.webServer>
            <httpErrors errorMode="Detailed" />
        </system.webServer>
    </location>
    <location path="api/v1">
        <system.webServer>
            <modules>
                <add name="ApiModule" />
            </modules>
        </system.webServer>
    </location>
    <location path="api/v1/admin">
        <system.webServer>
            <directoryBrowse enabled="true" />
        </system.webServer>
    </location>
</configuration>
"""
    eff = _build(config)

    # api/v1/admin overrides directoryBrowse.
    admin_dir = eff.get_effective_section("/directoryBrowse", location_path="api/v1/admin")
    assert admin_dir is not None
    assert admin_dir.attributes["enabled"] == "true"

    # api/v1/admin inherits httpErrors from api.
    admin_err = eff.get_effective_section("/httpErrors", location_path="api/v1/admin")
    assert admin_err is not None
    assert admin_err.attributes["errorMode"] == "Detailed"

    # api/v1/admin inherits modules from api/v1.
    admin_mod = eff.get_effective_section("/modules", location_path="api/v1/admin")
    assert admin_mod is not None
    assert len(admin_mod.children) == 1
    assert admin_mod.children[0].attributes.get("name") == "ApiModule"


# ---------------------------------------------------------------------------
# Origin chain traceability (4.3 supplement)
# ---------------------------------------------------------------------------


def test_effective_origin_chain_global_only() -> None:
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.webServer>
        <directoryBrowse enabled="false" />
    </system.webServer>
</configuration>
"""
    eff = _build(config)
    section = eff.get_effective_section("/directoryBrowse")
    assert section is not None
    assert len(section.origin_chain) == 1
    assert section.source == section.origin_chain[-1]
    assert section.source.xml_path is not None
    assert "directoryBrowse" in section.source.xml_path


def test_effective_origin_chain_location_override() -> None:
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.webServer>
        <directoryBrowse enabled="false" />
    </system.webServer>
    <location path="uploads">
        <system.webServer>
            <directoryBrowse enabled="true" />
        </system.webServer>
    </location>
</configuration>
"""
    eff = _build(config)
    loc = eff.get_effective_section("/directoryBrowse", location_path="uploads")
    assert loc is not None
    # Chain: global source → location source.
    assert len(loc.origin_chain) == 2
    assert "location" not in (loc.origin_chain[0].xml_path or "")
    assert "location" in (loc.origin_chain[1].xml_path or "")
    # .source is the last (most specific).
    assert loc.source == loc.origin_chain[-1]


def test_effective_origin_chain_deep_inheritance() -> None:
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.webServer>
        <httpErrors errorMode="Custom" />
    </system.webServer>
    <location path="api">
        <system.webServer>
            <httpErrors errorMode="Detailed" />
        </system.webServer>
    </location>
    <location path="api/v1">
        <system.webServer>
            <httpErrors errorMode="DetailedLocalOnly" />
        </system.webServer>
    </location>
</configuration>
"""
    eff = _build(config)
    v1 = eff.get_effective_section("/httpErrors", location_path="api/v1")
    assert v1 is not None
    # Chain: global → api → api/v1.
    assert len(v1.origin_chain) == 3
    assert v1.attributes["errorMode"] == "DetailedLocalOnly"


def test_effective_origin_chain_pure_inheritance_preserves_chain() -> None:
    """When a location purely inherits (no override), origin chain is preserved."""
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.webServer>
        <directoryBrowse enabled="false" />
    </system.webServer>
    <location path="api">
        <system.webServer>
            <httpErrors errorMode="Detailed" />
        </system.webServer>
    </location>
</configuration>
"""
    eff = _build(config)
    # directoryBrowse is purely inherited at "api" location.
    loc = eff.get_effective_section("/directoryBrowse", location_path="api")
    assert loc is not None
    assert len(loc.origin_chain) == 1  # only global source, no override


# ---------------------------------------------------------------------------
# New rules (4.5): attribute-based
# ---------------------------------------------------------------------------


def test_request_filtering_allow_high_bit_fires(tmp_path: Path) -> None:
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.webServer>
        <security>
            <requestFiltering allowHighBitCharacters="true" />
        </security>
    </system.webServer>
</configuration>
"""
    (tmp_path / "web.config").write_text(config, encoding="utf-8")
    result = analyze_iis_config(str(tmp_path / "web.config"))
    assert "iis.request_filtering_allow_high_bit" in {f.rule_id for f in result.findings}


def test_request_filtering_allow_high_bit_silent(tmp_path: Path) -> None:
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.webServer>
        <security>
            <requestFiltering allowHighBitCharacters="false" />
        </security>
    </system.webServer>
</configuration>
"""
    (tmp_path / "web.config").write_text(config, encoding="utf-8")
    result = analyze_iis_config(str(tmp_path / "web.config"))
    assert "iis.request_filtering_allow_high_bit" not in {f.rule_id for f in result.findings}


def test_anonymous_auth_enabled_fires_with_other_scheme(tmp_path: Path) -> None:
    """anonymous + basic both enabled → fires."""
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.webServer>
        <security>
            <authentication>
                <anonymousAuthentication enabled="true" />
                <basicAuthentication enabled="true" />
            </authentication>
        </security>
    </system.webServer>
</configuration>
"""
    (tmp_path / "web.config").write_text(config, encoding="utf-8")
    result = analyze_iis_config(str(tmp_path / "web.config"))
    assert "iis.anonymous_auth_enabled" in {f.rule_id for f in result.findings}
    finding = [f for f in result.findings if f.rule_id == "iis.anonymous_auth_enabled"][0]
    assert "basic" in finding.description


def test_anonymous_auth_alone_silent(tmp_path: Path) -> None:
    """anonymous only (no other scheme) → no finding."""
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.webServer>
        <security>
            <authentication>
                <anonymousAuthentication enabled="true" />
            </authentication>
        </security>
    </system.webServer>
</configuration>
"""
    (tmp_path / "web.config").write_text(config, encoding="utf-8")
    result = analyze_iis_config(str(tmp_path / "web.config"))
    assert "iis.anonymous_auth_enabled" not in {f.rule_id for f in result.findings}


def test_anonymous_auth_disabled_silent(tmp_path: Path) -> None:
    """anonymous disabled + basic enabled → no finding."""
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.webServer>
        <security>
            <authentication>
                <anonymousAuthentication enabled="false" />
                <basicAuthentication enabled="true" />
            </authentication>
        </security>
    </system.webServer>
</configuration>
"""
    (tmp_path / "web.config").write_text(config, encoding="utf-8")
    result = analyze_iis_config(str(tmp_path / "web.config"))
    assert "iis.anonymous_auth_enabled" not in {f.rule_id for f in result.findings}


def test_forms_auth_require_ssl_missing_fires(tmp_path: Path) -> None:
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.web>
        <authentication>
            <forms requireSSL="false" loginUrl="/login" />
        </authentication>
    </system.web>
</configuration>
"""
    (tmp_path / "web.config").write_text(config, encoding="utf-8")
    result = analyze_iis_config(str(tmp_path / "web.config"))
    assert "iis.forms_auth_require_ssl_missing" in {f.rule_id for f in result.findings}


def test_forms_auth_require_ssl_missing_fires_when_attribute_absent(tmp_path: Path) -> None:
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.web>
        <authentication>
            <forms loginUrl="/login" />
        </authentication>
    </system.web>
</configuration>
"""
    (tmp_path / "web.config").write_text(config, encoding="utf-8")
    result = analyze_iis_config(str(tmp_path / "web.config"))
    assert "iis.forms_auth_require_ssl_missing" in {f.rule_id for f in result.findings}


def test_forms_auth_require_ssl_silent(tmp_path: Path) -> None:
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.web>
        <authentication>
            <forms requireSSL="true" loginUrl="/login" />
        </authentication>
    </system.web>
</configuration>
"""
    (tmp_path / "web.config").write_text(config, encoding="utf-8")
    result = analyze_iis_config(str(tmp_path / "web.config"))
    assert "iis.forms_auth_require_ssl_missing" not in {f.rule_id for f in result.findings}


def test_session_state_cookieless_fires(tmp_path: Path) -> None:
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.web>
        <sessionState cookieless="UseUri" />
    </system.web>
</configuration>
"""
    (tmp_path / "web.config").write_text(config, encoding="utf-8")
    result = analyze_iis_config(str(tmp_path / "web.config"))
    assert "iis.session_state_cookieless" in {f.rule_id for f in result.findings}


def test_session_state_cookieless_true_fires(tmp_path: Path) -> None:
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.web>
        <sessionState cookieless="true" />
    </system.web>
</configuration>
"""
    (tmp_path / "web.config").write_text(config, encoding="utf-8")
    result = analyze_iis_config(str(tmp_path / "web.config"))
    assert "iis.session_state_cookieless" in {f.rule_id for f in result.findings}


def test_session_state_cookieless_silent(tmp_path: Path) -> None:
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.web>
        <sessionState cookieless="UseCookies" />
    </system.web>
</configuration>
"""
    (tmp_path / "web.config").write_text(config, encoding="utf-8")
    result = analyze_iis_config(str(tmp_path / "web.config"))
    assert "iis.session_state_cookieless" not in {f.rule_id for f in result.findings}


# ---------------------------------------------------------------------------
# New rules (4.5): children-based
# ---------------------------------------------------------------------------


def test_webdav_module_enabled_fires(tmp_path: Path) -> None:
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.webServer>
        <modules>
            <add name="WebDAVModule" />
        </modules>
    </system.webServer>
</configuration>
"""
    (tmp_path / "web.config").write_text(config, encoding="utf-8")
    result = analyze_iis_config(str(tmp_path / "web.config"))
    assert "iis.webdav_module_enabled" in {f.rule_id for f in result.findings}
    finding = [f for f in result.findings if f.rule_id == "iis.webdav_module_enabled"][0]
    assert "WebDAVModule" in finding.description


def test_webdav_module_silent(tmp_path: Path) -> None:
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.webServer>
        <modules>
            <add name="StaticFileModule" />
        </modules>
    </system.webServer>
</configuration>
"""
    (tmp_path / "web.config").write_text(config, encoding="utf-8")
    result = analyze_iis_config(str(tmp_path / "web.config"))
    assert "iis.webdav_module_enabled" not in {f.rule_id for f in result.findings}


def test_webdav_module_removed_silent(tmp_path: Path) -> None:
    """WebDAV added then removed via collection semantics → no finding."""
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.webServer>
        <modules>
            <add name="WebDAVModule" />
            <remove name="WebDAVModule" />
        </modules>
    </system.webServer>
</configuration>
"""
    (tmp_path / "web.config").write_text(config, encoding="utf-8")
    result = analyze_iis_config(str(tmp_path / "web.config"))
    assert "iis.webdav_module_enabled" not in {f.rule_id for f in result.findings}


def test_cgi_handler_enabled_fires(tmp_path: Path) -> None:
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.webServer>
        <handlers>
            <add name="CGI-exe" path="*.exe" verb="*" modules="CgiModule" />
        </handlers>
    </system.webServer>
</configuration>
"""
    (tmp_path / "web.config").write_text(config, encoding="utf-8")
    result = analyze_iis_config(str(tmp_path / "web.config"))
    assert "iis.cgi_handler_enabled" in {f.rule_id for f in result.findings}
    finding = [f for f in result.findings if f.rule_id == "iis.cgi_handler_enabled"][0]
    assert "CGI-exe" in finding.description


def test_cgi_handler_silent(tmp_path: Path) -> None:
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.webServer>
        <handlers>
            <add name="StaticFile" path="*" verb="*" modules="StaticFileModule" />
        </handlers>
    </system.webServer>
</configuration>
"""
    (tmp_path / "web.config").write_text(config, encoding="utf-8")
    result = analyze_iis_config(str(tmp_path / "web.config"))
    assert "iis.cgi_handler_enabled" not in {f.rule_id for f in result.findings}


def test_cgi_handler_enabled_fires_for_combined_modules(tmp_path: Path) -> None:
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.webServer>
        <handlers>
            <add
                name="CGI-combined"
                path="*.cgi"
                verb="*"
                modules="StaticFileModule, CgiModule"
            />
        </handlers>
    </system.webServer>
</configuration>
"""
    (tmp_path / "web.config").write_text(config, encoding="utf-8")
    result = analyze_iis_config(str(tmp_path / "web.config"))
    findings = [f for f in result.findings if f.rule_id == "iis.cgi_handler_enabled"]
    assert len(findings) == 1
    assert "CGI-combined" in findings[0].description


def test_x_powered_by_present_fires(tmp_path: Path) -> None:
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.webServer>
        <httpProtocol>
            <customHeaders>
                <add name="X-Powered-By" value="ASP.NET" />
            </customHeaders>
        </httpProtocol>
    </system.webServer>
</configuration>
"""
    (tmp_path / "web.config").write_text(config, encoding="utf-8")
    result = analyze_iis_config(str(tmp_path / "web.config"))
    assert "iis.custom_headers_expose_server" in {f.rule_id for f in result.findings}


def test_x_powered_by_removed_silent(tmp_path: Path) -> None:
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.webServer>
        <httpProtocol>
            <customHeaders>
                <remove name="X-Powered-By" />
            </customHeaders>
        </httpProtocol>
    </system.webServer>
</configuration>
"""
    (tmp_path / "web.config").write_text(config, encoding="utf-8")
    result = analyze_iis_config(str(tmp_path / "web.config"))
    assert "iis.custom_headers_expose_server" not in {f.rule_id for f in result.findings}


def test_x_powered_by_add_then_remove_silent(tmp_path: Path) -> None:
    """X-Powered-By added then removed → no finding."""
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.webServer>
        <httpProtocol>
            <customHeaders>
                <add name="X-Powered-By" value="ASP.NET" />
                <remove name="X-Powered-By" />
            </customHeaders>
        </httpProtocol>
    </system.webServer>
</configuration>
"""
    (tmp_path / "web.config").write_text(config, encoding="utf-8")
    result = analyze_iis_config(str(tmp_path / "web.config"))
    assert "iis.custom_headers_expose_server" not in {f.rule_id for f in result.findings}


def test_location_scoped_anonymous_auth_includes_context(tmp_path: Path) -> None:
    """anonymousAuthentication + basic at a location mentions the path."""
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <location path="public">
        <system.webServer>
            <security>
                <authentication>
                    <anonymousAuthentication enabled="true" />
                    <windowsAuthentication enabled="true" />
                </authentication>
            </security>
        </system.webServer>
    </location>
</configuration>
"""
    (tmp_path / "web.config").write_text(config, encoding="utf-8")
    result = analyze_iis_config(str(tmp_path / "web.config"))
    findings = [f for f in result.findings if f.rule_id == "iis.anonymous_auth_enabled"]
    assert len(findings) == 1
    assert "public" in findings[0].description
    assert "Windows" in findings[0].description


# ---------------------------------------------------------------------------
# New rules (4.5): planned rules — SSL, TLS, HSTS, content length, logging
# ---------------------------------------------------------------------------


def test_ssl_not_required_fires_when_none(tmp_path: Path) -> None:
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.webServer>
        <security>
            <access sslFlags="None" />
        </security>
    </system.webServer>
</configuration>
"""
    (tmp_path / "web.config").write_text(config, encoding="utf-8")
    result = analyze_iis_config(str(tmp_path / "web.config"))
    assert "iis.ssl_not_required" in {f.rule_id for f in result.findings}


def test_ssl_not_required_fires_when_empty(tmp_path: Path) -> None:
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.webServer>
        <security>
            <access sslFlags="" />
        </security>
    </system.webServer>
</configuration>
"""
    (tmp_path / "web.config").write_text(config, encoding="utf-8")
    result = analyze_iis_config(str(tmp_path / "web.config"))
    assert "iis.ssl_not_required" in {f.rule_id for f in result.findings}


def test_ssl_not_required_silent_when_ssl(tmp_path: Path) -> None:
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.webServer>
        <security>
            <access sslFlags="Ssl,Ssl128" />
        </security>
    </system.webServer>
</configuration>
"""
    (tmp_path / "web.config").write_text(config, encoding="utf-8")
    result = analyze_iis_config(str(tmp_path / "web.config"))
    assert "iis.ssl_not_required" not in {f.rule_id for f in result.findings}


def test_weak_tls_fires_ssl_without_ssl128(tmp_path: Path) -> None:
    """sslFlags="Ssl" (without Ssl128) → weak_tls fires."""
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.webServer>
        <security>
            <access sslFlags="Ssl" />
        </security>
    </system.webServer>
</configuration>
"""
    (tmp_path / "web.config").write_text(config, encoding="utf-8")
    result = analyze_iis_config(str(tmp_path / "web.config"))
    assert "iis.ssl_weak_cipher_strength" in {f.rule_id for f in result.findings}
    assert "iis.ssl_not_required" not in {f.rule_id for f in result.findings}


def test_weak_tls_uses_sslflag_tokens_not_substrings(tmp_path: Path) -> None:
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.webServer>
        <security>
            <access sslFlags="SslNegotiateCert" />
        </security>
    </system.webServer>
</configuration>
"""
    (tmp_path / "web.config").write_text(config, encoding="utf-8")
    result = analyze_iis_config(str(tmp_path / "web.config"))
    assert "iis.ssl_weak_cipher_strength" not in {f.rule_id for f in result.findings}


def test_missing_hsts_header_fires(tmp_path: Path) -> None:
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.webServer>
        <httpProtocol>
            <customHeaders>
                <add name="X-Content-Type-Options" value="nosniff" />
            </customHeaders>
        </httpProtocol>
    </system.webServer>
</configuration>
"""
    (tmp_path / "web.config").write_text(config, encoding="utf-8")
    result = analyze_iis_config(str(tmp_path / "web.config"))
    assert "iis.missing_hsts_header" in {f.rule_id for f in result.findings}


def test_missing_hsts_header_silent(tmp_path: Path) -> None:
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.webServer>
        <httpProtocol>
            <customHeaders>
                <add name="Strict-Transport-Security" value="max-age=31536000" />
            </customHeaders>
        </httpProtocol>
    </system.webServer>
</configuration>
"""
    (tmp_path / "web.config").write_text(config, encoding="utf-8")
    result = analyze_iis_config(str(tmp_path / "web.config"))
    assert "iis.missing_hsts_header" not in {f.rule_id for f in result.findings}


def test_max_allowed_content_length_missing_fires(tmp_path: Path) -> None:
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.webServer>
        <security>
            <requestFiltering>
                <requestLimits maxUrl="4096" />
            </requestFiltering>
        </security>
    </system.webServer>
</configuration>
"""
    (tmp_path / "web.config").write_text(config, encoding="utf-8")
    result = analyze_iis_config(str(tmp_path / "web.config"))
    assert "iis.max_allowed_content_length_missing" in {f.rule_id for f in result.findings}


def test_max_allowed_content_length_set_silent(tmp_path: Path) -> None:
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.webServer>
        <security>
            <requestFiltering>
                <requestLimits maxAllowedContentLength="4194304" />
            </requestFiltering>
        </security>
    </system.webServer>
</configuration>
"""
    (tmp_path / "web.config").write_text(config, encoding="utf-8")
    result = analyze_iis_config(str(tmp_path / "web.config"))
    assert "iis.max_allowed_content_length_missing" not in {f.rule_id for f in result.findings}


def test_logging_not_configured_fires(tmp_path: Path) -> None:
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.webServer>
        <httpLogging dontLog="true" />
    </system.webServer>
</configuration>
"""
    (tmp_path / "web.config").write_text(config, encoding="utf-8")
    result = analyze_iis_config(str(tmp_path / "web.config"))
    assert "iis.logging_not_configured" in {f.rule_id for f in result.findings}


def test_logging_not_configured_silent(tmp_path: Path) -> None:
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.webServer>
        <httpLogging dontLog="false" />
    </system.webServer>
</configuration>
"""
    (tmp_path / "web.config").write_text(config, encoding="utf-8")
    result = analyze_iis_config(str(tmp_path / "web.config"))
    assert "iis.logging_not_configured" not in {f.rule_id for f in result.findings}


# ---------------------------------------------------------------------------
# Absence-complete tests
# ---------------------------------------------------------------------------


def test_hsts_absence_fires_when_no_custom_headers_section(tmp_path: Path) -> None:
    """No customHeaders section at all → HSTS absence fires."""
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.webServer>
        <directoryBrowse enabled="false" />
    </system.webServer>
</configuration>
"""
    (tmp_path / "web.config").write_text(config, encoding="utf-8")
    result = analyze_iis_config(str(tmp_path / "web.config"))
    assert "iis.missing_hsts_header" in {f.rule_id for f in result.findings}


def test_logging_absence_fires_when_no_httpLogging_section(tmp_path: Path) -> None:
    """No httpLogging section at all → logging absence fires."""
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.webServer>
        <directoryBrowse enabled="false" />
    </system.webServer>
</configuration>
"""
    (tmp_path / "web.config").write_text(config, encoding="utf-8")
    result = analyze_iis_config(str(tmp_path / "web.config"))
    assert "iis.logging_not_configured" in {f.rule_id for f in result.findings}


def test_hsts_absence_silent_when_hsts_present(tmp_path: Path) -> None:
    """customHeaders with HSTS → no absence finding."""
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.webServer>
        <httpProtocol>
            <customHeaders>
                <add name="Strict-Transport-Security"
                     value="max-age=31536000" />
            </customHeaders>
        </httpProtocol>
    </system.webServer>
</configuration>
"""
    (tmp_path / "web.config").write_text(config, encoding="utf-8")
    result = analyze_iis_config(str(tmp_path / "web.config"))
    assert "iis.missing_hsts_header" not in {f.rule_id for f in result.findings}


# ---------------------------------------------------------------------------
# Broadened expose_server tests
# ---------------------------------------------------------------------------


def test_expose_server_aspnetmvc_version_fires(tmp_path: Path) -> None:
    """X-AspNetMvc-Version header triggers expose_server."""
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.webServer>
        <httpProtocol>
            <customHeaders>
                <add name="X-AspNetMvc-Version" value="5.2" />
                <add name="Strict-Transport-Security"
                     value="max-age=31536000" />
            </customHeaders>
        </httpProtocol>
    </system.webServer>
</configuration>
"""
    (tmp_path / "web.config").write_text(config, encoding="utf-8")
    result = analyze_iis_config(str(tmp_path / "web.config"))
    assert "iis.custom_headers_expose_server" in {f.rule_id for f in result.findings}
    finding = [f for f in result.findings if f.rule_id == "iis.custom_headers_expose_server"][0]
    assert "X-AspNetMvc-Version" in finding.description


def test_expose_server_both_headers_single_finding(tmp_path: Path) -> None:
    """X-Powered-By + X-AspNetMvc-Version → one finding listing both."""
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.webServer>
        <httpProtocol>
            <customHeaders>
                <add name="X-Powered-By" value="ASP.NET" />
                <add name="X-AspNetMvc-Version" value="5.2" />
                <add name="Strict-Transport-Security"
                     value="max-age=31536000" />
            </customHeaders>
        </httpProtocol>
    </system.webServer>
</configuration>
"""
    (tmp_path / "web.config").write_text(config, encoding="utf-8")
    result = analyze_iis_config(str(tmp_path / "web.config"))
    findings = [f for f in result.findings if f.rule_id == "iis.custom_headers_expose_server"]
    assert len(findings) == 1
    assert "X-Powered-By" in findings[0].description
    assert "X-AspNetMvc-Version" in findings[0].description


def test_expose_server_both_removed_silent(tmp_path: Path) -> None:
    """Both headers removed → no expose_server finding."""
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.webServer>
        <httpProtocol>
            <customHeaders>
                <add name="X-Powered-By" value="ASP.NET" />
                <remove name="X-Powered-By" />
                <add name="X-AspNetMvc-Version" value="5.2" />
                <remove name="X-AspNetMvc-Version" />
                <add name="Strict-Transport-Security"
                     value="max-age=31536000" />
            </customHeaders>
        </httpProtocol>
    </system.webServer>
</configuration>
"""
    (tmp_path / "web.config").write_text(config, encoding="utf-8")
    result = analyze_iis_config(str(tmp_path / "web.config"))
    assert "iis.custom_headers_expose_server" not in {f.rule_id for f in result.findings}


# ---------------------------------------------------------------------------
# ssl_not_required — binding-aware absence checks
# ---------------------------------------------------------------------------


def test_ssl_not_required_absence_fires_with_https_binding(tmp_path: Path) -> None:
    """HTTPS binding present but no /access section → fires ssl_not_required."""
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.applicationHost>
        <sites>
            <site name="Default Web Site" id="1">
                <bindings>
                    <binding protocol="https" bindingInformation="*:443:" />
                </bindings>
            </site>
        </sites>
    </system.applicationHost>
    <system.webServer>
        <httpProtocol>
            <customHeaders>
                <add name="Strict-Transport-Security"
                     value="max-age=31536000" />
            </customHeaders>
        </httpProtocol>
        <httpLogging dontLog="false" />
        <security>
            <requestFiltering>
                <requestLimits maxAllowedContentLength="4194304" />
            </requestFiltering>
        </security>
    </system.webServer>
</configuration>
"""
    (tmp_path / "web.config").write_text(config, encoding="utf-8")
    result = analyze_iis_config(str(tmp_path / "web.config"))
    assert "iis.ssl_not_required" in {f.rule_id for f in result.findings}


def test_ssl_not_required_absence_silent_without_https_binding(tmp_path: Path) -> None:
    """No HTTPS binding and no /access section → no ssl_not_required finding."""
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.webServer>
        <httpProtocol>
            <customHeaders>
                <add name="Strict-Transport-Security"
                     value="max-age=31536000" />
            </customHeaders>
        </httpProtocol>
        <httpLogging dontLog="false" />
        <security>
            <requestFiltering>
                <requestLimits maxAllowedContentLength="4194304" />
            </requestFiltering>
        </security>
    </system.webServer>
</configuration>
"""
    (tmp_path / "web.config").write_text(config, encoding="utf-8")
    result = analyze_iis_config(str(tmp_path / "web.config"))
    assert "iis.ssl_not_required" not in {f.rule_id for f in result.findings}


# ---------------------------------------------------------------------------
# max_allowed_content_length — absence and threshold checks
# ---------------------------------------------------------------------------


def test_max_content_length_absence_fires_when_no_request_limits(tmp_path: Path) -> None:
    """No requestLimits section at all → fires max_allowed_content_length_missing."""
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.webServer>
        <httpProtocol>
            <customHeaders>
                <add name="Strict-Transport-Security"
                     value="max-age=31536000" />
            </customHeaders>
        </httpProtocol>
        <httpLogging dontLog="false" />
    </system.webServer>
</configuration>
"""
    (tmp_path / "web.config").write_text(config, encoding="utf-8")
    result = analyze_iis_config(str(tmp_path / "web.config"))
    assert "iis.max_allowed_content_length_missing" in {f.rule_id for f in result.findings}


def test_max_content_length_excessive_fires(tmp_path: Path) -> None:
    """maxAllowedContentLength=1073741824 (1 GB) exceeds threshold → fires."""
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.webServer>
        <httpProtocol>
            <customHeaders>
                <add name="Strict-Transport-Security"
                     value="max-age=31536000" />
            </customHeaders>
        </httpProtocol>
        <httpLogging dontLog="false" />
        <security>
            <requestFiltering>
                <requestLimits maxAllowedContentLength="1073741824" />
            </requestFiltering>
        </security>
    </system.webServer>
</configuration>
"""
    (tmp_path / "web.config").write_text(config, encoding="utf-8")
    result = analyze_iis_config(str(tmp_path / "web.config"))
    findings = [f for f in result.findings if f.rule_id == "iis.max_allowed_content_length_missing"]
    assert len(findings) == 1
    assert "excessive" in findings[0].description.lower() or "1073741824" in findings[0].description


def test_max_content_length_reasonable_value_silent(tmp_path: Path) -> None:
    """maxAllowedContentLength=4194304 (4 MB) is reasonable → no finding."""
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.webServer>
        <httpProtocol>
            <customHeaders>
                <add name="Strict-Transport-Security"
                     value="max-age=31536000" />
            </customHeaders>
        </httpProtocol>
        <httpLogging dontLog="false" />
        <security>
            <requestFiltering>
                <requestLimits maxAllowedContentLength="4194304" />
            </requestFiltering>
        </security>
    </system.webServer>
</configuration>
"""
    (tmp_path / "web.config").write_text(config, encoding="utf-8")
    result = analyze_iis_config(str(tmp_path / "web.config"))
    assert "iis.max_allowed_content_length_missing" not in {f.rule_id for f in result.findings}

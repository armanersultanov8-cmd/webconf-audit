from __future__ import annotations

from webconf_audit.local.iis.effective import IISEffectiveSection
from webconf_audit.local.iis.parser import IISSourceRef
from webconf_audit.local.iis.rules.rule_utils import is_pure_inheritance


def test_is_pure_inheritance_true_for_location_copy_without_location_origin() -> None:
    section = IISEffectiveSection(
        tag="directoryBrowse",
        section_path_suffix="/directoryBrowse",
        attributes={"enabled": "true"},
        children=[],
        location_path="app",
        origin_chain=[
            IISSourceRef(
                file_path="applicationHost.config",
                xml_path="configuration/system.webServer/directoryBrowse",
            )
        ],
    )

    assert is_pure_inheritance(section) is True


def test_is_pure_inheritance_false_when_location_override_contributes_origin() -> None:
    section = IISEffectiveSection(
        tag="directoryBrowse",
        section_path_suffix="/directoryBrowse",
        attributes={"enabled": "true"},
        children=[],
        location_path="app",
        origin_chain=[
            IISSourceRef(
                file_path="applicationHost.config",
                xml_path="configuration/system.webServer/directoryBrowse",
            ),
            IISSourceRef(
                file_path="web.config",
                xml_path="configuration/location[@path='app']/system.webServer/directoryBrowse",
            ),
        ],
    )

    assert is_pure_inheritance(section) is False

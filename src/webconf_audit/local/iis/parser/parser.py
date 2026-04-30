from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal
# ``defusedxml.ElementTree`` hardens parsing against XXE / external-entity
# attacks but intentionally does not re-export the ``Element`` class:
# types still have to come from the stdlib ``xml.etree.ElementTree``
# module, so import them separately and keep ``ET`` for parser calls.
from defusedxml import ElementTree as ET
from xml.etree.ElementTree import Element as _XmlElement


IISConfigKind = Literal["applicationHost", "web", "machine", "unknown"]


class IISParseError(ValueError):
    def __init__(
        self,
        message: str,
        *,
        file_path: str | None = None,
        line: int | None = None,
    ) -> None:
        self.file_path = file_path
        self.line = line
        super().__init__(message)


@dataclass(slots=True)
class IISSourceRef:
    file_path: str | None = None
    xml_path: str | None = None
    line: int | None = None


@dataclass(slots=True)
class IISChildElement:
    tag: str
    attributes: dict[str, str] = field(default_factory=dict)
    source: IISSourceRef = field(default_factory=IISSourceRef)


@dataclass(slots=True)
class IISSection:
    tag: str
    xml_path: str
    attributes: dict[str, str] = field(default_factory=dict)
    children: list[IISChildElement] = field(default_factory=list)
    location_path: str | None = None
    source: IISSourceRef = field(default_factory=IISSourceRef)


@dataclass(slots=True)
class IISConfigDocument:
    root_tag: str
    config_kind: IISConfigKind
    sections: list[IISSection]
    file_path: str | None = None


def classify_config_kind(
    root_tag: str,
    file_path: str | None,
    *,
    root: _XmlElement | None = None,
) -> IISConfigKind:
    if file_path is not None:
        lower_path = file_path.lower().replace("\\", "/")
        if lower_path.endswith("applicationhost.config"):
            return "applicationHost"
        if lower_path.endswith("machine.config"):
            return "machine"
        if lower_path.endswith("web.config"):
            return "web"

    if root_tag == "configuration":
        if root is not None:
            child_tags = {child.tag for child in root}
            if "system.applicationHost" in child_tags:
                return "applicationHost"
            if _looks_like_machine_config(child_tags):
                return "machine"
        return "unknown"

    return "unknown"


def parse_iis_config(
    text: str,
    *,
    file_path: str | None = None,
) -> IISConfigDocument:
    try:
        root = ET.fromstring(text)
    except ET.ParseError as exc:
        line = exc.position[0] if exc.position else None
        raise IISParseError(
            f"XML parse error: {exc}",
            file_path=file_path,
            line=line,
        ) from exc

    config_kind = classify_config_kind(root.tag, file_path, root=root)
    sections = _extract_sections(root, file_path=file_path)

    return IISConfigDocument(
        root_tag=root.tag,
        config_kind=config_kind,
        sections=sections,
        file_path=file_path,
    )


def _extract_sections(
    root: _XmlElement,
    *,
    file_path: str | None = None,
) -> list[IISSection]:
    sections: list[IISSection] = []

    for child in root:
        if child.tag == "location":
            loc_path = child.attrib.get("path", "")
            loc_prefix = f"{root.tag}/location[@path='{loc_path}']"
            for grandchild in child:
                _append_section_tree(
                    grandchild,
                    parent_path=loc_prefix,
                    sections=sections,
                    file_path=file_path,
                    location_path=loc_path or None,
                )
        else:
            _append_section_tree(
                child,
                parent_path=root.tag,
                sections=sections,
                file_path=file_path,
                location_path=None,
            )

    return sections


def _looks_like_machine_config(child_tags: set[str]) -> bool:
    return "configSections" in child_tags and bool(
        child_tags & {"system.web", "runtime", "mscorlib"}
    )


_CHILD_DIRECTIVE_TAGS = frozenset({
    "add", "remove", "clear", "error", "binding",
    "deny", "allow", "rule", "filter", "limit",
})


def _is_child_directive(element: _XmlElement) -> bool:
    """Return True if the element should be stored as a child of its parent section."""
    return element.tag.lower() in _CHILD_DIRECTIVE_TAGS


def _append_section_tree(
    element: _XmlElement,
    *,
    parent_path: str,
    sections: list[IISSection],
    file_path: str | None,
    location_path: str | None = None,
) -> None:
    xml_path = f"{parent_path}/{element.tag}"
    child_elements: list[IISChildElement] = []
    sub_elements: list[_XmlElement] = []

    for child in element:
        if _is_child_directive(child):
            child_elements.append(
                IISChildElement(
                    tag=child.tag,
                    attributes=dict(child.attrib),
                    source=IISSourceRef(
                        file_path=file_path,
                        xml_path=f"{xml_path}/{child.tag}",
                    ),
                )
            )
        else:
            sub_elements.append(child)

    sections.append(
        IISSection(
            tag=element.tag,
            xml_path=xml_path,
            attributes=dict(element.attrib),
            children=child_elements,
            location_path=location_path,
            source=IISSourceRef(
                file_path=file_path,
                xml_path=xml_path,
            ),
        )
    )

    for sub in sub_elements:
        _append_section_tree(
            sub,
            parent_path=xml_path,
            sections=sections,
            file_path=file_path,
            location_path=location_path,
        )


__all__ = [
    "IISChildElement",
    "IISConfigDocument",
    "IISConfigKind",
    "IISParseError",
    "IISSection",
    "IISSourceRef",
    "classify_config_kind",
    "parse_iis_config",
]

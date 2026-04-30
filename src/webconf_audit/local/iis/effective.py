"""IIS effective configuration reconstruction for a single file scope.

Merges global sections with location-scoped overrides and applies
child-element collection semantics (clear / remove / add).
"""

from __future__ import annotations

from dataclasses import dataclass, field

from webconf_audit.local.iis.parser import (
    IISChildElement,
    IISConfigDocument,
    IISSection,
    IISSourceRef,
)

_REMOVE_KEY_COMBINATIONS: tuple[tuple[str, ...], ...] = (
    ("statusCode",),
    ("ipAddress", "subnetMask"),
    ("ipAddress",),
    ("name", "path", "verb"),
    ("name",),
    ("path", "verb"),
    ("path",),
)


@dataclass(frozen=True, slots=True)
class IISEffectiveSection:
    """A section after global and location merge."""

    tag: str
    section_path_suffix: str
    attributes: dict[str, str]
    children: list[IISChildElement]
    location_path: str | None
    origin_chain: list[IISSourceRef]

    @property
    def source(self) -> IISSourceRef:
        """Source of the most specific contributing section."""
        return self.origin_chain[-1]


@dataclass(frozen=True, slots=True)
class IISEffectiveConfig:
    """Effective configuration for one IIS config file."""

    global_sections: dict[str, IISEffectiveSection] = field(default_factory=dict)
    location_sections: dict[str, dict[str, IISEffectiveSection]] = field(
        default_factory=dict,
    )

    def get_effective_section(
        self,
        suffix: str,
        location_path: str | None = None,
    ) -> IISEffectiveSection | None:
        """Return the effective section for a suffix and optional location."""
        if location_path is not None:
            loc = self.location_sections.get(location_path, {})
            return loc.get(suffix)
        return self.global_sections.get(suffix)

    @property
    def all_sections(self) -> list[IISEffectiveSection]:
        """Return all effective sections across global and locations."""
        result = list(self.global_sections.values())
        for loc_dict in self.location_sections.values():
            result.extend(loc_dict.values())
        return result


def build_effective_config(doc: IISConfigDocument) -> IISEffectiveConfig:
    """Build effective config from a parsed IIS config document."""
    global_raw, location_raw = _group_raw_sections(doc.sections)
    global_effective = _merge_global_sections(global_raw)
    location_effective = _merge_location_sections(location_raw, global_effective)
    return IISEffectiveConfig(
        global_sections=global_effective,
        location_sections=location_effective,
    )


def _group_raw_sections(
    sections: list[IISSection],
) -> tuple[
    dict[str, list[IISSection]],
    dict[str, dict[str, list[IISSection]]],
]:
    global_raw: dict[str, list[IISSection]] = {}
    location_raw: dict[str, dict[str, list[IISSection]]] = {}
    for section in sections:
        suffix = _section_suffix(section.xml_path)
        if section.location_path is None:
            global_raw.setdefault(suffix, []).append(section)
            continue

        loc_dict = location_raw.setdefault(section.location_path, {})
        loc_dict.setdefault(suffix, []).append(section)
    return global_raw, location_raw


def _merge_global_sections(
    global_raw: dict[str, list[IISSection]],
) -> dict[str, IISEffectiveSection]:
    global_effective: dict[str, IISEffectiveSection] = {}
    for suffix, sections in global_raw.items():
        global_effective[suffix] = _merge_sections(sections, location_path=None)
    return global_effective


def _merge_location_sections(
    location_raw: dict[str, dict[str, list[IISSection]]],
    global_effective: dict[str, IISEffectiveSection],
) -> dict[str, dict[str, IISEffectiveSection]]:
    location_effective: dict[str, dict[str, IISEffectiveSection]] = {}
    for location_path in sorted(
        location_raw,
        key=lambda path: (path.count("/"), path),
    ):
        parent_effective = _find_parent_effective(
            location_path,
            location_effective,
            global_effective,
        )
        location_effective[location_path] = _merge_location_section_dict(
            location_path,
            parent_effective,
            location_raw[location_path],
        )
    return location_effective


def _merge_location_section_dict(
    location_path: str,
    parent_effective: dict[str, IISEffectiveSection],
    raw_sections: dict[str, list[IISSection]],
) -> dict[str, IISEffectiveSection]:
    merged: dict[str, IISEffectiveSection] = {}
    for suffix in set(parent_effective) | set(raw_sections):
        base = parent_effective.get(suffix)
        overrides = raw_sections.get(suffix, [])
        if not overrides:
            if base is not None:
                merged[suffix] = _clone_effective_section(
                    base,
                    location_path=location_path,
                )
            continue

        merged[suffix] = _merge_location_section_overrides(
            overrides,
            base,
            location_path,
        )
    return merged


def _merge_location_section_overrides(
    overrides: list[IISSection],
    base: IISEffectiveSection | None,
    location_path: str,
) -> IISEffectiveSection:
    base_attrs = dict(base.attributes) if base else {}
    base_children = list(base.children) if base else []
    base_origin = list(base.origin_chain) if base else []
    return _merge_sections(
        overrides,
        location_path=location_path,
        base_attrs=base_attrs,
        base_children=base_children,
        base_origin=base_origin,
    )


def _find_parent_effective(
    loc_path: str,
    location_effective: dict[str, dict[str, IISEffectiveSection]],
    global_effective: dict[str, IISEffectiveSection],
) -> dict[str, IISEffectiveSection]:
    """Find the nearest parent location's effective sections for *loc_path*."""
    parts = loc_path.replace("\\", "/").split("/")
    for depth in range(len(parts) - 1, 0, -1):
        candidate = "/".join(parts[:depth])
        if candidate in location_effective:
            return location_effective[candidate]
    return global_effective


def _merge_sections(
    sections: list[IISSection],
    *,
    location_path: str | None,
    base_attrs: dict[str, str] | None = None,
    base_children: list[IISChildElement] | None = None,
    base_origin: list[IISSourceRef] | None = None,
) -> IISEffectiveSection:
    """Merge multiple raw sections into one effective section."""
    attrs = dict(base_attrs) if base_attrs else {}
    children = list(base_children) if base_children else []
    origin = list(base_origin) if base_origin else []
    tag = sections[-1].tag

    for section in sections:
        attrs.update(section.attributes)
        origin.append(section.source)
        children = _merge_children(children, section.children)

    suffix = _section_suffix(sections[-1].xml_path)
    return IISEffectiveSection(
        tag=tag,
        section_path_suffix=suffix,
        attributes=attrs,
        children=children,
        location_path=location_path,
        origin_chain=origin,
    )


def _merge_children(
    base: list[IISChildElement],
    incoming: list[IISChildElement],
) -> list[IISChildElement]:
    """Apply IIS collection semantics to child elements."""
    result = list(base)
    for child in incoming:
        tag_lower = child.tag.lower()
        if tag_lower == "clear":
            result.clear()
            continue
        if tag_lower == "remove":
            if child.attributes:
                result = [
                    candidate
                    for candidate in result
                    if not _matches_remove_attributes(candidate, child)
                ]
            continue
        result.append(child)
    return result


def _matches_remove_attributes(
    candidate: IISChildElement,
    remove_child: IISChildElement,
) -> bool:
    """Return True when *candidate* matches every selected remove attribute."""
    match_attributes = _remove_match_attributes(remove_child)
    return all(
        candidate.attributes.get(name) == value
        for name, value in match_attributes.items()
    )


def _remove_match_attributes(remove_child: IISChildElement) -> dict[str, str]:
    attrs = remove_child.attributes
    for key_names in _REMOVE_KEY_COMBINATIONS:
        matched = _matching_remove_keys(attrs, key_names)
        if matched:
            return matched
    return attrs


def _matching_remove_keys(
    attrs: dict[str, str],
    key_names: tuple[str, ...],
) -> dict[str, str]:
    # IIS treats a ``<remove>`` element's key group as atomic: the whole
    # combination must be present on the element for it to be considered
    # a match.  Returning a partial dict when only some of the keys are
    # present (e.g. only ``ipAddress`` from the ``ipAddress``+``subnetMask``
    # pair used by ``ipSecurity``) causes the caller to match the wrong
    # entry and drop a different element from the collection.  Require
    # every key to be present before reporting a hit.
    if not all(name in attrs for name in key_names):
        return {}
    return {name: attrs[name] for name in key_names}


def _section_suffix(xml_path: str) -> str:
    """Extract the section-identifying suffix from an xml_path."""
    last_slash = xml_path.rfind("/")
    if last_slash >= 0:
        return xml_path[last_slash:]
    return f"/{xml_path}"


def merge_effective_configs(
    base: IISEffectiveConfig,
    override: IISEffectiveConfig,
) -> IISEffectiveConfig:
    """Merge two effective configs such as applicationHost.config and web.config."""
    merged_global = _merge_section_dicts(
        base.global_sections,
        override.global_sections,
        location_path=None,
    )

    merged_locations: dict[str, dict[str, IISEffectiveSection]] = {}
    all_location_paths = set(base.location_sections) | set(override.location_sections)
    for location_path in sorted(all_location_paths, key=lambda path: (path.count("/"), path)):
        base_loc = _effective_sections_for_location(base, location_path)
        override_loc = _effective_sections_for_location(override, location_path)
        merged_locations[location_path] = _merge_section_dicts(
            base_loc,
            override_loc,
            location_path=location_path,
        )

    return IISEffectiveConfig(
        global_sections=merged_global,
        location_sections=merged_locations,
    )


def _merge_section_dicts(
    base: dict[str, IISEffectiveSection],
    override: dict[str, IISEffectiveSection],
    *,
    location_path: str | None,
) -> dict[str, IISEffectiveSection]:
    """Merge two suffix-to-section mappings using IIS merge semantics."""
    merged: dict[str, IISEffectiveSection] = {}
    for suffix in set(base) | set(override):
        base_sec = base.get(suffix)
        override_sec = override.get(suffix)
        if base_sec is None and override_sec is not None:
            merged[suffix] = _clone_effective_section(
                override_sec,
                location_path=location_path,
            )
            continue
        if override_sec is None and base_sec is not None:
            merged[suffix] = _clone_effective_section(
                base_sec,
                location_path=location_path,
            )
            continue
        if base_sec is not None and override_sec is not None:
            merged[suffix] = _merge_effective_section_pair(
                base_sec,
                override_sec,
                location_path=location_path,
            )
    return merged


def _merge_effective_section_pair(
    base: IISEffectiveSection,
    override: IISEffectiveSection,
    *,
    location_path: str | None,
) -> IISEffectiveSection:
    """Merge two effective sections where override children already won locally."""
    attrs = dict(base.attributes)
    attrs.update(override.attributes)
    children = list(override.children)
    origin = list(base.origin_chain) + list(override.origin_chain)
    return IISEffectiveSection(
        tag=override.tag,
        section_path_suffix=override.section_path_suffix,
        attributes=attrs,
        children=children,
        location_path=location_path if location_path is not None else override.location_path,
        origin_chain=origin,
    )


def _effective_sections_for_location(
    config: IISEffectiveConfig,
    location_path: str,
) -> dict[str, IISEffectiveSection]:
    if location_path in config.location_sections:
        return config.location_sections[location_path]
    return _find_parent_effective(
        location_path,
        config.location_sections,
        config.global_sections,
    )


def _clone_effective_section(
    section: IISEffectiveSection,
    *,
    location_path: str | None,
) -> IISEffectiveSection:
    return IISEffectiveSection(
        tag=section.tag,
        section_path_suffix=section.section_path_suffix,
        attributes=dict(section.attributes),
        children=list(section.children),
        location_path=location_path if location_path is not None else section.location_path,
        origin_chain=list(section.origin_chain),
    )


__all__ = [
    "IISEffectiveConfig",
    "IISEffectiveSection",
    "build_effective_config",
    "merge_effective_configs",
]

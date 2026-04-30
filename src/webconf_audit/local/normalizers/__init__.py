"""Normalization dispatch - thin entry point for universal rules.

Usage::

    from webconf_audit.local.normalizers import normalize_config

    normalized = normalize_config("nginx", ast=ast)
    # or
    normalized = normalize_config("lighttpd", ast=ast, effective_config=eff)
"""

from __future__ import annotations

from typing import Any

from webconf_audit.local.normalized import NormalizedConfig


def normalize_config(
    server_type: str,
    *,
    ast: Any = None,
    effective_config: Any = None,
    doc: Any = None,
    merged_directives: Any = None,
) -> NormalizedConfig:
    """Dispatch to the appropriate server normalizer.

    Parameters
    ----------
    server_type:
        One of ``"nginx"``, ``"apache"``, ``"lighttpd"``, ``"iis"``.
    ast:
        Server-native AST (required for Nginx, Apache, Lighttpd).
    effective_config:
        Server-native effective config (optional; used by Lighttpd, IIS).
    doc:
        IIS ``IISConfigDocument`` (required for IIS).

    Returns
    -------
    NormalizedConfig
        Normalized configuration.  For unknown server types, returns an
        empty config with the given ``server_type``.
    """
    normalized_server_type = server_type.strip().lower()

    if normalized_server_type == "nginx":
        from webconf_audit.local.normalizers.nginx_normalizer import normalize_nginx

        _require_argument("ast", ast, normalized_server_type)
        return normalize_nginx(ast)

    if normalized_server_type == "apache":
        from webconf_audit.local.normalizers.apache_normalizer import normalize_apache

        _require_argument("ast", ast, normalized_server_type)
        return normalize_apache(ast, effective_config=effective_config)

    if normalized_server_type == "lighttpd":
        from webconf_audit.local.normalizers.lighttpd_normalizer import (
            normalize_lighttpd,
        )

        _require_argument("ast", ast, normalized_server_type)
        return normalize_lighttpd(
            ast, effective_config=effective_config,
            merged_directives=merged_directives,
        )

    if normalized_server_type == "iis":
        from webconf_audit.local.normalizers.iis_normalizer import normalize_iis

        _require_argument("doc", doc, normalized_server_type)
        return normalize_iis(doc, effective_config=effective_config)

    # Unknown server type - return empty config.
    return NormalizedConfig(server_type=normalized_server_type)


def _require_argument(name: str, value: Any, server_type: str) -> None:
    if value is None:
        raise ValueError(f"{server_type} normalization requires {name}.")


__all__ = ["normalize_config"]

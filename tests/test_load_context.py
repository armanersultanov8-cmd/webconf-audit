from pathlib import Path

from webconf_audit.local.load_context import LoadContext
from webconf_audit.local.apache import analyze_apache_config
from webconf_audit.local.lighttpd import analyze_lighttpd_config
from webconf_audit.local.nginx import analyze_nginx_config


def test_nginx_analysis_metadata_contains_load_context(tmp_path: Path) -> None:
    root = tmp_path / "nginx.conf"
    include_path = tmp_path / "extra.conf"
    root.write_text("include extra.conf;\nworker_processes 1;\nevents {}\n", encoding="utf-8")
    include_path.write_text("http {}\n", encoding="utf-8")

    result = analyze_nginx_config(str(root))
    load_context = result.metadata["load_context"]

    assert load_context["root_file"] == str(root)
    assert set(load_context["files"]) == {str(root), str(include_path)}
    assert load_context["edges"] == [
        {
            "source_file": str(root),
            "source_line": 1,
            "target_file": str(include_path),
        }
    ]


def test_apache_analysis_metadata_contains_load_context(tmp_path: Path) -> None:
    root = tmp_path / "httpd.conf"
    include_path = tmp_path / "extra.conf"
    root.write_text("Include extra.conf\nServerSignature Off\n", encoding="utf-8")
    include_path.write_text("ServerTokens Prod\n", encoding="utf-8")

    result = analyze_apache_config(str(root))
    load_context = result.metadata["load_context"]

    assert load_context["root_file"] == str(root)
    assert set(load_context["files"]) == {str(root), str(include_path)}
    assert load_context["edges"] == [
        {
            "source_file": str(root),
            "source_line": 1,
            "target_file": str(include_path),
        }
    ]


def test_lighttpd_analysis_metadata_contains_load_context(tmp_path: Path) -> None:
    root = tmp_path / "lighttpd.conf"
    include_path = tmp_path / "extra.conf"
    root.write_text('include "extra.conf"\nserver.document-root = "/var/www"\n', encoding="utf-8")
    include_path.write_text('server.port = 8080\n', encoding="utf-8")

    result = analyze_lighttpd_config(str(root))
    load_context = result.metadata["load_context"]

    assert load_context["root_file"] == str(root)
    assert set(load_context["files"]) == {str(root), str(include_path)}
    assert load_context["edges"] == [
        {
            "source_file": str(root),
            "source_line": 1,
            "target_file": str(include_path),
        }
    ]


def test_nginx_load_context_no_includes(tmp_path: Path) -> None:
    root = tmp_path / "nginx.conf"
    root.write_text("worker_processes 1;\nevents {}\nhttp {}\n", encoding="utf-8")

    result = analyze_nginx_config(str(root))
    load_context = result.metadata["load_context"]

    assert load_context["root_file"] == str(root)
    assert set(load_context["files"]) == {str(root)}
    assert load_context["edges"] == []


def test_nginx_load_context_nested_includes(tmp_path: Path) -> None:
    root = tmp_path / "nginx.conf"
    include_a = tmp_path / "a.conf"
    include_b = tmp_path / "b.conf"
    root.write_text("include a.conf;\nworker_processes 1;\n", encoding="utf-8")
    include_a.write_text("include b.conf;\nevents {}\n", encoding="utf-8")
    include_b.write_text("http {}\n", encoding="utf-8")

    result = analyze_nginx_config(str(root))
    load_context = result.metadata["load_context"]

    assert set(load_context["files"]) == {str(root), str(include_a), str(include_b)}
    assert load_context["edges"] == [
        {"source_file": str(root), "source_line": 1, "target_file": str(include_a)},
        {"source_file": str(include_a), "source_line": 1, "target_file": str(include_b)},
    ]


def test_nginx_load_context_glob_includes(tmp_path: Path) -> None:
    root = tmp_path / "nginx.conf"
    conf_dir = tmp_path / "conf.d"
    conf_dir.mkdir()
    include_a = conf_dir / "a.conf"
    include_b = conf_dir / "b.conf"
    root.write_text("include conf.d/*.conf;\nworker_processes 1;\n", encoding="utf-8")
    include_a.write_text("events {}\n", encoding="utf-8")
    include_b.write_text("http {}\n", encoding="utf-8")

    result = analyze_nginx_config(str(root))
    load_context = result.metadata["load_context"]

    assert set(load_context["files"]) == {str(root), str(include_a), str(include_b)}
    assert load_context["edges"] == [
        {"source_file": str(root), "source_line": 1, "target_file": str(include_a)},
        {"source_file": str(root), "source_line": 1, "target_file": str(include_b)},
    ]


def test_apache_load_context_nested_includes(tmp_path: Path) -> None:
    root = tmp_path / "httpd.conf"
    include_a = tmp_path / "a.conf"
    include_b = tmp_path / "b.conf"
    root.write_text("Include a.conf\nServerSignature Off\n", encoding="utf-8")
    include_a.write_text("Include b.conf\nServerTokens Prod\n", encoding="utf-8")
    include_b.write_text("TraceEnable Off\n", encoding="utf-8")

    result = analyze_apache_config(str(root))
    load_context = result.metadata["load_context"]

    assert set(load_context["files"]) == {str(root), str(include_a), str(include_b)}
    assert load_context["edges"] == [
        {"source_file": str(root), "source_line": 1, "target_file": str(include_a)},
        {"source_file": str(include_a), "source_line": 1, "target_file": str(include_b)},
    ]


def test_lighttpd_load_context_no_includes(tmp_path: Path) -> None:
    root = tmp_path / "lighttpd.conf"
    root.write_text('server.document-root = "/var/www"\nserver.port = 8080\n', encoding="utf-8")

    result = analyze_lighttpd_config(str(root))
    load_context = result.metadata["load_context"]

    assert load_context["root_file"] == str(root)
    assert set(load_context["files"]) == {str(root)}
    assert load_context["edges"] == []


def test_lighttpd_load_context_marks_skipped_include_shell(tmp_path: Path) -> None:
    root = tmp_path / "lighttpd.conf"
    root.write_text('include_shell "generate-config"\nserver.tag = ""\n', encoding="utf-8")

    result = analyze_lighttpd_config(str(root))
    load_context = result.metadata["load_context"]

    assert load_context["root_file"] == str(root)
    assert set(load_context["files"]) == {str(root), "shell:skipped"}
    assert load_context["edges"] == [
        {
            "source_file": str(root),
            "source_line": 1,
            "target_file": "shell:skipped",
        }
    ]


def test_lighttpd_load_context_records_executed_include_shell(
    tmp_path: Path,
    monkeypatch,
) -> None:
    root = tmp_path / "lighttpd.conf"
    root.write_text('include_shell "generate-config"\nserver.tag = ""\n', encoding="utf-8")

    monkeypatch.setattr(
        "webconf_audit.local.lighttpd.include.execute_include_shell",
        lambda command, timeout=5, cwd=None: "server.port = 8080\n",
    )

    result = analyze_lighttpd_config(str(root), execute_shell=True)
    load_context = result.metadata["load_context"]

    assert load_context["root_file"] == str(root)
    assert set(load_context["files"]) == {str(root), "shell:generate-config"}
    assert load_context["edges"] == [
        {
            "source_file": str(root),
            "source_line": 1,
            "target_file": "shell:generate-config",
        }
    ]


def test_load_context_unit_add_edge() -> None:
    ctx = LoadContext(root_file="root.conf")

    ctx.add_edge("root.conf", 3, "extra.conf")

    assert ctx.files == {"root.conf", "extra.conf"}
    assert ctx.to_dict() == {
        "root_file": "root.conf",
        "files": ["extra.conf", "root.conf"],
        "edges": [
            {
                "source_file": "root.conf",
                "source_line": 3,
                "target_file": "extra.conf",
            }
        ],
    }


def test_load_context_unit_post_init_adds_root() -> None:
    ctx = LoadContext(root_file="x")

    assert "x" in ctx.files
    assert ctx.edges == []

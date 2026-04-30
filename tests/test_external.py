import http.client
from datetime import timezone

import pytest

from webconf_audit.external.recon import ErrorPageProbe, MalformedRequestProbe, OptionsObservation, ProbeAttempt, ProbeTarget, SensitivePathProbe, ServerIdentification, ServerIdentificationEvidence, TLSInfo, analyze_external_target
from webconf_audit.external.rules._helpers import _parse_cert_date
from webconf_audit.external.rules import hostname_matches_san, run_external_rules


def _analyze_with_probe_attempts(
    monkeypatch,
    probe_attempts: list[ProbeAttempt],
    target: str = "example.com",
    sensitive_path_probes: list[SensitivePathProbe] | None = None,
    error_page_probes: list[ErrorPageProbe] | None = None,
    malformed_request_probes: list[MalformedRequestProbe] | None = None,
    additional_probe_attempts: list[ProbeAttempt] | None = None,
):
    extra_attempts = additional_probe_attempts or []
    attempts_by_target = {
        attempt.target: attempt
        for attempt in [*probe_attempts, *extra_attempts]
    }

    monkeypatch.setattr(
        "webconf_audit.external.recon._build_probe_targets",
        lambda _external_target: [attempt.target for attempt in probe_attempts],
    )
    monkeypatch.setattr(
        "webconf_audit.external.recon._probe_target",
        lambda probe_target: attempts_by_target[probe_target],
    )
    monkeypatch.setattr(
        "webconf_audit.external.recon._probe_sensitive_paths",
        lambda successful_attempts, identification=None: (
            sensitive_path_probes if sensitive_path_probes is not None else []
        ),
    )
    monkeypatch.setattr(
        "webconf_audit.external.recon._probe_error_pages",
        lambda successful_attempts: error_page_probes if error_page_probes is not None else [],
    )
    monkeypatch.setattr(
        "webconf_audit.external.recon._probe_malformed_requests",
        lambda successful_attempts: malformed_request_probes if malformed_request_probes is not None else [],
    )

    return analyze_external_target(target)


_ALL_SECURITY_HEADERS = {
    "strict_transport_security_header": "max-age=31536000; includeSubDomains",
    "x_frame_options_header": "DENY",
    "x_content_type_options_header": "nosniff",
    "content_security_policy_header": "default-src 'self'",
    "referrer_policy_header": "strict-origin-when-cross-origin",
    "permissions_policy_header": "geolocation=()",
    "cross_origin_embedder_policy_header": "require-corp",
    "cross_origin_opener_policy_header": "same-origin",
    "cross_origin_resource_policy_header": "same-origin",
}


def _server_identification(
    server_type: str | None,
    confidence: str,
    *,
    evidence: tuple[ServerIdentificationEvidence, ...] = (),
) -> ServerIdentification:
    return ServerIdentification(
        server_type=server_type,
        confidence=confidence,
        evidence=evidence,
        candidate_server_types=(server_type,) if server_type is not None else (),
    )


def test_probe_target_url_brackets_ipv6_host() -> None:
    target = ProbeTarget(scheme="http", host="2001:db8::1", port=8080, path="/")
    assert target.url == "http://[2001:db8::1]:8080/"


def test_probe_target_url_ipv4_not_bracketed() -> None:
    target = ProbeTarget(scheme="https", host="192.168.1.1", port=443, path="/")
    assert target.url == "https://192.168.1.1/"


def test_probe_target_url_hostname_not_bracketed() -> None:
    target = ProbeTarget(scheme="https", host="example.com", port=443, path="/")
    assert target.url == "https://example.com/"


def test_analyze_external_target_detects_nginx_server_type(monkeypatch) -> None:
    probe_attempts = [
        ProbeAttempt(
            target=ProbeTarget(scheme="https", host="example.com", port=443, path="/"),
            tcp_open=True,
            status_code=200,
            reason_phrase="OK",
            server_header="nginx",
            **_ALL_SECURITY_HEADERS,
        ),
        ProbeAttempt(
            target=ProbeTarget(scheme="http", host="example.com", port=80, path="/"),
            tcp_open=False,
            error_message="TCP connection failed or timed out.",
        ),
    ]

    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)

    assert result.mode == "external"
    assert result.target == "example.com"
    assert result.server_type == "nginx"
    assert result.findings == []
    assert result.issues == []
    assert "probable_server_type: nginx" in result.diagnostics
    assert result.metadata["probe_attempts"][0]["url"] == "https://example.com/"
    assert result.metadata["probe_attempts"][0]["strict_transport_security_header"] == "max-age=31536000; includeSubDomains"


def test_analyze_external_target_passes_server_identification_into_rules(monkeypatch) -> None:
    captured: dict[str, object] = {}
    probe_attempts = [
        ProbeAttempt(
            target=ProbeTarget(scheme="https", host="example.com", port=443, path="/"),
            tcp_open=True,
            status_code=200,
            reason_phrase="OK",
            server_header="nginx/1.24.0",
            **_ALL_SECURITY_HEADERS,
        ),
    ]
    attempts_by_target = {attempt.target: attempt for attempt in probe_attempts}

    monkeypatch.setattr(
        "webconf_audit.external.recon._build_probe_targets",
        lambda _external_target: [attempt.target for attempt in probe_attempts],
    )
    monkeypatch.setattr(
        "webconf_audit.external.recon._probe_target",
        lambda probe_target: attempts_by_target[probe_target],
    )
    monkeypatch.setattr(
        "webconf_audit.external.recon._probe_sensitive_paths",
        lambda successful_attempts, identification=None: [],
    )
    monkeypatch.setattr(
        "webconf_audit.external.recon._probe_error_pages",
        lambda successful_attempts: [],
    )
    monkeypatch.setattr(
        "webconf_audit.external.recon._probe_malformed_requests",
        lambda successful_attempts: [],
    )

    def fake_run_external_rules(
        attempts: list[ProbeAttempt],
        target: str,
        sensitive_path_probes: list[SensitivePathProbe] | None = None,
        server_identification: ServerIdentification | None = None,
    ):
        captured["attempts"] = attempts
        captured["target"] = target
        captured["sensitive_path_probes"] = sensitive_path_probes
        captured["server_identification"] = server_identification
        return []

    monkeypatch.setattr(
        "webconf_audit.external.recon.run_external_rules",
        fake_run_external_rules,
    )

    result = analyze_external_target("example.com")

    assert result.server_type == "nginx"
    assert captured["target"] == "example.com"
    assert captured["sensitive_path_probes"] == []
    identification = captured["server_identification"]
    assert isinstance(identification, ServerIdentification)
    assert identification.server_type == "nginx"
    assert identification.confidence == "high"


def test_run_external_rules_server_identification_is_noop_for_non_nginx_server() -> None:
    probe_attempts = [
        _https_probe_with_headers(server_header="nginx/1.24.0"),
        _http_redirect_probe(),
    ]
    identification = ServerIdentification(
        server_type="apache",
        confidence="high",
        evidence=(),
        candidate_server_types=("apache",),
    )

    baseline = run_external_rules(probe_attempts, "example.com")
    with_identification = run_external_rules(
        probe_attempts,
        "example.com",
        server_identification=identification,
    )

    assert [f.rule_id for f in with_identification] == [f.rule_id for f in baseline]
    assert [f.location.target for f in with_identification] == [
        f.location.target for f in baseline
    ]


def test_nginx_conditional_version_rule_fires_at_high_confidence() -> None:
    probe_attempts = [
        _https_probe_with_headers(server_header="nginx/1.24.0"),
        _http_redirect_probe(),
    ]
    identification = ServerIdentification(
        server_type="nginx",
        confidence="high",
        evidence=(),
        candidate_server_types=("nginx",),
    )

    findings = run_external_rules(
        probe_attempts,
        "example.com",
        server_identification=identification,
    )

    rule_ids = {f.rule_id for f in findings}
    assert "external.nginx.version_disclosed_in_server_header" in rule_ids
    assert "external.server_version_disclosed" not in rule_ids


def test_nginx_conditional_version_rule_does_not_fire_below_threshold() -> None:
    probe_attempts = [
        _https_probe_with_headers(server_header="nginx/1.24.0"),
        _http_redirect_probe(),
    ]
    identification = ServerIdentification(
        server_type="nginx",
        confidence="low",
        evidence=(),
        candidate_server_types=("nginx",),
    )

    findings = run_external_rules(
        probe_attempts,
        "example.com",
        server_identification=identification,
    )

    rule_ids = {f.rule_id for f in findings}
    assert "external.nginx.version_disclosed_in_server_header" not in rule_ids
    assert "external.server_version_disclosed" in rule_ids


def test_nginx_conditional_version_rule_does_not_fire_for_other_server_type() -> None:
    probe_attempts = [
        _https_probe_with_headers(server_header="nginx/1.24.0"),
        _http_redirect_probe(),
    ]
    identification = ServerIdentification(
        server_type="apache",
        confidence="high",
        evidence=(),
        candidate_server_types=("apache",),
    )

    findings = run_external_rules(
        probe_attempts,
        "example.com",
        server_identification=identification,
    )

    rule_ids = {f.rule_id for f in findings}
    assert "external.nginx.version_disclosed_in_server_header" not in rule_ids
    assert "external.server_version_disclosed" in rule_ids


def test_nginx_default_welcome_page_rule_fires_at_medium_confidence() -> None:
    probe_attempts = [
        _https_probe_with_headers(
            server_header="nginx",
            body_snippet=(
                "<html><title>Welcome to nginx!</title>"
                "<body>Welcome to nginx! If you see this page, the nginx web "
                "server is successfully installed and working.</body></html>"
            ),
        ),
        _http_redirect_probe(),
    ]
    identification = ServerIdentification(
        server_type="nginx",
        confidence="medium",
        evidence=(),
        candidate_server_types=("nginx",),
    )

    findings = run_external_rules(
        probe_attempts,
        "example.com",
        server_identification=identification,
    )

    welcome_findings = [
        f for f in findings if f.rule_id == "external.nginx.default_welcome_page"
    ]
    assert len(welcome_findings) == 1
    assert welcome_findings[0].location.target == "https://example.com/"


def test_nginx_default_welcome_page_rule_does_not_fire_for_custom_page() -> None:
    probe_attempts = [
        _https_probe_with_headers(
            server_header="nginx",
            body_snippet="<html><body>Custom application homepage</body></html>",
        ),
        _http_redirect_probe(),
    ]
    identification = ServerIdentification(
        server_type="nginx",
        confidence="high",
        evidence=(),
        candidate_server_types=("nginx",),
    )

    findings = run_external_rules(
        probe_attempts,
        "example.com",
        server_identification=identification,
    )

    assert "external.nginx.default_welcome_page" not in {f.rule_id for f in findings}


def test_nginx_default_welcome_page_rule_does_not_fire_for_non_root_path() -> None:
    probe_attempts = [
        _https_probe_with_headers(
            target=ProbeTarget(
                scheme="https",
                host="example.com",
                port=443,
                path="/app",
            ),
            server_header="nginx",
            body_snippet=(
                "Welcome to nginx! If you see this page, the nginx web server "
                "is successfully installed and working."
            ),
        ),
        _http_redirect_probe(),
    ]
    identification = ServerIdentification(
        server_type="nginx",
        confidence="high",
        evidence=(),
        candidate_server_types=("nginx",),
    )

    findings = run_external_rules(
        probe_attempts,
        "example.com/app",
        server_identification=identification,
    )

    assert "external.nginx.default_welcome_page" not in {f.rule_id for f in findings}


def test_apache_conditional_version_rule_fires_at_high_confidence() -> None:
    probe_attempts = [
        _https_probe_with_headers(server_header="Apache/2.4.58 (Ubuntu)"),
        _http_redirect_probe(),
    ]
    identification = ServerIdentification(
        server_type="apache",
        confidence="high",
        evidence=(),
        candidate_server_types=("apache",),
    )

    findings = run_external_rules(
        probe_attempts,
        "example.com",
        server_identification=identification,
    )

    rule_ids = {f.rule_id for f in findings}
    assert "external.apache.version_disclosed_in_server_header" in rule_ids
    assert "external.server_version_disclosed" not in rule_ids


def test_apache_conditional_version_rule_does_not_fire_below_threshold() -> None:
    probe_attempts = [
        _https_probe_with_headers(server_header="Apache/2.4.58 (Ubuntu)"),
        _http_redirect_probe(),
    ]
    identification = ServerIdentification(
        server_type="apache",
        confidence="low",
        evidence=(),
        candidate_server_types=("apache",),
    )

    findings = run_external_rules(
        probe_attempts,
        "example.com",
        server_identification=identification,
    )

    rule_ids = {f.rule_id for f in findings}
    assert "external.apache.version_disclosed_in_server_header" not in rule_ids
    assert "external.server_version_disclosed" in rule_ids


def test_apache_mod_status_public_fires_at_medium_confidence() -> None:
    path_probes = [
        SensitivePathProbe(
            url="https://example.com/server-status?auto",
            path="/server-status?auto",
            status_code=200,
            content_type="text/plain",
            body_snippet="Total Accesses: 1",
        )
    ]
    identification = ServerIdentification(
        server_type="apache",
        confidence="medium",
        evidence=(),
        candidate_server_types=("apache",),
    )

    findings = run_external_rules(
        [_https_probe_with_headers(server_header="Apache/2.4.58")],
        "example.com",
        sensitive_path_probes=path_probes,
        server_identification=identification,
    )

    rule_ids = {f.rule_id for f in findings}
    assert "external.apache.mod_status_public" in rule_ids
    assert "external.server_status_exposed" not in rule_ids


def test_apache_mod_status_public_does_not_fire_for_other_server_type() -> None:
    path_probes = [
        SensitivePathProbe(
            url="https://example.com/server-status",
            path="/server-status",
            status_code=200,
            content_type="text/html",
        )
    ]
    identification = ServerIdentification(
        server_type="nginx",
        confidence="high",
        evidence=(),
        candidate_server_types=("nginx",),
    )

    findings = run_external_rules(
        [_https_probe_with_headers(server_header="nginx")],
        "example.com",
        sensitive_path_probes=path_probes,
        server_identification=identification,
    )

    rule_ids = {f.rule_id for f in findings}
    assert "external.apache.mod_status_public" not in rule_ids
    assert "external.server_status_exposed" in rule_ids


def test_apache_etag_inode_disclosure_fires_at_high_confidence() -> None:
    probe_attempts = [
        _https_probe_with_headers(
            server_header="Apache/2.4.58",
            etag_header='"2c-5f5e100-61a1b2c3"',
        ),
        _http_redirect_probe(),
    ]
    identification = ServerIdentification(
        server_type="apache",
        confidence="high",
        evidence=(),
        candidate_server_types=("apache",),
    )

    findings = run_external_rules(
        probe_attempts,
        "example.com",
        server_identification=identification,
    )

    assert "external.apache.etag_inode_disclosure" in {f.rule_id for f in findings}


def test_apache_etag_inode_disclosure_does_not_fire_for_generic_etag() -> None:
    probe_attempts = [
        _https_probe_with_headers(
            server_header="Apache/2.4.58",
            etag_header='"abc123"',
        ),
        _http_redirect_probe(),
    ]
    identification = ServerIdentification(
        server_type="apache",
        confidence="high",
        evidence=(),
        candidate_server_types=("apache",),
    )

    findings = run_external_rules(
        probe_attempts,
        "example.com",
        server_identification=identification,
    )

    assert "external.apache.etag_inode_disclosure" not in {
        f.rule_id for f in findings
    }


def test_iis_aspnet_version_header_rule_fires_at_medium_confidence() -> None:
    probe_attempts = [
        _https_probe_with_headers(x_aspnet_version_header="4.0.30319"),
        _http_redirect_probe(),
    ]
    identification = ServerIdentification(
        server_type="iis",
        confidence="medium",
        evidence=(),
        candidate_server_types=("iis",),
    )

    findings = run_external_rules(
        probe_attempts,
        "example.com",
        server_identification=identification,
    )

    rule_ids = {f.rule_id for f in findings}
    assert "external.iis.aspnet_version_header_present" in rule_ids
    assert "external.x_aspnet_version_header_present" not in rule_ids


def test_iis_aspnet_version_header_rule_does_not_fire_below_threshold() -> None:
    probe_attempts = [
        _https_probe_with_headers(x_aspnet_version_header="4.0.30319"),
        _http_redirect_probe(),
    ]
    identification = ServerIdentification(
        server_type="iis",
        confidence="low",
        evidence=(),
        candidate_server_types=("iis",),
    )

    findings = run_external_rules(
        probe_attempts,
        "example.com",
        server_identification=identification,
    )

    rule_ids = {f.rule_id for f in findings}
    assert "external.iis.aspnet_version_header_present" not in rule_ids
    assert "external.x_aspnet_version_header_present" in rule_ids


def test_iis_aspnet_version_header_rule_does_not_fire_for_other_server_type() -> None:
    probe_attempts = [
        _https_probe_with_headers(x_aspnet_version_header="4.0.30319"),
        _http_redirect_probe(),
    ]
    identification = ServerIdentification(
        server_type="nginx",
        confidence="high",
        evidence=(),
        candidate_server_types=("nginx",),
    )

    findings = run_external_rules(
        probe_attempts,
        "example.com",
        server_identification=identification,
    )

    rule_ids = {f.rule_id for f in findings}
    assert "external.iis.aspnet_version_header_present" not in rule_ids
    assert "external.x_aspnet_version_header_present" in rule_ids


def test_iis_detailed_error_page_rule_fires_for_error_page_evidence() -> None:
    identification = ServerIdentification(
        server_type="iis",
        confidence="high",
        evidence=(
            ServerIdentificationEvidence(
                source_url="https://example.com/_wca_nonexistent_404_probe",
                signal="error_page_body",
                value="<h2>IIS Detailed Error - 404.0 - Not Found</h2>",
                indicates="iis",
                strength="moderate",
                detail="Default error page matches IIS detailed error content.",
            ),
        ),
        candidate_server_types=("iis",),
    )

    findings = run_external_rules(
        [_https_probe_with_headers(server_header="Microsoft-IIS/10.0")],
        "example.com",
        server_identification=identification,
    )

    detailed_findings = [
        f for f in findings if f.rule_id == "external.iis.detailed_error_page"
    ]
    assert len(detailed_findings) == 1
    assert detailed_findings[0].location.target == "https://example.com/_wca_nonexistent_404_probe"


def test_iis_detailed_error_page_rule_fires_for_malformed_evidence() -> None:
    identification = ServerIdentification(
        server_type="iis",
        confidence="medium",
        evidence=(
            ServerIdentificationEvidence(
                source_url="https://example.com/",
                signal="malformed_response_body",
                value="<title>Server Error in '/' Application.</title>",
                indicates="iis",
                strength="moderate",
                detail="Malformed response matches IIS detailed error content.",
            ),
        ),
        candidate_server_types=("iis",),
    )

    findings = run_external_rules(
        [_https_probe_with_headers(server_header="Microsoft-IIS/10.0")],
        "example.com",
        server_identification=identification,
    )

    assert "external.iis.detailed_error_page" in {f.rule_id for f in findings}


def test_iis_detailed_error_page_rule_does_not_fire_for_non_detailed_iis_evidence() -> None:
    identification = ServerIdentification(
        server_type="iis",
        confidence="high",
        evidence=(
            ServerIdentificationEvidence(
                source_url="https://example.com/",
                signal="malformed_response_body",
                value="<h2>Bad Request - Invalid URL</h2>",
                indicates="iis",
                strength="moderate",
                detail="Malformed response body matches a generic IIS signature.",
            ),
        ),
        candidate_server_types=("iis",),
    )

    findings = run_external_rules(
        [_https_probe_with_headers(server_header="Microsoft-IIS/10.0")],
        "example.com",
        server_identification=identification,
    )

    assert "external.iis.detailed_error_page" not in {f.rule_id for f in findings}


def test_lighttpd_version_in_server_header_fires_at_high_confidence() -> None:
    probe_attempts = [
        _https_probe_with_headers(server_header="lighttpd/1.4.71"),
        _http_redirect_probe(),
    ]
    identification = ServerIdentification(
        server_type="lighttpd",
        confidence="high",
        evidence=(),
        candidate_server_types=("lighttpd",),
    )

    findings = run_external_rules(
        probe_attempts,
        "example.com",
        server_identification=identification,
    )

    rule_ids = {f.rule_id for f in findings}
    assert "external.lighttpd.version_in_server_header" in rule_ids
    assert "external.server_version_disclosed" not in rule_ids


def test_lighttpd_version_in_server_header_does_not_fire_below_threshold() -> None:
    probe_attempts = [
        _https_probe_with_headers(server_header="lighttpd/1.4.71"),
        _http_redirect_probe(),
    ]
    identification = ServerIdentification(
        server_type="lighttpd",
        confidence="low",
        evidence=(),
        candidate_server_types=("lighttpd",),
    )

    findings = run_external_rules(
        probe_attempts,
        "example.com",
        server_identification=identification,
    )

    rule_ids = {f.rule_id for f in findings}
    assert "external.lighttpd.version_in_server_header" not in rule_ids
    assert "external.server_version_disclosed" in rule_ids


def test_lighttpd_mod_status_public_fires_at_medium_confidence() -> None:
    path_probes = [
        SensitivePathProbe(
            url="https://example.com/server-status",
            path="/server-status",
            status_code=200,
            content_type="text/plain",
            body_snippet="Total Accesses: 1",
        )
    ]
    identification = ServerIdentification(
        server_type="lighttpd",
        confidence="medium",
        evidence=(),
        candidate_server_types=("lighttpd",),
    )

    findings = run_external_rules(
        [_https_probe_with_headers(server_header="lighttpd/1.4.71")],
        "example.com",
        sensitive_path_probes=path_probes,
        server_identification=identification,
    )

    rule_ids = {f.rule_id for f in findings}
    assert "external.lighttpd.mod_status_public" in rule_ids
    assert "external.server_status_exposed" not in rule_ids


def test_lighttpd_mod_status_public_does_not_fire_for_other_server_type() -> None:
    path_probes = [
        SensitivePathProbe(
            url="https://example.com/server-status",
            path="/server-status",
            status_code=200,
            content_type="text/plain",
            body_snippet="Total Accesses: 1",
        )
    ]
    identification = ServerIdentification(
        server_type="nginx",
        confidence="high",
        evidence=(),
        candidate_server_types=("nginx",),
    )

    findings = run_external_rules(
        [_https_probe_with_headers(server_header="nginx")],
        "example.com",
        sensitive_path_probes=path_probes,
        server_identification=identification,
    )

    rule_ids = {f.rule_id for f in findings}
    assert "external.lighttpd.mod_status_public" not in rule_ids
    assert "external.server_status_exposed" in rule_ids


@pytest.mark.parametrize(
    ("confidence", "should_fire"),
    [
        ("medium", True),
        ("high", True),
        ("low", False),
        ("none", False),
    ],
)
def test_nginx_default_welcome_page_rule_threshold_behavior(
    confidence: str,
    should_fire: bool,
) -> None:
    probe_attempts = [
        _https_probe_with_headers(
            server_header="nginx",
            body_snippet=(
                "<html><title>Welcome to nginx!</title>"
                "<body>Welcome to nginx! If you see this page, the nginx web "
                "server is successfully installed and working.</body></html>"
            ),
        ),
        _http_redirect_probe(),
    ]
    identification = _server_identification(
        "nginx" if confidence != "none" else None,
        confidence,
    )

    findings = run_external_rules(
        probe_attempts,
        "example.com",
        server_identification=identification,
    )

    assert ("external.nginx.default_welcome_page" in {f.rule_id for f in findings}) is should_fire


@pytest.mark.parametrize(
    ("confidence", "should_fire"),
    [
        ("medium", True),
        ("high", True),
        ("low", False),
        ("none", False),
    ],
)
def test_apache_mod_status_public_threshold_behavior(
    confidence: str,
    should_fire: bool,
) -> None:
    path_probes = [
        SensitivePathProbe(
            url="https://example.com/server-status?auto",
            path="/server-status?auto",
            status_code=200,
            content_type="text/plain",
            body_snippet="Total Accesses: 1",
        )
    ]
    identification = _server_identification(
        "apache" if confidence != "none" else None,
        confidence,
    )

    findings = run_external_rules(
        [_https_probe_with_headers(server_header="Apache/2.4.58")],
        "example.com",
        sensitive_path_probes=path_probes,
        server_identification=identification,
    )

    rule_ids = {f.rule_id for f in findings}
    assert ("external.apache.mod_status_public" in rule_ids) is should_fire
    assert ("external.server_status_exposed" in rule_ids) is (not should_fire)


@pytest.mark.parametrize(
    ("confidence", "should_fire"),
    [
        ("medium", True),
        ("high", True),
        ("low", False),
        ("none", False),
    ],
)
def test_iis_detailed_error_page_rule_threshold_behavior(
    confidence: str,
    should_fire: bool,
) -> None:
    identification = _server_identification(
        "iis" if confidence != "none" else None,
        confidence,
        evidence=(
            ServerIdentificationEvidence(
                source_url="https://example.com/",
                signal="malformed_response_body",
                value="<title>Server Error in '/' Application.</title>",
                indicates="iis",
                strength="moderate",
                detail="Malformed response matches IIS detailed error content.",
            ),
        ),
    )

    findings = run_external_rules(
        [_https_probe_with_headers(server_header="Microsoft-IIS/10.0")],
        "example.com",
        server_identification=identification,
    )

    assert ("external.iis.detailed_error_page" in {f.rule_id for f in findings}) is should_fire


def test_iis_detailed_error_page_rule_does_not_fire_for_other_server_type() -> None:
    identification = _server_identification(
        "apache",
        "high",
        evidence=(
            ServerIdentificationEvidence(
                source_url="https://example.com/",
                signal="malformed_response_body",
                value="<title>Server Error in '/' Application.</title>",
                indicates="iis",
                strength="moderate",
                detail="Malformed response matches IIS detailed error content.",
            ),
        ),
    )

    findings = run_external_rules(
        [_https_probe_with_headers(server_header="Apache/2.4.58")],
        "example.com",
        server_identification=identification,
    )

    assert "external.iis.detailed_error_page" not in {f.rule_id for f in findings}


@pytest.mark.parametrize(
    ("confidence", "should_fire"),
    [
        ("medium", True),
        ("high", True),
        ("low", False),
        ("none", False),
    ],
)
def test_lighttpd_mod_status_public_threshold_behavior(
    confidence: str,
    should_fire: bool,
) -> None:
    path_probes = [
        SensitivePathProbe(
            url="https://example.com/server-status",
            path="/server-status",
            status_code=200,
            content_type="text/plain",
            body_snippet="Total Accesses: 1",
        )
    ]
    identification = _server_identification(
        "lighttpd" if confidence != "none" else None,
        confidence,
    )

    findings = run_external_rules(
        [_https_probe_with_headers(server_header="lighttpd/1.4.71")],
        "example.com",
        sensitive_path_probes=path_probes,
        server_identification=identification,
    )

    rule_ids = {f.rule_id for f in findings}
    assert ("external.lighttpd.mod_status_public" in rule_ids) is should_fire
    assert ("external.server_status_exposed" in rule_ids) is (not should_fire)


def test_analyze_external_target_returns_issue_when_no_service_is_reachable(monkeypatch) -> None:
    probe_attempts = [
        ProbeAttempt(
            target=ProbeTarget(scheme="https", host="example.com", port=443, path="/"),
            tcp_open=False,
            error_message="TCP connection failed or timed out.",
        ),
        ProbeAttempt(
            target=ProbeTarget(scheme="http", host="example.com", port=80, path="/"),
            tcp_open=False,
            error_message="TCP connection failed or timed out.",
        ),
    ]

    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)

    assert result.mode == "external"
    assert result.server_type is None
    assert result.findings == []
    assert len(result.issues) == 1
    assert result.issues[0].code == "external_no_http_service"
    assert result.issues[0].location is not None
    assert result.issues[0].location.kind == "endpoint"


def test_analyze_external_target_returns_warning_when_server_type_is_unknown(monkeypatch) -> None:
    probe_attempts = [
        ProbeAttempt(
            target=ProbeTarget(scheme="https", host="example.com", port=443, path="/"),
            tcp_open=True,
            status_code=200,
            reason_phrase="OK",
            server_header="custom-edge",
            **_ALL_SECURITY_HEADERS,
        )
    ]

    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)

    assert result.mode == "external"
    assert result.server_type is None
    assert result.findings == []
    assert len(result.issues) == 1
    assert result.issues[0].code == "external_server_type_unknown"


def test_analyze_external_target_adds_https_not_available_finding_when_https_has_no_response(
    monkeypatch,
) -> None:
    probe_attempts = [
        ProbeAttempt(
            target=ProbeTarget(scheme="https", host="example.com", port=443, path="/"),
            tcp_open=False,
            error_message="TCP connection failed or timed out.",
        ),
        ProbeAttempt(
            target=ProbeTarget(scheme="http", host="example.com", port=80, path="/"),
            tcp_open=True,
            status_code=301,
            reason_phrase="Moved Permanently",
            server_header="apache/2.4.58",
            location_header="https://example.com/",
        ),
    ]

    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)

    assert "external.https_not_available" in {finding.rule_id for finding in result.findings}


def test_analyze_external_target_adds_http_not_redirected_to_https_finding_when_http_returns_200(
    monkeypatch,
) -> None:
    probe_attempts = [
        ProbeAttempt(
            target=ProbeTarget(scheme="https", host="example.com", port=443, path="/"),
            tcp_open=True,
            status_code=200,
            reason_phrase="OK",
            server_header="nginx/1.24.0",
            strict_transport_security_header="max-age=31536000",
        ),
        ProbeAttempt(
            target=ProbeTarget(scheme="http", host="example.com", port=80, path="/"),
            tcp_open=True,
            status_code=200,
            reason_phrase="OK",
            server_header="nginx/1.24.0",
        ),
    ]

    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)

    assert "external.http_not_redirected_to_https" in {finding.rule_id for finding in result.findings}


def test_analyze_external_target_does_not_add_http_redirect_finding_for_https_redirect(
    monkeypatch,
) -> None:
    probe_attempts = [
        ProbeAttempt(
            target=ProbeTarget(scheme="https", host="example.com", port=443, path="/"),
            tcp_open=True,
            status_code=200,
            reason_phrase="OK",
            server_header="apache/2.4.58",
            strict_transport_security_header="max-age=31536000",
        ),
        ProbeAttempt(
            target=ProbeTarget(scheme="http", host="example.com", port=80, path="/"),
            tcp_open=True,
            status_code=301,
            reason_phrase="Moved Permanently",
            server_header="apache/2.4.58",
            location_header="https://example.com/",
        ),
    ]

    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)

    assert "external.http_not_redirected_to_https" not in {
        finding.rule_id for finding in result.findings
    }


def test_analyze_external_target_adds_hsts_missing_finding_for_https_without_header(
    monkeypatch,
) -> None:
    probe_attempts = [
        ProbeAttempt(
            target=ProbeTarget(scheme="https", host="example.com", port=443, path="/"),
            tcp_open=True,
            status_code=200,
            reason_phrase="OK",
            server_header="nginx/1.24.0",
        ),
        ProbeAttempt(
            target=ProbeTarget(scheme="http", host="example.com", port=80, path="/"),
            tcp_open=True,
            status_code=301,
            reason_phrase="Moved Permanently",
            server_header="nginx/1.24.0",
            location_header="https://example.com/",
        ),
    ]

    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)

    assert "external.hsts_header_missing" in {finding.rule_id for finding in result.findings}


def test_analyze_external_target_does_not_add_hsts_missing_finding_when_header_exists(
    monkeypatch,
) -> None:
    probe_attempts = [
        ProbeAttempt(
            target=ProbeTarget(scheme="https", host="example.com", port=443, path="/"),
            tcp_open=True,
            status_code=200,
            reason_phrase="OK",
            server_header="nginx/1.24.0",
            strict_transport_security_header="max-age=31536000",
        ),
        ProbeAttempt(
            target=ProbeTarget(scheme="http", host="example.com", port=80, path="/"),
            tcp_open=True,
            status_code=301,
            reason_phrase="Moved Permanently",
            server_header="nginx/1.24.0",
            location_header="https://example.com/",
        ),
    ]

    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)

    assert "external.hsts_header_missing" not in {finding.rule_id for finding in result.findings}


def test_analyze_external_target_returns_findings_in_analysis_result(monkeypatch) -> None:
    probe_attempts = [
        ProbeAttempt(
            target=ProbeTarget(scheme="https", host="example.com", port=443, path="/"),
            tcp_open=False,
            error_message="TCP connection failed or timed out.",
        ),
        ProbeAttempt(
            target=ProbeTarget(scheme="http", host="example.com", port=80, path="/"),
            tcp_open=True,
            status_code=200,
            reason_phrase="OK",
            server_header="apache/2.4.58",
        ),
    ]

    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)

    rule_ids = {finding.rule_id for finding in result.findings}
    assert "external.https_not_available" in rule_ids
    assert "external.http_not_redirected_to_https" in rule_ids
    assert "external.apache.version_disclosed_in_server_header" in rule_ids
    assert "external.server_version_disclosed" not in rule_ids
    assert all(finding.kind == "finding" for finding in result.findings)


def _https_probe_with_headers(**overrides) -> ProbeAttempt:
    defaults = {
        "target": ProbeTarget(scheme="https", host="example.com", port=443, path="/"),
        "tcp_open": True,
        "status_code": 200,
        "reason_phrase": "OK",
        "server_header": "nginx",
        **_ALL_SECURITY_HEADERS,
    }
    defaults.update(overrides)
    return ProbeAttempt(**defaults)


def _http_redirect_probe(
    *,
    target: ProbeTarget | None = None,
    status_code: int = 301,
    reason_phrase: str = "Moved Permanently",
    server_header: str = "nginx",
    location_header: str = "https://example.com/",
) -> ProbeAttempt:
    return ProbeAttempt(
        target=target or ProbeTarget(scheme="http", host="example.com", port=80, path="/"),
        tcp_open=True,
        status_code=status_code,
        reason_phrase=reason_phrase,
        server_header=server_header,
        location_header=location_header,
    )


def _sensitive_path_probe(
    path: str,
    *,
    status_code: int = 200,
    content_type: str | None = "text/html",
    body_snippet: str | None = None,
) -> SensitivePathProbe:
    return SensitivePathProbe(
        url=f"https://example.com{path}",
        path=path,
        status_code=status_code,
        content_type=content_type,
        body_snippet=body_snippet,
    )


def test_redirect_chain_metadata_and_diagnostics_present(monkeypatch) -> None:
    initial_attempts = [
        _https_probe_with_headers(),
        _http_redirect_probe(location_header="https://example.com/start"),
    ]
    additional_attempts = [
        _https_probe_with_headers(
            target=ProbeTarget(scheme="https", host="example.com", port=443, path="/start"),
            status_code=302,
            reason_phrase="Found",
            location_header="https://example.com/login",
        ),
        _https_probe_with_headers(
            target=ProbeTarget(scheme="https", host="example.com", port=443, path="/login"),
        ),
    ]

    result = _analyze_with_probe_attempts(
        monkeypatch,
        initial_attempts,
        additional_probe_attempts=additional_attempts,
    )

    chains = result.metadata["redirect_chains"]
    assert len(chains) == 1
    chain = chains[0]
    assert chain["source_url"] == "http://example.com/"
    assert chain["final_url"] == "https://example.com/login"
    assert [hop["url"] for hop in chain["hops"]] == [
        "http://example.com/",
        "https://example.com/start",
        "https://example.com/login",
    ]
    assert chain["loop_detected"] is False
    assert chain["mixed_scheme_redirect"] is False
    assert chain["cross_domain_redirect"] is False
    assert any(
        "redirect_chain: http://example.com/ -> https://example.com/start -> https://example.com/login"
        in diagnostic
        for diagnostic in result.diagnostics
    )


def test_redirect_chain_detects_mixed_scheme(monkeypatch) -> None:
    initial_attempts = [
        _https_probe_with_headers(),
        _http_redirect_probe(location_header="https://example.com/start"),
    ]
    additional_attempts = [
        _https_probe_with_headers(
            target=ProbeTarget(scheme="https", host="example.com", port=443, path="/start"),
            status_code=302,
            reason_phrase="Found",
            location_header="http://example.com/final",
        ),
        ProbeAttempt(
            target=ProbeTarget(scheme="http", host="example.com", port=80, path="/final"),
            tcp_open=True,
            status_code=200,
            reason_phrase="OK",
            server_header="nginx",
        ),
    ]

    result = _analyze_with_probe_attempts(
        monkeypatch,
        initial_attempts,
        additional_probe_attempts=additional_attempts,
    )

    chain = result.metadata["redirect_chains"][0]
    assert chain["mixed_scheme_redirect"] is True
    assert chain["cross_domain_redirect"] is False
    assert any("redirect_chain_mixed_scheme:" in diagnostic for diagnostic in result.diagnostics)


def test_redirect_chain_detects_cross_domain_redirect(monkeypatch) -> None:
    initial_attempts = [
        _https_probe_with_headers(),
        _http_redirect_probe(location_header="https://login.example.net/"),
    ]
    additional_attempts = [
        _https_probe_with_headers(
            target=ProbeTarget(scheme="https", host="login.example.net", port=443, path="/"),
            server_header="nginx",
        ),
    ]

    result = _analyze_with_probe_attempts(
        monkeypatch,
        initial_attempts,
        additional_probe_attempts=additional_attempts,
    )

    chain = result.metadata["redirect_chains"][0]
    assert chain["cross_domain_redirect"] is True
    assert chain["final_url"] == "https://login.example.net/"
    assert any("redirect_chain_cross_domain:" in diagnostic for diagnostic in result.diagnostics)


def test_redirect_chain_detects_loop(monkeypatch) -> None:
    initial_attempts = [
        _https_probe_with_headers(),
        _http_redirect_probe(location_header="https://example.com/start"),
    ]
    additional_attempts = [
        _https_probe_with_headers(
            target=ProbeTarget(scheme="https", host="example.com", port=443, path="/start"),
            status_code=302,
            reason_phrase="Found",
            location_header="http://example.com/",
        ),
    ]

    result = _analyze_with_probe_attempts(
        monkeypatch,
        initial_attempts,
        additional_probe_attempts=additional_attempts,
    )

    chain = result.metadata["redirect_chains"][0]
    assert chain["loop_detected"] is True
    assert chain["final_url"] == "http://example.com/"
    assert any("redirect_chain_loop:" in diagnostic for diagnostic in result.diagnostics)


def test_x_frame_options_missing_fires_when_header_absent(monkeypatch) -> None:
    probe_attempts = [
        _https_probe_with_headers(x_frame_options_header=None),
        _http_redirect_probe(),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    assert "external.x_frame_options_missing" in {f.rule_id for f in result.findings}


def test_x_frame_options_missing_does_not_fire_when_header_present(monkeypatch) -> None:
    probe_attempts = [_https_probe_with_headers(), _http_redirect_probe()]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    assert "external.x_frame_options_missing" not in {f.rule_id for f in result.findings}


def test_x_content_type_options_missing_fires_when_header_absent(monkeypatch) -> None:
    probe_attempts = [
        _https_probe_with_headers(x_content_type_options_header=None),
        _http_redirect_probe(),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    assert "external.x_content_type_options_missing" in {f.rule_id for f in result.findings}


def test_x_content_type_options_missing_does_not_fire_when_header_present(monkeypatch) -> None:
    probe_attempts = [_https_probe_with_headers(), _http_redirect_probe()]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    assert "external.x_content_type_options_missing" not in {f.rule_id for f in result.findings}


def test_content_security_policy_missing_fires_when_header_absent(monkeypatch) -> None:
    probe_attempts = [
        _https_probe_with_headers(content_security_policy_header=None),
        _http_redirect_probe(),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    assert "external.content_security_policy_missing" in {f.rule_id for f in result.findings}


def test_content_security_policy_missing_does_not_fire_when_header_present(monkeypatch) -> None:
    probe_attempts = [_https_probe_with_headers(), _http_redirect_probe()]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    assert "external.content_security_policy_missing" not in {f.rule_id for f in result.findings}


def test_referrer_policy_missing_fires_when_header_absent(monkeypatch) -> None:
    probe_attempts = [
        _https_probe_with_headers(referrer_policy_header=None),
        _http_redirect_probe(),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    assert "external.referrer_policy_missing" in {f.rule_id for f in result.findings}


def test_referrer_policy_missing_does_not_fire_when_header_present(monkeypatch) -> None:
    probe_attempts = [_https_probe_with_headers(), _http_redirect_probe()]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    assert "external.referrer_policy_missing" not in {f.rule_id for f in result.findings}


def test_permissions_policy_missing_fires_when_header_absent(monkeypatch) -> None:
    probe_attempts = [
        _https_probe_with_headers(permissions_policy_header=None),
        _http_redirect_probe(),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    assert "external.permissions_policy_missing" in {f.rule_id for f in result.findings}


def test_permissions_policy_missing_does_not_fire_when_header_present(monkeypatch) -> None:
    probe_attempts = [_https_probe_with_headers(), _http_redirect_probe()]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    assert "external.permissions_policy_missing" not in {f.rule_id for f in result.findings}


def test_coep_missing_fires_when_header_absent(monkeypatch) -> None:
    probe_attempts = [
        _https_probe_with_headers(cross_origin_embedder_policy_header=None),
        _http_redirect_probe(),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    assert "external.coep_missing" in {f.rule_id for f in result.findings}


def test_coep_missing_does_not_fire_when_header_present(monkeypatch) -> None:
    probe_attempts = [_https_probe_with_headers(), _http_redirect_probe()]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    assert "external.coep_missing" not in {f.rule_id for f in result.findings}


def test_coop_missing_fires_when_header_absent(monkeypatch) -> None:
    probe_attempts = [
        _https_probe_with_headers(cross_origin_opener_policy_header=None),
        _http_redirect_probe(),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    assert "external.coop_missing" in {f.rule_id for f in result.findings}


def test_coop_missing_does_not_fire_when_header_present(monkeypatch) -> None:
    probe_attempts = [_https_probe_with_headers(), _http_redirect_probe()]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    assert "external.coop_missing" not in {f.rule_id for f in result.findings}


def test_corp_missing_fires_when_header_absent(monkeypatch) -> None:
    probe_attempts = [
        _https_probe_with_headers(cross_origin_resource_policy_header=None),
        _http_redirect_probe(),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    assert "external.corp_missing" in {f.rule_id for f in result.findings}


def test_corp_missing_does_not_fire_when_header_present(monkeypatch) -> None:
    probe_attempts = [_https_probe_with_headers(), _http_redirect_probe()]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    assert "external.corp_missing" not in {f.rule_id for f in result.findings}


def test_server_version_disclosed_fires_when_version_in_header(monkeypatch) -> None:
    probe_attempts = [
        _https_probe_with_headers(server_header="Apache/2.4.58 (Ubuntu)"),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    version_findings = [
        f for f in result.findings
        if f.rule_id == "external.apache.version_disclosed_in_server_header"
    ]
    assert len(version_findings) >= 1
    assert "Apache/2.4.58 (Ubuntu)" in version_findings[0].description


def test_server_version_disclosed_does_not_fire_for_minimal_header(monkeypatch) -> None:
    probe_attempts = [_https_probe_with_headers(server_header="nginx"), _http_redirect_probe()]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    assert "external.server_version_disclosed" not in {f.rule_id for f in result.findings}


def test_server_version_disclosed_does_not_fire_when_no_server_header(monkeypatch) -> None:
    probe_attempts = [
        _https_probe_with_headers(server_header=None),
        _http_redirect_probe(),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    assert "external.server_version_disclosed" not in {f.rule_id for f in result.findings}


# --- HSTS header invalid ---


def test_hsts_invalid_does_not_fire_for_valid_max_age(monkeypatch) -> None:
    probe_attempts = [
        _https_probe_with_headers(strict_transport_security_header="max-age=31536000"),
        _http_redirect_probe(),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    assert "external.hsts_header_invalid" not in {f.rule_id for f in result.findings}


def test_hsts_invalid_fires_when_max_age_missing(monkeypatch) -> None:
    probe_attempts = [
        _https_probe_with_headers(strict_transport_security_header="includeSubDomains"),
        _http_redirect_probe(),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    assert "external.hsts_header_invalid" in {f.rule_id for f in result.findings}


def test_hsts_invalid_fires_when_max_age_not_a_number(monkeypatch) -> None:
    probe_attempts = [
        _https_probe_with_headers(strict_transport_security_header="max-age=abc"),
        _http_redirect_probe(),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    assert "external.hsts_header_invalid" in {f.rule_id for f in result.findings}


def test_hsts_invalid_fires_when_max_age_is_zero(monkeypatch) -> None:
    probe_attempts = [
        _https_probe_with_headers(strict_transport_security_header="max-age=0"),
        _http_redirect_probe(),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    assert "external.hsts_header_invalid" in {f.rule_id for f in result.findings}


def test_hsts_invalid_does_not_fire_when_header_absent(monkeypatch) -> None:
    probe_attempts = [
        _https_probe_with_headers(strict_transport_security_header=None),
        _http_redirect_probe(),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    assert "external.hsts_header_invalid" not in {f.rule_id for f in result.findings}


# --- X-Frame-Options invalid ---


def test_x_frame_options_invalid_does_not_fire_for_deny(monkeypatch) -> None:
    probe_attempts = [
        _https_probe_with_headers(x_frame_options_header="DENY"),
        _http_redirect_probe(),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    assert "external.x_frame_options_invalid" not in {f.rule_id for f in result.findings}


def test_x_frame_options_invalid_does_not_fire_for_sameorigin(monkeypatch) -> None:
    probe_attempts = [
        _https_probe_with_headers(x_frame_options_header="SAMEORIGIN"),
        _http_redirect_probe(),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    assert "external.x_frame_options_invalid" not in {f.rule_id for f in result.findings}


def test_x_frame_options_invalid_fires_for_allowall(monkeypatch) -> None:
    probe_attempts = [
        _https_probe_with_headers(x_frame_options_header="ALLOWALL"),
        _http_redirect_probe(),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    assert "external.x_frame_options_invalid" in {f.rule_id for f in result.findings}


def test_x_frame_options_invalid_does_not_fire_when_header_absent(monkeypatch) -> None:
    probe_attempts = [
        _https_probe_with_headers(x_frame_options_header=None),
        _http_redirect_probe(),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    assert "external.x_frame_options_invalid" not in {f.rule_id for f in result.findings}


# --- X-Content-Type-Options invalid ---


def test_x_content_type_options_invalid_does_not_fire_for_nosniff(monkeypatch) -> None:
    probe_attempts = [
        _https_probe_with_headers(x_content_type_options_header="nosniff"),
        _http_redirect_probe(),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    assert "external.x_content_type_options_invalid" not in {f.rule_id for f in result.findings}


def test_x_content_type_options_invalid_fires_for_bad_value(monkeypatch) -> None:
    probe_attempts = [
        _https_probe_with_headers(x_content_type_options_header="sniff"),
        _http_redirect_probe(),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    assert "external.x_content_type_options_invalid" in {f.rule_id for f in result.findings}


def test_x_content_type_options_invalid_does_not_fire_when_header_absent(monkeypatch) -> None:
    probe_attempts = [
        _https_probe_with_headers(x_content_type_options_header=None),
        _http_redirect_probe(),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    assert "external.x_content_type_options_invalid" not in {f.rule_id for f in result.findings}


# --- Referrer-Policy unsafe ---


def test_referrer_policy_unsafe_fires_for_unsafe_url(monkeypatch) -> None:
    probe_attempts = [
        _https_probe_with_headers(referrer_policy_header="unsafe-url"),
        _http_redirect_probe(),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    assert "external.referrer_policy_unsafe" in {f.rule_id for f in result.findings}


def test_referrer_policy_unsafe_does_not_fire_for_strict_origin(monkeypatch) -> None:
    probe_attempts = [
        _https_probe_with_headers(referrer_policy_header="strict-origin-when-cross-origin"),
        _http_redirect_probe(),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    assert "external.referrer_policy_unsafe" not in {f.rule_id for f in result.findings}


def test_referrer_policy_unsafe_does_not_fire_for_no_referrer(monkeypatch) -> None:
    probe_attempts = [
        _https_probe_with_headers(referrer_policy_header="no-referrer"),
        _http_redirect_probe(),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    assert "external.referrer_policy_unsafe" not in {f.rule_id for f in result.findings}


def test_referrer_policy_unsafe_does_not_fire_when_header_absent(monkeypatch) -> None:
    probe_attempts = [
        _https_probe_with_headers(referrer_policy_header=None),
        _http_redirect_probe(),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    assert "external.referrer_policy_unsafe" not in {f.rule_id for f in result.findings}


# --- Mutual exclusivity: missing vs invalid never both fire ---


def test_hsts_missing_and_invalid_are_mutually_exclusive(monkeypatch) -> None:
    """When HSTS is present but invalid, only invalid fires, not missing."""
    probe_attempts = [
        _https_probe_with_headers(strict_transport_security_header="includeSubDomains"),
        _http_redirect_probe(),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    rule_ids = {f.rule_id for f in result.findings}
    assert "external.hsts_header_invalid" in rule_ids
    assert "external.hsts_header_missing" not in rule_ids


def test_x_frame_options_missing_and_invalid_are_mutually_exclusive(monkeypatch) -> None:
    """When X-Frame-Options is present but invalid, only invalid fires, not missing."""
    probe_attempts = [
        _https_probe_with_headers(x_frame_options_header="ALLOWALL"),
        _http_redirect_probe(),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    rule_ids = {f.rule_id for f in result.findings}
    assert "external.x_frame_options_invalid" in rule_ids
    assert "external.x_frame_options_missing" not in rule_ids


# --- HEAD + GET fallback ---


def _setup_head_fallback_probe(monkeypatch, head_status, head_error=None):
    """Set up monkeypatches where HEAD returns the given status/error and GET returns 200."""
    target = ProbeTarget(scheme="https", host="example.com", port=443, path="/")
    methods_called = []

    def fake_try(probe_target, method):
        methods_called.append(method)
        if method == "HEAD":
            if head_error:
                return ProbeAttempt(
                    target=probe_target,
                    tcp_open=True,
                    error_message=head_error,
                )
            return ProbeAttempt(
                target=probe_target,
                tcp_open=True,
                effective_method="HEAD",
                status_code=head_status,
                reason_phrase="Method Not Allowed" if head_status == 405 else "Not Implemented",
                server_header="nginx",
            )
        return ProbeAttempt(
            target=probe_target,
            tcp_open=True,
            effective_method="GET",
            status_code=200,
            reason_phrase="OK",
            server_header="nginx",
            content_type_header="text/html",
            **_ALL_SECURITY_HEADERS,
        )

    monkeypatch.setattr("webconf_audit.external.recon._is_tcp_port_open", lambda h, p: True)
    monkeypatch.setattr("webconf_audit.external.recon._try_http_method", fake_try)

    return target, methods_called


def test_get_fallback_on_head_405(monkeypatch) -> None:
    from webconf_audit.external.recon import _probe_target

    target, _ = _setup_head_fallback_probe(monkeypatch, head_status=405)
    result = _probe_target(target)

    assert result.has_http_response
    assert result.effective_method == "GET"
    assert result.status_code == 200


def test_get_fallback_on_head_501(monkeypatch) -> None:
    from webconf_audit.external.recon import _probe_target

    target, _ = _setup_head_fallback_probe(monkeypatch, head_status=501)
    result = _probe_target(target)

    assert result.effective_method == "GET"
    assert result.status_code == 200


def test_successful_head_does_not_trigger_get_fallback(monkeypatch) -> None:
    from webconf_audit.external.recon import _probe_target

    target = ProbeTarget(scheme="https", host="example.com", port=443, path="/")
    methods_called = []

    def fake_try(probe_target, method):
        methods_called.append(method)
        return ProbeAttempt(
            target=probe_target,
            tcp_open=True,
            effective_method="HEAD",
            status_code=200,
            reason_phrase="OK",
            server_header="nginx",
            **_ALL_SECURITY_HEADERS,
        )

    monkeypatch.setattr("webconf_audit.external.recon._is_tcp_port_open", lambda h, p: True)
    monkeypatch.setattr("webconf_audit.external.recon._try_http_method", fake_try)

    result = _probe_target(target)
    assert result.effective_method == "HEAD"
    assert methods_called == ["HEAD"]


def test_get_fallback_when_head_fails_after_tcp_open(monkeypatch) -> None:
    from webconf_audit.external.recon import _probe_target

    target, _ = _setup_head_fallback_probe(
        monkeypatch, head_status=None, head_error="Connection reset by peer"
    )
    result = _probe_target(target)

    assert result.effective_method == "GET"
    assert result.status_code == 200


def test_effective_method_in_metadata(monkeypatch) -> None:
    probe_attempts = [
        _https_probe_with_headers(effective_method="GET"),
        _http_redirect_probe(),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    assert result.metadata["probe_attempts"][0]["effective_method"] == "GET"
    assert not any(diagnostic.startswith("effective_method:") for diagnostic in result.diagnostics)


# --- Additional collected headers ---


def test_content_type_header_captured(monkeypatch) -> None:
    probe_attempts = [
        _https_probe_with_headers(content_type_header="text/html; charset=utf-8"),
        _http_redirect_probe(),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    assert result.metadata["probe_attempts"][0]["content_type_header"] == "text/html; charset=utf-8"


def test_x_powered_by_header_captured(monkeypatch) -> None:
    probe_attempts = [
        _https_probe_with_headers(x_powered_by_header="PHP/8.2.0"),
        _http_redirect_probe(),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    assert result.metadata["probe_attempts"][0]["x_powered_by_header"] == "PHP/8.2.0"


def test_x_aspnet_version_header_captured(monkeypatch) -> None:
    probe_attempts = [
        _https_probe_with_headers(x_aspnet_version_header="4.0.30319"),
        _http_redirect_probe(),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    assert result.metadata["probe_attempts"][0]["x_aspnet_version_header"] == "4.0.30319"


def test_additional_response_headers_captured(monkeypatch) -> None:
    probe_attempts = [
        _https_probe_with_headers(
            cache_control_header="no-store",
            x_dns_prefetch_control_header="off",
            cross_origin_embedder_policy_header="require-corp",
            cross_origin_opener_policy_header="same-origin",
            cross_origin_resource_policy_header="same-origin",
        ),
        _http_redirect_probe(),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)

    metadata = result.metadata["probe_attempts"][0]
    assert metadata["cache_control_header"] == "no-store"
    assert metadata["x_dns_prefetch_control_header"] == "off"
    assert metadata["cross_origin_embedder_policy_header"] == "require-corp"
    assert metadata["cross_origin_opener_policy_header"] == "same-origin"
    assert metadata["cross_origin_resource_policy_header"] == "same-origin"


def test_try_http_method_collects_additional_response_headers(monkeypatch) -> None:
    from webconf_audit.external.recon import _try_http_method

    class DummyMessage:
        def get_all(self, _name: str) -> list[str]:
            return []

    class DummyResponse:
        status = 200
        reason = "OK"
        msg = DummyMessage()

        def __init__(self) -> None:
            self.headers = {
                "Cache-Control": "no-store",
                "X-DNS-Prefetch-Control": "off",
                "Cross-Origin-Embedder-Policy": "require-corp",
                "Cross-Origin-Opener-Policy": "same-origin",
                "Cross-Origin-Resource-Policy": "same-origin",
            }

        def getheader(self, name: str) -> str | None:
            return self.headers.get(name)

        def read(self, *_args) -> bytes:
            return b""

    class DummyConnection:
        def __init__(self) -> None:
            self.sock = None

        def request(self, _method: str, _path: str) -> None:
            return None

        def getresponse(self) -> DummyResponse:
            return DummyResponse()

        def close(self) -> None:
            return None

    monkeypatch.setattr(
        "webconf_audit.external.recon._build_connection",
        lambda _probe_target: DummyConnection(),
    )

    attempt = _try_http_method(
        ProbeTarget(scheme="http", host="example.com", port=80, path="/"),
        "HEAD",
    )

    assert attempt.cache_control_header == "no-store"
    assert attempt.x_dns_prefetch_control_header == "off"
    assert attempt.cross_origin_embedder_policy_header == "require-corp"
    assert attempt.cross_origin_opener_policy_header == "same-origin"
    assert attempt.cross_origin_resource_policy_header == "same-origin"


def test_try_http_method_handles_http_exception_as_probe_failure(monkeypatch) -> None:
    from webconf_audit.external.recon import _try_http_method

    class DummyConnection:
        def __init__(self) -> None:
            self.sock = None

        def request(self, _method: str, _path: str) -> None:
            return None

        def getresponse(self):
            raise http.client.BadStatusLine("\x15\x03\x03")

        def close(self) -> None:
            return None

    monkeypatch.setattr(
        "webconf_audit.external.recon._build_connection",
        lambda _probe_target: DummyConnection(),
    )

    attempt = _try_http_method(
        ProbeTarget(scheme="http", host="example.com", port=443, path="/"),
        "HEAD",
    )

    assert attempt.tcp_open is True
    assert attempt.status_code is None
    assert attempt.error_message is not None
    assert "\\x15\\x03\\x03" not in attempt.error_message


# --- X-Powered-By presence rule ---


def test_x_powered_by_present_fires_when_header_set(monkeypatch) -> None:
    probe_attempts = [
        _https_probe_with_headers(x_powered_by_header="Express"),
        _http_redirect_probe(),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    findings = [
        f for f in result.findings
        if f.rule_id == "external.x_powered_by_header_present"
    ]
    assert len(findings) == 1
    assert findings[0].location is not None
    assert findings[0].location.details == "X-Powered-By: Express"


def test_x_powered_by_present_does_not_fire_when_header_absent(monkeypatch) -> None:
    probe_attempts = [_https_probe_with_headers(), _http_redirect_probe()]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    assert "external.x_powered_by_header_present" not in {f.rule_id for f in result.findings}


# --- X-AspNet-Version presence rule ---


def test_x_aspnet_version_present_fires_when_header_set(monkeypatch) -> None:
    probe_attempts = [
        _https_probe_with_headers(x_aspnet_version_header="4.0.30319"),
        _http_redirect_probe(),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    findings = [
        f for f in result.findings
        if f.rule_id == "external.x_aspnet_version_header_present"
    ]
    assert len(findings) == 1
    assert findings[0].location is not None
    assert findings[0].location.details == "X-AspNet-Version: 4.0.30319"


def test_x_aspnet_version_present_does_not_fire_when_header_absent(monkeypatch) -> None:
    probe_attempts = [_https_probe_with_headers(), _http_redirect_probe()]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    assert "external.x_aspnet_version_header_present" not in {f.rule_id for f in result.findings}


# --- Extended version disclosure ---


def test_version_disclosure_fires_for_server_header(monkeypatch) -> None:
    """Apache Server header version disclosure now uses the Apache-specific rule."""
    probe_attempts = [
        _https_probe_with_headers(server_header="Apache/2.4.58"),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    version_findings = [
        f for f in result.findings
        if f.rule_id == "external.apache.version_disclosed_in_server_header"
    ]
    assert len(version_findings) >= 1
    assert "Apache/2.4.58" in version_findings[0].description


def test_version_disclosure_fires_for_x_powered_by_with_version(monkeypatch) -> None:
    probe_attempts = [
        _https_probe_with_headers(x_powered_by_header="PHP/8.2.0"),
        _http_redirect_probe(),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    version_findings = [f for f in result.findings if f.rule_id == "external.server_version_disclosed"]
    assert len(version_findings) >= 1
    assert "X-Powered-By" in version_findings[0].description


def test_version_disclosure_fires_for_x_aspnet_version(monkeypatch) -> None:
    probe_attempts = [
        _https_probe_with_headers(x_aspnet_version_header="4.0.30319"),
        _http_redirect_probe(),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    version_findings = [f for f in result.findings if f.rule_id == "external.server_version_disclosed"]
    assert len(version_findings) >= 1
    assert "X-AspNet-Version" in version_findings[0].description


def test_x_powered_by_express_triggers_presence_but_not_version_disclosure(monkeypatch) -> None:
    """Express without version number: presence rule yes, version disclosure no."""
    probe_attempts = [
        _https_probe_with_headers(x_powered_by_header="Express"),
        _http_redirect_probe(),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    rule_ids = {f.rule_id for f in result.findings}
    assert "external.x_powered_by_header_present" in rule_ids
    assert "external.server_version_disclosed" not in rule_ids


# --- Coexistence: presence + version disclosure can both fire ---


def test_x_powered_by_with_version_fires_both_presence_and_disclosure(monkeypatch) -> None:
    probe_attempts = [
        _https_probe_with_headers(x_powered_by_header="PHP/8.2.0"),
        _http_redirect_probe(),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    rule_ids = {f.rule_id for f in result.findings}
    assert "external.x_powered_by_header_present" in rule_ids
    assert "external.server_version_disclosed" in rule_ids


def test_x_aspnet_version_fires_both_presence_and_disclosure(monkeypatch) -> None:
    probe_attempts = [
        _https_probe_with_headers(x_aspnet_version_header="4.0.30319"),
        _http_redirect_probe(),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    rule_ids = {f.rule_id for f in result.findings}
    assert "external.x_aspnet_version_header_present" in rule_ids
    assert "external.server_version_disclosed" in rule_ids


# --- Disclosure rules apply to HTTP too, not only HTTPS ---


def test_x_powered_by_fires_for_http_response(monkeypatch) -> None:
    probe_attempts = [
        ProbeAttempt(
            target=ProbeTarget(scheme="http", host="example.com", port=80, path="/"),
            tcp_open=True,
            status_code=200,
            reason_phrase="OK",
            server_header="nginx",
            x_powered_by_header="PHP/8.2.0",
        ),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    rule_ids = {f.rule_id for f in result.findings}
    assert "external.x_powered_by_header_present" in rule_ids


# --- CORS / Allow header metadata ---


def test_access_control_allow_origin_in_metadata(monkeypatch) -> None:
    probe_attempts = [
        _https_probe_with_headers(access_control_allow_origin_header="*"),
        _http_redirect_probe(),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    assert result.metadata["probe_attempts"][0]["access_control_allow_origin_header"] == "*"


def test_access_control_allow_credentials_in_metadata(monkeypatch) -> None:
    probe_attempts = [
        _https_probe_with_headers(access_control_allow_credentials_header="true"),
        _http_redirect_probe(),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    assert result.metadata["probe_attempts"][0]["access_control_allow_credentials_header"] == "true"


def test_allow_header_in_metadata(monkeypatch) -> None:
    probe_attempts = [
        _https_probe_with_headers(allow_header="GET, HEAD, OPTIONS"),
        _http_redirect_probe(),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    assert result.metadata["probe_attempts"][0]["allow_header"] == "GET, HEAD, OPTIONS"


# --- CORS wildcard origin rule ---


def test_cors_wildcard_origin_fires_for_star(monkeypatch) -> None:
    probe_attempts = [
        _https_probe_with_headers(access_control_allow_origin_header="*"),
        _http_redirect_probe(),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    assert "external.cors_wildcard_origin" in {f.rule_id for f in result.findings}


def test_cors_wildcard_origin_does_not_fire_when_absent(monkeypatch) -> None:
    probe_attempts = [_https_probe_with_headers(), _http_redirect_probe()]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    assert "external.cors_wildcard_origin" not in {f.rule_id for f in result.findings}


def test_cors_wildcard_origin_does_not_fire_for_concrete_origin(monkeypatch) -> None:
    probe_attempts = [
        _https_probe_with_headers(access_control_allow_origin_header="https://example.com"),
        _http_redirect_probe(),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    assert "external.cors_wildcard_origin" not in {f.rule_id for f in result.findings}


# --- CORS wildcard with credentials rule ---


def test_cors_wildcard_with_credentials_fires(monkeypatch) -> None:
    probe_attempts = [
        _https_probe_with_headers(
            access_control_allow_origin_header="*",
            access_control_allow_credentials_header="true",
        ),
        _http_redirect_probe(),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    assert "external.cors_wildcard_with_credentials" in {f.rule_id for f in result.findings}


def test_cors_wildcard_with_credentials_case_insensitive(monkeypatch) -> None:
    probe_attempts = [
        _https_probe_with_headers(
            access_control_allow_origin_header="*",
            access_control_allow_credentials_header="True",
        ),
        _http_redirect_probe(),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    assert "external.cors_wildcard_with_credentials" in {f.rule_id for f in result.findings}


def test_cors_wildcard_with_credentials_does_not_fire_for_concrete_origin(monkeypatch) -> None:
    probe_attempts = [
        _https_probe_with_headers(
            access_control_allow_origin_header="https://example.com",
            access_control_allow_credentials_header="true",
        ),
        _http_redirect_probe(),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    assert "external.cors_wildcard_with_credentials" not in {f.rule_id for f in result.findings}


def test_cors_wildcard_with_credentials_does_not_fire_without_credentials(monkeypatch) -> None:
    probe_attempts = [
        _https_probe_with_headers(access_control_allow_origin_header="*"),
        _http_redirect_probe(),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    assert "external.cors_wildcard_with_credentials" not in {f.rule_id for f in result.findings}


# --- TRACE method allowed rule ---


def test_trace_method_allowed_fires_when_trace_in_allow(monkeypatch) -> None:
    probe_attempts = [
        _https_probe_with_headers(allow_header="GET, HEAD, TRACE, OPTIONS"),
        _http_redirect_probe(),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    assert "external.trace_method_allowed" in {f.rule_id for f in result.findings}


def test_trace_method_allowed_does_not_fire_without_trace(monkeypatch) -> None:
    probe_attempts = [
        _https_probe_with_headers(allow_header="GET, HEAD, OPTIONS"),
        _http_redirect_probe(),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    assert "external.trace_method_allowed" not in {f.rule_id for f in result.findings}


def test_trace_method_allowed_does_not_fire_when_allow_absent(monkeypatch) -> None:
    probe_attempts = [_https_probe_with_headers(), _http_redirect_probe()]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    assert "external.trace_method_allowed" not in {f.rule_id for f in result.findings}


def test_trace_method_allowed_handles_case_and_spaces(monkeypatch) -> None:
    probe_attempts = [
        _https_probe_with_headers(allow_header="get , head , trace , options"),
        _http_redirect_probe(),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    assert "external.trace_method_allowed" in {f.rule_id for f in result.findings}


def test_trace_method_allowed_fires_for_http_response(monkeypatch) -> None:
    probe_attempts = [
        ProbeAttempt(
            target=ProbeTarget(scheme="http", host="example.com", port=80, path="/"),
            tcp_open=True,
            status_code=200,
            reason_phrase="OK",
            server_header="apache",
            allow_header="GET, HEAD, TRACE",
        ),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    assert "external.trace_method_allowed" in {f.rule_id for f in result.findings}


# --- Allow header preservation across HEAD->GET fallback ---


def test_allow_header_preserved_from_head_405_to_get_fallback(monkeypatch) -> None:
    from webconf_audit.external.recon import _probe_target

    target = ProbeTarget(scheme="https", host="example.com", port=443, path="/")

    def fake_try(probe_target, method):
        if method == "HEAD":
            return ProbeAttempt(
                target=probe_target,
                tcp_open=True,
                effective_method="HEAD",
                status_code=405,
                reason_phrase="Method Not Allowed",
                server_header="apache",
                allow_header="GET, HEAD, TRACE",
            )
        return ProbeAttempt(
            target=probe_target,
            tcp_open=True,
            effective_method="GET",
            status_code=200,
            reason_phrase="OK",
            server_header="apache",
            **_ALL_SECURITY_HEADERS,
        )

    monkeypatch.setattr("webconf_audit.external.recon._is_tcp_port_open", lambda h, p: True)
    monkeypatch.setattr("webconf_audit.external.recon._try_http_method", fake_try)

    result = _probe_target(target)
    assert result.effective_method == "GET"
    assert result.status_code == 200
    assert result.allow_header == "GET, HEAD, TRACE"


# --- CORS mutual exclusion: wildcard+credentials suppresses plain wildcard ---


def test_cors_wildcard_and_credentials_suppresses_plain_wildcard_rule(monkeypatch) -> None:
    probe_attempts = [
        _https_probe_with_headers(
            access_control_allow_origin_header="*",
            access_control_allow_credentials_header="true",
        ),
        _http_redirect_probe(),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    rule_ids = {f.rule_id for f in result.findings}
    assert "external.cors_wildcard_with_credentials" in rule_ids
    assert "external.cors_wildcard_origin" not in rule_ids


# --- Cookie helper tests ---


def test_parse_cookie_extracts_name_and_attributes() -> None:
    from webconf_audit.external.recon._cookie import parse_cookie

    cookie = parse_cookie("session_id=abc123; Secure; HttpOnly; SameSite=Lax; Path=/")
    assert cookie.name == "session_id"
    assert cookie.has_secure is True
    assert cookie.has_httponly is True
    assert cookie.samesite_value == "Lax"


def test_parse_cookie_case_insensitive_attributes() -> None:
    from webconf_audit.external.recon._cookie import parse_cookie

    cookie = parse_cookie("sid=x; secure; HTTPONLY; samesite=Strict")
    assert cookie.has_secure is True
    assert cookie.has_httponly is True
    assert cookie.samesite_value == "Strict"


def test_parse_cookie_missing_attributes() -> None:
    from webconf_audit.external.recon._cookie import parse_cookie

    cookie = parse_cookie("sid=x; Path=/")
    assert cookie.name == "sid"
    assert cookie.has_secure is False
    assert cookie.has_httponly is False
    assert cookie.samesite_value is None


def test_is_session_like_cookie_matches() -> None:
    from webconf_audit.external.recon._cookie import is_session_like_cookie

    assert is_session_like_cookie("PHPSESSID") is True
    assert is_session_like_cookie("session_id") is True
    assert is_session_like_cookie("auth_token") is True
    assert is_session_like_cookie("JWT") is True
    assert is_session_like_cookie("connect.sid") is True
    assert is_session_like_cookie("my_token") is True


def test_is_session_like_cookie_rejects_non_session() -> None:
    from webconf_audit.external.recon._cookie import is_session_like_cookie

    assert is_session_like_cookie("_ga") is False
    assert is_session_like_cookie("theme") is False
    assert is_session_like_cookie("lang") is False


def test_is_session_like_cookie_excludes_csrf_cookies() -> None:
    from webconf_audit.external.recon._cookie import is_session_like_cookie

    assert is_session_like_cookie("csrftoken") is False
    assert is_session_like_cookie("xsrf-token") is False
    assert is_session_like_cookie("csrf-token") is False
    assert is_session_like_cookie("CSRFTOKEN") is False


def test_csrf_cookies_do_not_trigger_cookie_rules(monkeypatch) -> None:
    probe_attempts = [
        _https_probe_with_headers(
            set_cookie_headers=("csrftoken=abc; Path=/", "xsrf-token=xyz; Path=/"),
        ),
        _http_redirect_probe(),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    cookie_rules = {
        "external.cookie_missing_secure_on_https",
        "external.cookie_missing_httponly",
        "external.cookie_missing_samesite",
    }
    assert not cookie_rules.intersection({f.rule_id for f in result.findings})


# --- Set-Cookie collection metadata ---


def test_set_cookie_headers_in_metadata(monkeypatch) -> None:
    probe_attempts = [
        _https_probe_with_headers(
            set_cookie_headers=("session_id=abc; Secure", "lang=en"),
        ),
        _http_redirect_probe(),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    cookies = result.metadata["probe_attempts"][0]["set_cookie_headers"]
    assert cookies == ["session_id=abc; Secure", "lang=en"]


def test_set_cookie_empty_when_no_cookies(monkeypatch) -> None:
    probe_attempts = [_https_probe_with_headers(), _http_redirect_probe()]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    assert result.metadata["probe_attempts"][0]["set_cookie_headers"] == []


# --- Cookie missing Secure on HTTPS ---


def test_cookie_missing_secure_fires_on_https(monkeypatch) -> None:
    probe_attempts = [
        _https_probe_with_headers(
            set_cookie_headers=("session_id=abc; HttpOnly; SameSite=Lax",),
        ),
        _http_redirect_probe(),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    secure_findings = [f for f in result.findings if f.rule_id == "external.cookie_missing_secure_on_https"]
    assert len(secure_findings) == 1
    assert "session_id" in secure_findings[0].description


def test_cookie_missing_secure_does_not_fire_on_http(monkeypatch) -> None:
    probe_attempts = [
        ProbeAttempt(
            target=ProbeTarget(scheme="http", host="example.com", port=80, path="/"),
            tcp_open=True,
            status_code=200,
            reason_phrase="OK",
            server_header="nginx",
            set_cookie_headers=("session_id=abc; HttpOnly",),
        ),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    assert "external.cookie_missing_secure_on_https" not in {f.rule_id for f in result.findings}


def test_cookie_missing_secure_does_not_fire_when_secure_present(monkeypatch) -> None:
    probe_attempts = [
        _https_probe_with_headers(
            set_cookie_headers=("session_id=abc; Secure; HttpOnly; SameSite=Lax",),
        ),
        _http_redirect_probe(),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    assert "external.cookie_missing_secure_on_https" not in {f.rule_id for f in result.findings}


# --- Cookie missing HttpOnly ---


def test_cookie_missing_httponly_fires(monkeypatch) -> None:
    probe_attempts = [
        _https_probe_with_headers(
            set_cookie_headers=("session_id=abc; Secure; SameSite=Lax",),
        ),
        _http_redirect_probe(),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    httponly_findings = [f for f in result.findings if f.rule_id == "external.cookie_missing_httponly"]
    assert len(httponly_findings) == 1
    assert "session_id" in httponly_findings[0].description


def test_cookie_missing_httponly_does_not_fire_when_present(monkeypatch) -> None:
    probe_attempts = [
        _https_probe_with_headers(
            set_cookie_headers=("session_id=abc; Secure; HttpOnly; SameSite=Lax",),
        ),
        _http_redirect_probe(),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    assert "external.cookie_missing_httponly" not in {f.rule_id for f in result.findings}


# --- Cookie missing SameSite ---


def test_cookie_missing_samesite_fires(monkeypatch) -> None:
    probe_attempts = [
        _https_probe_with_headers(
            set_cookie_headers=("session_id=abc; Secure; HttpOnly",),
        ),
        _http_redirect_probe(),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    samesite_findings = [f for f in result.findings if f.rule_id == "external.cookie_missing_samesite"]
    assert len(samesite_findings) == 1
    assert "session_id" in samesite_findings[0].description


def test_cookie_missing_samesite_does_not_fire_when_present(monkeypatch) -> None:
    probe_attempts = [
        _https_probe_with_headers(
            set_cookie_headers=("session_id=abc; Secure; HttpOnly; SameSite=Strict",),
        ),
        _http_redirect_probe(),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    assert "external.cookie_missing_samesite" not in {f.rule_id for f in result.findings}


# --- No findings for non-session cookies ---


def test_no_cookie_findings_for_non_session_cookie(monkeypatch) -> None:
    probe_attempts = [
        _https_probe_with_headers(
            set_cookie_headers=("_ga=GA1.2.123; Path=/",),
        ),
        _http_redirect_probe(),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    cookie_rules = {
        "external.cookie_missing_secure_on_https",
        "external.cookie_missing_httponly",
        "external.cookie_missing_samesite",
    }
    assert not cookie_rules.intersection({f.rule_id for f in result.findings})


# --- Multiple cookies with mixed posture ---


def test_multiple_cookies_mixed_posture(monkeypatch) -> None:
    probe_attempts = [
        _https_probe_with_headers(
            set_cookie_headers=(
                "session_id=abc; Secure; HttpOnly; SameSite=Lax",
                "auth_token=xyz; Path=/",
            ),
        ),
        _http_redirect_probe(),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)

    secure_findings = [f for f in result.findings if f.rule_id == "external.cookie_missing_secure_on_https"]
    assert len(secure_findings) == 1
    assert "auth_token" in secure_findings[0].description

    httponly_findings = [f for f in result.findings if f.rule_id == "external.cookie_missing_httponly"]
    assert len(httponly_findings) == 1
    assert "auth_token" in httponly_findings[0].description

    samesite_findings = [f for f in result.findings if f.rule_id == "external.cookie_missing_samesite"]
    assert len(samesite_findings) == 1
    assert "auth_token" in samesite_findings[0].description


# --- TLS observation metadata ---


_VALID_TLS = TLSInfo(
    protocol_version="TLSv1.3",
    cert_not_before="Jan  1 00:00:00 2025 GMT",
    cert_not_after="Dec 31 23:59:59 2027 GMT",
    cert_subject="commonName=example.com",
    cert_issuer="commonName=Test CA",
)


def test_tls_info_in_metadata(monkeypatch) -> None:
    probe_attempts = [
        _https_probe_with_headers(tls_info=_VALID_TLS),
        _http_redirect_probe(),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    tls_meta = result.metadata["probe_attempts"][0]["tls_info"]
    assert tls_meta is not None
    assert tls_meta["protocol_version"] == "TLSv1.3"
    assert tls_meta["cert_not_after"] == "Dec 31 23:59:59 2027 GMT"
    assert tls_meta["cert_subject"] == "commonName=example.com"
    assert tls_meta["cert_issuer"] == "commonName=Test CA"


def test_tls_info_none_when_http(monkeypatch) -> None:
    probe_attempts = [
        _https_probe_with_headers(),
        _http_redirect_probe(),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    assert result.metadata["probe_attempts"][0]["tls_info"] is None


def test_tls_cipher_info_in_metadata(monkeypatch) -> None:
    tls = TLSInfo(
        protocol_version="TLSv1.3",
        cipher_name="TLS_AES_256_GCM_SHA384",
        cipher_bits=256,
        cipher_protocol="TLSv1.3",
        cert_not_before="Jan  1 00:00:00 2025 GMT",
        cert_not_after="Dec 31 23:59:59 2027 GMT",
        cert_subject="commonName=example.com",
        cert_issuer="commonName=Test CA",
    )
    probe_attempts = [
        _https_probe_with_headers(tls_info=tls),
        _http_redirect_probe(),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    tls_meta = result.metadata["probe_attempts"][0]["tls_info"]
    assert tls_meta["cipher_name"] == "TLS_AES_256_GCM_SHA384"
    assert tls_meta["cipher_bits"] == 256
    assert tls_meta["cipher_protocol"] == "TLSv1.3"


def test_tls_cipher_none_when_not_available(monkeypatch) -> None:
    tls = TLSInfo(protocol_version="TLSv1.2")
    probe_attempts = [
        _https_probe_with_headers(tls_info=tls),
        _http_redirect_probe(),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    tls_meta = result.metadata["probe_attempts"][0]["tls_info"]
    assert tls_meta["cipher_name"] is None
    assert tls_meta["cipher_bits"] is None
    assert tls_meta["cipher_protocol"] is None


def test_tls_san_in_metadata(monkeypatch) -> None:
    tls = TLSInfo(
        protocol_version="TLSv1.3",
        cert_san=("example.com", "*.example.com", "www.example.com"),
        cert_not_before="Jan  1 00:00:00 2025 GMT",
        cert_not_after="Dec 31 23:59:59 2027 GMT",
        cert_subject="commonName=example.com",
        cert_issuer="commonName=Test CA",
    )
    probe_attempts = [
        _https_probe_with_headers(tls_info=tls),
        _http_redirect_probe(),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    tls_meta = result.metadata["probe_attempts"][0]["tls_info"]
    assert tls_meta["cert_san"] == ["example.com", "*.example.com", "www.example.com"]


def test_tls_san_empty_when_absent(monkeypatch) -> None:
    tls = TLSInfo(protocol_version="TLSv1.3")
    probe_attempts = [
        _https_probe_with_headers(tls_info=tls),
        _http_redirect_probe(),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    tls_meta = result.metadata["probe_attempts"][0]["tls_info"]
    assert tls_meta["cert_san"] == []






def test_tls_cipher_in_diagnostics(monkeypatch) -> None:
    tls = TLSInfo(
        protocol_version="TLSv1.3",
        cipher_name="TLS_AES_256_GCM_SHA384",
        cipher_bits=256,
    )
    probe_attempts = [
        _https_probe_with_headers(tls_info=tls),
        _http_redirect_probe(),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    assert any("tls_cipher: TLS_AES_256_GCM_SHA384 (256 bits)" in d for d in result.diagnostics)


def test_tls_san_in_diagnostics(monkeypatch) -> None:
    tls = TLSInfo(
        protocol_version="TLSv1.3",
        cert_san=("example.com", "www.example.com"),
    )
    probe_attempts = [
        _https_probe_with_headers(tls_info=tls),
        _http_redirect_probe(),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    assert any("cert_san: example.com, www.example.com" in d for d in result.diagnostics)


def test_deep_tls_probe_results_in_diagnostics(monkeypatch) -> None:
    tls = TLSInfo(
        protocol_version="TLSv1.3",
        supported_protocols=("TLSv1.2", "TLSv1.3"),
        cert_chain_complete=False,
        cert_chain_error="unable to get local issuer certificate",
    )
    probe_attempts = [
        _https_probe_with_headers(tls_info=tls),
        _http_redirect_probe(),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    assert any("tls_supported: TLSv1.2, TLSv1.3" in d for d in result.diagnostics)
    assert any("cert_chain_complete: False" in d for d in result.diagnostics)
    assert any(
        "cert_chain_error: unable to get local issuer certificate" in d
        for d in result.diagnostics
    )


# --- _extract_san unit test ---


def test_extract_san_helper() -> None:
    from webconf_audit.external.recon import _extract_san

    cert = {"subjectAltName": (("DNS", "example.com"), ("DNS", "*.example.com"))}
    assert _extract_san(cert) == ("example.com", "*.example.com")


def test_extract_san_empty_when_no_san() -> None:
    from webconf_audit.external.recon import _extract_san

    assert _extract_san({}) == ()
    assert _extract_san({"subjectAltName": None}) == ()
    assert _extract_san({"subjectAltName": ()}) == ()


def test_extract_san_filters_non_dns_entries() -> None:
    """Only DNS-type SAN entries are extracted; IP, email, URI are dropped."""
    from webconf_audit.external.recon import _extract_san

    cert = {
        "subjectAltName": (
            ("DNS", "example.com"),
            ("IP Address", "192.168.1.1"),
            ("DNS", "www.example.com"),
            ("email", "admin@example.com"),
            ("URI", "https://example.com"),
        ),
    }
    assert _extract_san(cert) == ("example.com", "www.example.com")


def test_extract_san_all_non_dns_returns_empty() -> None:
    """When all SAN entries are non-DNS, return empty tuple."""
    from webconf_audit.external.recon import _extract_san

    cert = {
        "subjectAltName": (
            ("IP Address", "10.0.0.1"),
            ("email", "admin@example.com"),
        ),
    }
    assert _extract_san(cert) == ()


# --- Certificate expired rule ---


# --- Certificate expired rule ---


def test_certificate_expired_fires(monkeypatch) -> None:
    tls = TLSInfo(
        protocol_version="TLSv1.2",
        cert_not_after="Jan  1 00:00:00 2020 GMT",
    )
    probe_attempts = [
        _https_probe_with_headers(tls_info=tls),
        _http_redirect_probe(),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    assert "external.certificate_expired" in {f.rule_id for f in result.findings}


def test_certificate_expired_does_not_fire_for_valid_cert(monkeypatch) -> None:
    tls = TLSInfo(
        protocol_version="TLSv1.2",
        cert_not_after="Dec 31 23:59:59 2027 GMT",
    )
    probe_attempts = [
        _https_probe_with_headers(tls_info=tls),
        _http_redirect_probe(),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    assert "external.certificate_expired" not in {f.rule_id for f in result.findings}


def test_certificate_expired_does_not_fire_when_tls_info_absent(monkeypatch) -> None:
    probe_attempts = [_https_probe_with_headers(), _http_redirect_probe()]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    assert "external.certificate_expired" not in {f.rule_id for f in result.findings}


# --- Certificate expires soon rule ---


def test_certificate_expires_soon_fires(monkeypatch) -> None:
    from datetime import datetime, timedelta, timezone

    soon = datetime.now(timezone.utc) + timedelta(days=10)
    cert_date = soon.strftime("%b %d %H:%M:%S %Y GMT")
    tls = TLSInfo(protocol_version="TLSv1.2", cert_not_after=cert_date)
    probe_attempts = [
        _https_probe_with_headers(tls_info=tls),
        _http_redirect_probe(),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    assert "external.certificate_expires_soon" in {f.rule_id for f in result.findings}


def test_certificate_expires_soon_does_not_fire_for_distant_expiry(monkeypatch) -> None:
    tls = TLSInfo(
        protocol_version="TLSv1.2",
        cert_not_after="Dec 31 23:59:59 2027 GMT",
    )
    probe_attempts = [
        _https_probe_with_headers(tls_info=tls),
        _http_redirect_probe(),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    assert "external.certificate_expires_soon" not in {f.rule_id for f in result.findings}


def test_certificate_expires_soon_does_not_fire_for_already_expired(monkeypatch) -> None:
    tls = TLSInfo(
        protocol_version="TLSv1.2",
        cert_not_after="Jan  1 00:00:00 2020 GMT",
    )
    probe_attempts = [
        _https_probe_with_headers(tls_info=tls),
        _http_redirect_probe(),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    rule_ids = {f.rule_id for f in result.findings}
    assert "external.certificate_expired" in rule_ids
    assert "external.certificate_expires_soon" not in rule_ids


# ---------------------------------------------------------------------------
# OPTIONS observation – metadata
# ---------------------------------------------------------------------------


def test_options_observation_captured_in_metadata(monkeypatch) -> None:
    obs = OptionsObservation(status_code=200, allow_header="GET, HEAD, OPTIONS")
    probe_attempts = [
        _https_probe_with_headers(options_observation=obs),
        _http_redirect_probe(),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    meta_obs = result.metadata["probe_attempts"][0]["options_observation"]
    assert meta_obs is not None
    assert meta_obs["status_code"] == 200
    assert meta_obs["allow_header"] == "GET, HEAD, OPTIONS"
    assert meta_obs["public_header"] is None
    assert meta_obs["error_message"] is None


def test_options_observation_none_in_metadata(monkeypatch) -> None:
    probe_attempts = [
        _https_probe_with_headers(),
        _http_redirect_probe(),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    assert result.metadata["probe_attempts"][0]["options_observation"] is None


# ---------------------------------------------------------------------------
# external.options_method_exposed
# ---------------------------------------------------------------------------


def test_options_method_exposed_fires_when_allow_present(monkeypatch) -> None:
    obs = OptionsObservation(status_code=200, allow_header="GET, HEAD, OPTIONS")
    probe_attempts = [
        _https_probe_with_headers(options_observation=obs),
        _http_redirect_probe(),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    assert "external.options_method_exposed" in {f.rule_id for f in result.findings}


def test_options_method_exposed_fires_when_public_present(monkeypatch) -> None:
    obs = OptionsObservation(status_code=200, public_header="GET, HEAD, TRACE")
    probe_attempts = [
        _https_probe_with_headers(options_observation=obs),
        _http_redirect_probe(),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    assert "external.options_method_exposed" in {f.rule_id for f in result.findings}


def test_options_method_exposed_does_not_fire_without_observation(monkeypatch) -> None:
    probe_attempts = [
        _https_probe_with_headers(),
        _http_redirect_probe(),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    assert "external.options_method_exposed" not in {f.rule_id for f in result.findings}


def test_options_method_exposed_does_not_fire_when_no_methods(monkeypatch) -> None:
    obs = OptionsObservation(status_code=200)
    probe_attempts = [
        _https_probe_with_headers(options_observation=obs),
        _http_redirect_probe(),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    assert "external.options_method_exposed" not in {f.rule_id for f in result.findings}


# ---------------------------------------------------------------------------
# external.dangerous_http_methods_enabled
# ---------------------------------------------------------------------------


def test_dangerous_methods_fires_for_trace_and_delete(monkeypatch) -> None:
    obs = OptionsObservation(status_code=200, allow_header="GET, HEAD, TRACE, DELETE")
    probe_attempts = [
        _https_probe_with_headers(options_observation=obs),
        _http_redirect_probe(),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    rule_ids = {f.rule_id for f in result.findings}
    assert "external.dangerous_http_methods_enabled" in rule_ids
    finding = [f for f in result.findings if f.rule_id == "external.dangerous_http_methods_enabled"][0]
    assert "DELETE" in finding.description
    assert "TRACE" in finding.description


def test_dangerous_methods_fires_for_put_delete_only(monkeypatch) -> None:
    obs = OptionsObservation(status_code=200, allow_header="GET, HEAD, PUT, DELETE")
    probe_attempts = [
        _https_probe_with_headers(options_observation=obs),
        _http_redirect_probe(),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    assert "external.dangerous_http_methods_enabled" in {f.rule_id for f in result.findings}


def test_dangerous_methods_does_not_fire_for_safe_methods(monkeypatch) -> None:
    obs = OptionsObservation(status_code=200, allow_header="GET, HEAD, OPTIONS, POST")
    probe_attempts = [
        _https_probe_with_headers(options_observation=obs),
        _http_redirect_probe(),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    assert "external.dangerous_http_methods_enabled" not in {f.rule_id for f in result.findings}


def test_dangerous_methods_case_insensitive(monkeypatch) -> None:
    obs = OptionsObservation(status_code=200, allow_header="get, head, Trace, delete")
    probe_attempts = [
        _https_probe_with_headers(options_observation=obs),
        _http_redirect_probe(),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    assert "external.dangerous_http_methods_enabled" in {f.rule_id for f in result.findings}


def test_dangerous_methods_whitespace_tolerant(monkeypatch) -> None:
    obs = OptionsObservation(status_code=200, allow_header=" GET , TRACE , DELETE ")
    probe_attempts = [
        _https_probe_with_headers(options_observation=obs),
        _http_redirect_probe(),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    assert "external.dangerous_http_methods_enabled" in {f.rule_id for f in result.findings}


def test_dangerous_methods_does_not_fire_without_observation(monkeypatch) -> None:
    probe_attempts = [
        _https_probe_with_headers(),
        _http_redirect_probe(),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    assert "external.dangerous_http_methods_enabled" not in {f.rule_id for f in result.findings}


def test_dangerous_methods_via_public_header(monkeypatch) -> None:
    obs = OptionsObservation(status_code=200, public_header="GET, HEAD, TRACE")
    probe_attempts = [
        _https_probe_with_headers(options_observation=obs),
        _http_redirect_probe(),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    assert "external.dangerous_http_methods_enabled" in {f.rule_id for f in result.findings}


# ---------------------------------------------------------------------------
# external.trace_method_exposed_via_options
# ---------------------------------------------------------------------------


def test_trace_via_options_fires_when_not_in_head_allow(monkeypatch) -> None:
    obs = OptionsObservation(status_code=200, allow_header="GET, HEAD, TRACE")
    probe_attempts = [
        _https_probe_with_headers(options_observation=obs),
        _http_redirect_probe(),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    assert "external.trace_method_exposed_via_options" in {f.rule_id for f in result.findings}


def test_trace_via_options_suppressed_when_already_in_head_allow(monkeypatch) -> None:
    obs = OptionsObservation(status_code=200, allow_header="GET, HEAD, TRACE")
    probe_attempts = [
        _https_probe_with_headers(
            allow_header="GET, HEAD, TRACE",
            options_observation=obs,
        ),
        _http_redirect_probe(),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    rule_ids = {f.rule_id for f in result.findings}
    assert "external.trace_method_exposed_via_options" not in rule_ids
    assert "external.trace_method_allowed" in rule_ids


def test_trace_via_options_does_not_fire_without_observation(monkeypatch) -> None:
    probe_attempts = [
        _https_probe_with_headers(),
        _http_redirect_probe(),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    assert "external.trace_method_exposed_via_options" not in {f.rule_id for f in result.findings}


def test_trace_via_options_does_not_fire_when_no_trace(monkeypatch) -> None:
    obs = OptionsObservation(status_code=200, allow_header="GET, HEAD, OPTIONS")
    probe_attempts = [
        _https_probe_with_headers(options_observation=obs),
        _http_redirect_probe(),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    assert "external.trace_method_exposed_via_options" not in {f.rule_id for f in result.findings}


def test_trace_via_options_public_header_sets_correct_source_detail(monkeypatch) -> None:
    obs = OptionsObservation(status_code=200, public_header="GET, HEAD, TRACE")
    probe_attempts = [
        _https_probe_with_headers(options_observation=obs),
        _http_redirect_probe(),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    findings = [f for f in result.findings if f.rule_id == "external.trace_method_exposed_via_options"]
    assert len(findings) == 1
    assert findings[0].location.details == "OPTIONS Public"


# ---------------------------------------------------------------------------
# No false positives from new OPTIONS rules on baseline probes
# ---------------------------------------------------------------------------


def test_no_options_findings_on_baseline_probe(monkeypatch) -> None:
    probe_attempts = [
        _https_probe_with_headers(),
        _http_redirect_probe(),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    options_rule_ids = {
        "external.options_method_exposed",
        "external.dangerous_http_methods_enabled",
        "external.trace_method_exposed_via_options",
    }
    fired = options_rule_ids & {f.rule_id for f in result.findings}
    assert fired == set()


# ---------------------------------------------------------------------------
# Sensitive path probes – metadata
# ---------------------------------------------------------------------------


def test_sensitive_paths_phase_1_4_1_set() -> None:
    from webconf_audit.external.recon import _SENSITIVE_PATHS

    assert _SENSITIVE_PATHS == (
        "/.git/HEAD",
        "/server-status",
        "/server-info",
        "/nginx_status",
        "/.env",
        "/.htaccess",
        "/.htpasswd",
        "/wp-admin/",
        "/phpinfo.php",
        "/elmah.axd",
        "/trace.axd",
        "/web.config",
        "/robots.txt",
        "/sitemap.xml",
        "/.svn/entries",
    )


def test_probe_sensitive_paths_uses_all_universal_paths(monkeypatch) -> None:
    from webconf_audit.external.recon import _SENSITIVE_PATHS, _probe_sensitive_paths

    seen_paths: list[str] = []

    def fake_try_sensitive_path(probe_target: ProbeTarget) -> SensitivePathProbe:
        seen_paths.append(probe_target.path)
        return SensitivePathProbe(url=probe_target.url, path=probe_target.path, status_code=404)

    monkeypatch.setattr(
        "webconf_audit.external.recon._try_sensitive_path",
        fake_try_sensitive_path,
    )

    _probe_sensitive_paths([_https_probe_with_headers()])

    assert seen_paths == list(_SENSITIVE_PATHS)


def test_probe_sensitive_paths_deduplicates_same_endpoint(monkeypatch) -> None:
    from webconf_audit.external.recon import _SENSITIVE_PATHS, _probe_sensitive_paths

    seen_paths: list[str] = []

    def fake_try_sensitive_path(probe_target: ProbeTarget) -> SensitivePathProbe:
        seen_paths.append(probe_target.path)
        return SensitivePathProbe(url=probe_target.url, path=probe_target.path, status_code=404)

    monkeypatch.setattr(
        "webconf_audit.external.recon._try_sensitive_path",
        fake_try_sensitive_path,
    )

    duplicate_attempts = [_https_probe_with_headers(), _https_probe_with_headers()]
    _probe_sensitive_paths(duplicate_attempts)

    assert seen_paths == list(_SENSITIVE_PATHS)


@pytest.mark.parametrize("confidence", ["medium", "high"])
def test_probe_sensitive_paths_adds_apache_conditional_paths_at_supported_confidence(
    monkeypatch,
    confidence: str,
) -> None:
    from webconf_audit.external.recon import _probe_sensitive_paths

    seen_paths: list[str] = []

    def fake_try_sensitive_path(probe_target: ProbeTarget) -> SensitivePathProbe:
        seen_paths.append(probe_target.path)
        return SensitivePathProbe(url=probe_target.url, path=probe_target.path, status_code=404)

    monkeypatch.setattr(
        "webconf_audit.external.recon._try_sensitive_path",
        fake_try_sensitive_path,
    )

    identification = ServerIdentification(
        server_type="apache",
        confidence=confidence,
        evidence=(),
        candidate_server_types=("apache",),
    )
    _probe_sensitive_paths([_https_probe_with_headers()], identification)

    assert "/server-status?auto" in seen_paths


def test_probe_sensitive_paths_skips_conditional_paths_for_unknown_identification(monkeypatch) -> None:
    from webconf_audit.external.recon import _probe_sensitive_paths

    seen_paths: list[str] = []

    def fake_try_sensitive_path(probe_target: ProbeTarget) -> SensitivePathProbe:
        seen_paths.append(probe_target.path)
        return SensitivePathProbe(url=probe_target.url, path=probe_target.path, status_code=404)

    monkeypatch.setattr(
        "webconf_audit.external.recon._try_sensitive_path",
        fake_try_sensitive_path,
    )

    identification = ServerIdentification(
        server_type=None,
        confidence="none",
        evidence=(),
    )
    _probe_sensitive_paths([_https_probe_with_headers()], identification)

    assert "/server-status?auto" not in seen_paths


def test_probe_sensitive_paths_skips_conditional_paths_for_ambiguous_identification(monkeypatch) -> None:
    from webconf_audit.external.recon import _probe_sensitive_paths

    seen_paths: list[str] = []

    def fake_try_sensitive_path(probe_target: ProbeTarget) -> SensitivePathProbe:
        seen_paths.append(probe_target.path)
        return SensitivePathProbe(url=probe_target.url, path=probe_target.path, status_code=404)

    monkeypatch.setattr(
        "webconf_audit.external.recon._try_sensitive_path",
        fake_try_sensitive_path,
    )

    identification = ServerIdentification(
        server_type=None,
        confidence="none",
        evidence=(),
        ambiguous=True,
        candidate_server_types=("apache", "nginx"),
    )
    _probe_sensitive_paths([_https_probe_with_headers()], identification)

    assert "/server-status?auto" not in seen_paths


def test_probe_sensitive_paths_skips_conditional_paths_for_other_server_type(monkeypatch) -> None:
    from webconf_audit.external.recon import _probe_sensitive_paths

    seen_paths: list[str] = []

    def fake_try_sensitive_path(probe_target: ProbeTarget) -> SensitivePathProbe:
        seen_paths.append(probe_target.path)
        return SensitivePathProbe(url=probe_target.url, path=probe_target.path, status_code=404)

    monkeypatch.setattr(
        "webconf_audit.external.recon._try_sensitive_path",
        fake_try_sensitive_path,
    )

    identification = ServerIdentification(
        server_type="nginx",
        confidence="high",
        evidence=(),
        candidate_server_types=("nginx",),
    )
    _probe_sensitive_paths([_https_probe_with_headers()], identification)

    assert "/server-status?auto" not in seen_paths


def test_probe_sensitive_paths_skips_conditional_paths_for_low_confidence(monkeypatch) -> None:
    from webconf_audit.external.recon import _probe_sensitive_paths

    seen_paths: list[str] = []

    def fake_try_sensitive_path(probe_target: ProbeTarget) -> SensitivePathProbe:
        seen_paths.append(probe_target.path)
        return SensitivePathProbe(url=probe_target.url, path=probe_target.path, status_code=404)

    monkeypatch.setattr(
        "webconf_audit.external.recon._try_sensitive_path",
        fake_try_sensitive_path,
    )

    identification = ServerIdentification(
        server_type="apache",
        confidence="low",
        evidence=(),
        candidate_server_types=("apache",),
    )
    _probe_sensitive_paths([_https_probe_with_headers()], identification)

    assert "/server-status?auto" not in seen_paths


def test_analyze_external_target_wires_identification_into_conditional_sensitive_paths(
    monkeypatch,
) -> None:
    seen_paths: list[str] = []
    probe_attempts = [
        ProbeAttempt(
            target=ProbeTarget(scheme="https", host="example.com", port=443, path="/"),
            tcp_open=True,
            status_code=200,
            reason_phrase="OK",
            server_header="Apache/2.4.58",
            **_ALL_SECURITY_HEADERS,
        )
    ]
    attempts_by_target = {attempt.target: attempt for attempt in probe_attempts}

    monkeypatch.setattr(
        "webconf_audit.external.recon._build_probe_targets",
        lambda _external_target: [attempt.target for attempt in probe_attempts],
    )
    monkeypatch.setattr(
        "webconf_audit.external.recon._probe_target",
        lambda probe_target: attempts_by_target[probe_target],
    )
    monkeypatch.setattr(
        "webconf_audit.external.recon._probe_error_pages",
        lambda successful_attempts: [],
    )
    monkeypatch.setattr(
        "webconf_audit.external.recon._probe_malformed_requests",
        lambda successful_attempts: [],
    )

    def fake_try_sensitive_path(probe_target: ProbeTarget) -> SensitivePathProbe:
        seen_paths.append(probe_target.path)
        return SensitivePathProbe(url=probe_target.url, path=probe_target.path, status_code=404)

    monkeypatch.setattr(
        "webconf_audit.external.recon._try_sensitive_path",
        fake_try_sensitive_path,
    )

    result = analyze_external_target("example.com")

    assert result.server_type == "apache"
    assert "/server-status?auto" in seen_paths


def test_analyze_external_target_adds_conditional_sensitive_path_at_medium_confidence(
    monkeypatch,
) -> None:
    seen_paths: list[str] = []
    probe_attempts = [
        ProbeAttempt(
            target=ProbeTarget(scheme="https", host="example.com", port=443, path="/"),
            tcp_open=True,
            status_code=200,
            reason_phrase="OK",
            server_header="custom-edge",
            **_ALL_SECURITY_HEADERS,
        )
    ]
    attempts_by_target = {attempt.target: attempt for attempt in probe_attempts}

    monkeypatch.setattr(
        "webconf_audit.external.recon._build_probe_targets",
        lambda _external_target: [attempt.target for attempt in probe_attempts],
    )
    monkeypatch.setattr(
        "webconf_audit.external.recon._probe_target",
        lambda probe_target: attempts_by_target[probe_target],
    )
    monkeypatch.setattr(
        "webconf_audit.external.recon._probe_error_pages",
        lambda successful_attempts: [
            ErrorPageProbe(
                url="https://example.com/_wca_nonexistent_404_probe",
                status_code=404,
                body_snippet="Apache Server at example.com Port 443",
            )
        ],
    )
    monkeypatch.setattr(
        "webconf_audit.external.recon._probe_malformed_requests",
        lambda successful_attempts: [
            MalformedRequestProbe(
                url="https://example.com/",
                status_code=400,
                body_snippet="Apache Server at example.com Port 443",
            )
        ],
    )

    def fake_try_sensitive_path(probe_target: ProbeTarget) -> SensitivePathProbe:
        seen_paths.append(probe_target.path)
        return SensitivePathProbe(url=probe_target.url, path=probe_target.path, status_code=404)

    monkeypatch.setattr(
        "webconf_audit.external.recon._try_sensitive_path",
        fake_try_sensitive_path,
    )

    result = analyze_external_target("example.com")

    assert result.server_type == "apache"
    assert result.metadata["server_identification"]["confidence"] == "medium"
    assert "/server-status?auto" in seen_paths
    assert any(
        probe["path"] == "/server-status?auto"
        for probe in result.metadata["sensitive_path_probes"]
    )


def test_analyze_external_target_skips_conditional_sensitive_path_when_unknown(
    monkeypatch,
) -> None:
    seen_paths: list[str] = []
    probe_attempts = [
        ProbeAttempt(
            target=ProbeTarget(scheme="https", host="example.com", port=443, path="/"),
            tcp_open=True,
            status_code=200,
            reason_phrase="OK",
            server_header="custom-edge",
            **_ALL_SECURITY_HEADERS,
        )
    ]
    attempts_by_target = {attempt.target: attempt for attempt in probe_attempts}

    monkeypatch.setattr(
        "webconf_audit.external.recon._build_probe_targets",
        lambda _external_target: [attempt.target for attempt in probe_attempts],
    )
    monkeypatch.setattr(
        "webconf_audit.external.recon._probe_target",
        lambda probe_target: attempts_by_target[probe_target],
    )
    monkeypatch.setattr(
        "webconf_audit.external.recon._probe_error_pages",
        lambda successful_attempts: [],
    )
    monkeypatch.setattr(
        "webconf_audit.external.recon._probe_malformed_requests",
        lambda successful_attempts: [],
    )

    def fake_try_sensitive_path(probe_target: ProbeTarget) -> SensitivePathProbe:
        seen_paths.append(probe_target.path)
        return SensitivePathProbe(url=probe_target.url, path=probe_target.path, status_code=404)

    monkeypatch.setattr(
        "webconf_audit.external.recon._try_sensitive_path",
        fake_try_sensitive_path,
    )

    result = analyze_external_target("example.com")

    assert result.server_type is None
    assert "/server-status?auto" not in seen_paths
    assert all(
        probe["path"] != "/server-status?auto"
        for probe in result.metadata["sensitive_path_probes"]
    )


def test_sensitive_path_probes_in_metadata(monkeypatch) -> None:
    sp = SensitivePathProbe(
        url="https://example.com/.git/HEAD",
        path="/.git/HEAD",
        status_code=200,
        content_type="text/plain",
        body_snippet="ref: refs/heads/main",
    )
    probe_attempts = [
        _https_probe_with_headers(),
        _http_redirect_probe(),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts, sensitive_path_probes=[sp])
    meta_sp = result.metadata["sensitive_path_probes"]
    assert len(meta_sp) == 1
    assert meta_sp[0]["url"] == "https://example.com/.git/HEAD"
    assert meta_sp[0]["path"] == "/.git/HEAD"
    assert meta_sp[0]["status_code"] == 200
    assert meta_sp[0]["content_type"] == "text/plain"
    assert meta_sp[0]["body_snippet"] == "ref: refs/heads/main"
    assert meta_sp[0]["error_message"] is None


def test_sensitive_path_probes_empty_in_metadata(monkeypatch) -> None:
    probe_attempts = [
        _https_probe_with_headers(),
        _http_redirect_probe(),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    assert result.metadata["sensitive_path_probes"] == []


# ---------------------------------------------------------------------------
# external.git_metadata_exposed
# ---------------------------------------------------------------------------


def test_git_metadata_exposed_fires_on_ref_body(monkeypatch) -> None:
    sp = SensitivePathProbe(
        url="https://example.com/.git/HEAD",
        path="/.git/HEAD",
        status_code=200,
        content_type="text/plain",
        body_snippet="ref: refs/heads/main",
    )
    probe_attempts = [
        _https_probe_with_headers(),
        _http_redirect_probe(),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts, sensitive_path_probes=[sp])
    findings = [f for f in result.findings if f.rule_id == "external.git_metadata_exposed"]
    assert len(findings) == 1
    assert findings[0].location.target == "https://example.com/.git/HEAD"
    assert findings[0].location.details == "/.git/HEAD"


def test_git_metadata_exposed_does_not_fire_on_404(monkeypatch) -> None:
    sp = SensitivePathProbe(
        url="https://example.com/.git/HEAD",
        path="/.git/HEAD",
        status_code=404,
        content_type="text/html",
        body_snippet="Not Found",
    )
    probe_attempts = [
        _https_probe_with_headers(),
        _http_redirect_probe(),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts, sensitive_path_probes=[sp])
    assert "external.git_metadata_exposed" not in {f.rule_id for f in result.findings}


def test_git_metadata_exposed_does_not_fire_without_ref_body(monkeypatch) -> None:
    sp = SensitivePathProbe(
        url="https://example.com/.git/HEAD",
        path="/.git/HEAD",
        status_code=200,
        content_type="text/html",
        body_snippet="<html>Custom 200 page</html>",
    )
    probe_attempts = [
        _https_probe_with_headers(),
        _http_redirect_probe(),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts, sensitive_path_probes=[sp])
    assert "external.git_metadata_exposed" not in {f.rule_id for f in result.findings}


def test_git_metadata_exposed_does_not_fire_when_absent(monkeypatch) -> None:
    probe_attempts = [
        _https_probe_with_headers(),
        _http_redirect_probe(),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    assert "external.git_metadata_exposed" not in {f.rule_id for f in result.findings}


# ---------------------------------------------------------------------------
# external.server_status_exposed
# ---------------------------------------------------------------------------


def test_server_status_exposed_fires_on_200(monkeypatch) -> None:
    sp = SensitivePathProbe(
        url="https://example.com/server-status",
        path="/server-status",
        status_code=200,
        content_type="text/html",
        body_snippet="<html>Apache Status</html>",
    )
    probe_attempts = [
        _https_probe_with_headers(),
        _http_redirect_probe(),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts, sensitive_path_probes=[sp])
    findings = [f for f in result.findings if f.rule_id == "external.server_status_exposed"]
    assert len(findings) == 1
    assert findings[0].location.target == "https://example.com/server-status"


def test_server_status_exposed_fires_on_server_status_auto(monkeypatch) -> None:
    sp = SensitivePathProbe(
        url="https://example.com/server-status?auto",
        path="/server-status?auto",
        status_code=200,
        content_type="text/plain",
        body_snippet="Total Accesses: 1",
    )
    probe_attempts = [
        _https_probe_with_headers(server_header="Apache/2.4.58"),
        _http_redirect_probe(),
    ]
    result = _analyze_with_probe_attempts(
        monkeypatch,
        probe_attempts,
        sensitive_path_probes=[sp],
    )
    findings = [f for f in result.findings if f.rule_id == "external.server_status_exposed"]
    assert len(findings) == 1
    assert findings[0].location.target == "https://example.com/server-status?auto"
    assert findings[0].location.details == "/server-status?auto"


def test_server_status_exposed_does_not_fire_on_403(monkeypatch) -> None:
    sp = SensitivePathProbe(
        url="https://example.com/server-status",
        path="/server-status",
        status_code=403,
        content_type="text/html",
    )
    probe_attempts = [
        _https_probe_with_headers(),
        _http_redirect_probe(),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts, sensitive_path_probes=[sp])
    assert "external.server_status_exposed" not in {f.rule_id for f in result.findings}


def test_server_status_exposed_does_not_fire_on_server_status_auto_404(monkeypatch) -> None:
    sp = SensitivePathProbe(
        url="https://example.com/server-status?auto",
        path="/server-status?auto",
        status_code=404,
        content_type="text/plain",
    )
    probe_attempts = [
        _https_probe_with_headers(server_header="Apache/2.4.58"),
        _http_redirect_probe(),
    ]
    result = _analyze_with_probe_attempts(
        monkeypatch,
        probe_attempts,
        sensitive_path_probes=[sp],
    )
    assert "external.server_status_exposed" not in {f.rule_id for f in result.findings}


def test_server_status_exposed_does_not_fire_when_absent(monkeypatch) -> None:
    probe_attempts = [
        _https_probe_with_headers(),
        _http_redirect_probe(),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    assert "external.server_status_exposed" not in {f.rule_id for f in result.findings}


# ---------------------------------------------------------------------------
# external.server_info_exposed
# ---------------------------------------------------------------------------


def test_server_info_exposed_fires_on_200(monkeypatch) -> None:
    sp = SensitivePathProbe(
        url="https://example.com/server-info",
        path="/server-info",
        status_code=200,
        content_type="text/html",
    )
    probe_attempts = [
        _https_probe_with_headers(),
        _http_redirect_probe(),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts, sensitive_path_probes=[sp])
    findings = [f for f in result.findings if f.rule_id == "external.server_info_exposed"]
    assert len(findings) == 1
    assert findings[0].location.target == "https://example.com/server-info"


def test_server_info_exposed_does_not_fire_on_404(monkeypatch) -> None:
    sp = SensitivePathProbe(
        url="https://example.com/server-info",
        path="/server-info",
        status_code=404,
    )
    probe_attempts = [
        _https_probe_with_headers(),
        _http_redirect_probe(),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts, sensitive_path_probes=[sp])
    assert "external.server_info_exposed" not in {f.rule_id for f in result.findings}


# ---------------------------------------------------------------------------
# external.nginx_status_exposed
# ---------------------------------------------------------------------------


def test_nginx_status_exposed_fires_on_200(monkeypatch) -> None:
    sp = SensitivePathProbe(
        url="https://example.com/nginx_status",
        path="/nginx_status",
        status_code=200,
        content_type="text/plain",
        body_snippet="Active connections: 1",
    )
    probe_attempts = [
        _https_probe_with_headers(),
        _http_redirect_probe(),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts, sensitive_path_probes=[sp])
    findings = [f for f in result.findings if f.rule_id == "external.nginx_status_exposed"]
    assert len(findings) == 1
    assert findings[0].location.target == "https://example.com/nginx_status"


def test_nginx_status_exposed_does_not_fire_on_404(monkeypatch) -> None:
    sp = SensitivePathProbe(
        url="https://example.com/nginx_status",
        path="/nginx_status",
        status_code=404,
    )
    probe_attempts = [
        _https_probe_with_headers(),
        _http_redirect_probe(),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts, sensitive_path_probes=[sp])
    assert "external.nginx_status_exposed" not in {f.rule_id for f in result.findings}


# ---------------------------------------------------------------------------
# Expanded universal sensitive path rules (Phase 1.4.2)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("path", "rule_id", "content_type", "body_snippet"),
    [
        ("/.env", "external.env_file_exposed", "text/plain", "SECRET_KEY=abc123\nAPP_ENV=prod"),
        ("/.htaccess", "external.htaccess_exposed", "text/plain", "Deny from all"),
        ("/.htpasswd", "external.htpasswd_exposed", "text/plain", "admin:$apr1$example"),
        (
            "/wp-admin/",
            "external.wordpress_admin_panel_exposed",
            "text/html",
            "<title>Log In - WordPress</title>",
        ),
        (
            "/phpinfo.php",
            "external.phpinfo_exposed",
            "text/html",
            "<title>phpinfo()</title>",
        ),
        (
            "/elmah.axd",
            "external.elmah_axd_exposed",
            "text/html",
            "<html>Error Log for Application</html>",
        ),
        (
            "/trace.axd",
            "external.trace_axd_exposed",
            "text/html",
            "<html>Application Trace</html>",
        ),
        (
            "/web.config",
            "external.web_config_exposed",
            "application/xml",
            "<configuration><appSettings /></configuration>",
        ),
        ("/robots.txt", "external.robots_txt_exposed", "text/plain", "User-agent: *"),
        (
            "/sitemap.xml",
            "external.sitemap_xml_exposed",
            "application/xml",
            "<?xml version='1.0'?><urlset />",
        ),
        ("/.svn/entries", "external.svn_metadata_exposed", "text/plain", "12\n"),
    ],
)
def test_expanded_sensitive_path_rules_fire_on_accessible_match(
    monkeypatch,
    path: str,
    rule_id: str,
    content_type: str,
    body_snippet: str,
) -> None:
    sp = _sensitive_path_probe(
        path,
        status_code=200,
        content_type=content_type,
        body_snippet=body_snippet,
    )
    probe_attempts = [
        _https_probe_with_headers(),
        _http_redirect_probe(),
    ]

    result = _analyze_with_probe_attempts(
        monkeypatch,
        probe_attempts,
        sensitive_path_probes=[sp],
    )

    findings = [f for f in result.findings if f.rule_id == rule_id]
    assert len(findings) == 1
    assert findings[0].location.target == f"https://example.com{path}"
    assert findings[0].location.details == path


@pytest.mark.parametrize(
    ("path", "rule_id"),
    [
        ("/.env", "external.env_file_exposed"),
        ("/.htaccess", "external.htaccess_exposed"),
        ("/.htpasswd", "external.htpasswd_exposed"),
        ("/wp-admin/", "external.wordpress_admin_panel_exposed"),
        ("/phpinfo.php", "external.phpinfo_exposed"),
        ("/elmah.axd", "external.elmah_axd_exposed"),
        ("/trace.axd", "external.trace_axd_exposed"),
        ("/web.config", "external.web_config_exposed"),
        ("/robots.txt", "external.robots_txt_exposed"),
        ("/sitemap.xml", "external.sitemap_xml_exposed"),
        ("/.svn/entries", "external.svn_metadata_exposed"),
    ],
)
def test_expanded_sensitive_path_rules_do_not_fire_on_404(
    monkeypatch,
    path: str,
    rule_id: str,
) -> None:
    sp = _sensitive_path_probe(path, status_code=404, body_snippet="Not Found")
    probe_attempts = [
        _https_probe_with_headers(),
        _http_redirect_probe(),
    ]

    result = _analyze_with_probe_attempts(
        monkeypatch,
        probe_attempts,
        sensitive_path_probes=[sp],
    )

    assert rule_id not in {f.rule_id for f in result.findings}


@pytest.mark.parametrize(
    ("path", "rule_id", "body_snippet"),
    [
        ("/.env", "external.env_file_exposed", "<html>Custom page</html>"),
        ("/phpinfo.php", "external.phpinfo_exposed", "<html>PHP status</html>"),
        ("/web.config", "external.web_config_exposed", "<html>configuration</html>"),
    ],
)
def test_body_matched_sensitive_path_rules_require_expected_content(
    monkeypatch,
    path: str,
    rule_id: str,
    body_snippet: str,
) -> None:
    sp = _sensitive_path_probe(path, status_code=200, body_snippet=body_snippet)
    probe_attempts = [
        _https_probe_with_headers(),
        _http_redirect_probe(),
    ]

    result = _analyze_with_probe_attempts(
        monkeypatch,
        probe_attempts,
        sensitive_path_probes=[sp],
    )

    assert rule_id not in {f.rule_id for f in result.findings}


# ---------------------------------------------------------------------------
# No false positives from sensitive path rules on baseline probes
# ---------------------------------------------------------------------------


def test_no_sensitive_path_findings_on_baseline_probe(monkeypatch) -> None:
    probe_attempts = [
        _https_probe_with_headers(),
        _http_redirect_probe(),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    sensitive_rule_ids = {
        "external.git_metadata_exposed",
        "external.server_status_exposed",
        "external.server_info_exposed",
        "external.nginx_status_exposed",
        "external.env_file_exposed",
        "external.htaccess_exposed",
        "external.htpasswd_exposed",
        "external.wordpress_admin_panel_exposed",
        "external.phpinfo_exposed",
        "external.elmah_axd_exposed",
        "external.trace_axd_exposed",
        "external.web_config_exposed",
        "external.robots_txt_exposed",
        "external.sitemap_xml_exposed",
        "external.svn_metadata_exposed",
    }
    fired = sensitive_rule_ids & {f.rule_id for f in result.findings}
    assert fired == set()


def test_non_200_responses_do_not_trigger_sensitive_path_rules(monkeypatch) -> None:
    path_probes = [
        SensitivePathProbe(url="https://example.com/.git/HEAD", path="/.git/HEAD", status_code=404),
        SensitivePathProbe(url="https://example.com/server-status", path="/server-status", status_code=403),
        SensitivePathProbe(url="https://example.com/server-info", path="/server-info", status_code=500),
        SensitivePathProbe(url="https://example.com/nginx_status", path="/nginx_status", status_code=301),
        SensitivePathProbe(url="https://example.com/.env", path="/.env", status_code=404),
        SensitivePathProbe(url="https://example.com/.htaccess", path="/.htaccess", status_code=403),
        SensitivePathProbe(url="https://example.com/.htpasswd", path="/.htpasswd", status_code=404),
        SensitivePathProbe(url="https://example.com/wp-admin/", path="/wp-admin/", status_code=302),
        SensitivePathProbe(url="https://example.com/phpinfo.php", path="/phpinfo.php", status_code=404),
        SensitivePathProbe(url="https://example.com/elmah.axd", path="/elmah.axd", status_code=401),
        SensitivePathProbe(url="https://example.com/trace.axd", path="/trace.axd", status_code=403),
        SensitivePathProbe(url="https://example.com/web.config", path="/web.config", status_code=404),
        SensitivePathProbe(url="https://example.com/robots.txt", path="/robots.txt", status_code=304),
        SensitivePathProbe(url="https://example.com/sitemap.xml", path="/sitemap.xml", status_code=500),
        SensitivePathProbe(url="https://example.com/.svn/entries", path="/.svn/entries", status_code=404),
    ]
    probe_attempts = [
        _https_probe_with_headers(),
        _http_redirect_probe(),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts, sensitive_path_probes=path_probes)
    sensitive_rule_ids = {
        "external.git_metadata_exposed",
        "external.server_status_exposed",
        "external.server_info_exposed",
        "external.nginx_status_exposed",
        "external.env_file_exposed",
        "external.htaccess_exposed",
        "external.htpasswd_exposed",
        "external.wordpress_admin_panel_exposed",
        "external.phpinfo_exposed",
        "external.elmah_axd_exposed",
        "external.trace_axd_exposed",
        "external.web_config_exposed",
        "external.robots_txt_exposed",
        "external.sitemap_xml_exposed",
        "external.svn_metadata_exposed",
    }
    fired = sensitive_rule_ids & {f.rule_id for f in result.findings}
    assert fired == set()


# ---------------------------------------------------------------------------
# Server identification evidence tests
# ---------------------------------------------------------------------------


def test_server_identification_nginx_with_strong_evidence(monkeypatch) -> None:
    probe_attempts = [
        ProbeAttempt(
            target=ProbeTarget(scheme="https", host="example.com", port=443, path="/"),
            tcp_open=True,
            status_code=200,
            reason_phrase="OK",
            server_header="nginx/1.24.0",
            **_ALL_SECURITY_HEADERS,
        ),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)

    assert result.server_type == "nginx"
    ident = result.metadata["server_identification"]
    assert ident["server_type"] == "nginx"
    assert ident["confidence"] == "high"
    assert ident["ambiguous"] is False
    assert ident["candidate_server_types"] == ["nginx"]
    assert ident["evidence"][0]["source_url"] == "https://example.com/"
    assert ident["evidence"][0]["signal"] == "server_header"
    assert ident["evidence"][0]["indicates"] == "nginx"
    assert ident["evidence"][0]["strength"] == "strong"
    assert "probable_server_type: nginx" in result.diagnostics
    assert "identification_confidence: high" in result.diagnostics


def test_server_identification_apache_via_server_header(monkeypatch) -> None:
    probe_attempts = [
        ProbeAttempt(
            target=ProbeTarget(scheme="https", host="example.com", port=443, path="/"),
            tcp_open=True,
            status_code=200,
            reason_phrase="OK",
            server_header="Apache/2.4.58 (Ubuntu)",
            **_ALL_SECURITY_HEADERS,
        ),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)

    assert result.server_type == "apache"
    ident = result.metadata["server_identification"]
    assert ident["server_type"] == "apache"
    assert ident["confidence"] == "high"
    assert ident["ambiguous"] is False
    assert ident["candidate_server_types"] == ["apache"]
    assert ident["evidence"][0]["source_url"] == "https://example.com/"


def test_server_identification_iis_via_aspnet_headers(monkeypatch) -> None:
    probe_attempts = [
        ProbeAttempt(
            target=ProbeTarget(scheme="https", host="example.com", port=443, path="/"),
            tcp_open=True,
            status_code=200,
            reason_phrase="OK",
            x_powered_by_header="ASP.NET",
            x_aspnet_version_header="4.0.30319",
            **_ALL_SECURITY_HEADERS,
        ),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)

    assert result.server_type == "iis"
    ident = result.metadata["server_identification"]
    assert ident["server_type"] == "iis"
    assert ident["confidence"] == "medium"
    assert ident["ambiguous"] is False
    assert ident["candidate_server_types"] == ["iis"]
    assert len(ident["evidence"]) == 2
    assert {e["signal"] for e in ident["evidence"]} == {
        "x_powered_by_header",
        "x_aspnet_version_header",
    }
    assert {e["source_url"] for e in ident["evidence"]} == {"https://example.com/"}


def test_server_identification_unknown_with_no_evidence(monkeypatch) -> None:
    probe_attempts = [
        ProbeAttempt(
            target=ProbeTarget(scheme="https", host="example.com", port=443, path="/"),
            tcp_open=True,
            status_code=200,
            reason_phrase="OK",
            server_header="custom-edge",
            **_ALL_SECURITY_HEADERS,
        ),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)

    assert result.server_type is None
    ident = result.metadata["server_identification"]
    assert ident["server_type"] is None
    assert ident["confidence"] == "none"
    assert ident["evidence"] == []
    assert len(result.issues) == 1
    assert result.issues[0].code == "external_server_type_unknown"


def test_server_identification_openresty_maps_to_nginx(monkeypatch) -> None:
    probe_attempts = [
        ProbeAttempt(
            target=ProbeTarget(scheme="https", host="example.com", port=443, path="/"),
            tcp_open=True,
            status_code=200,
            reason_phrase="OK",
            server_header="openresty/1.21.4.1",
            **_ALL_SECURITY_HEADERS,
        ),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)

    assert result.server_type == "nginx"
    ident = result.metadata["server_identification"]
    assert ident["server_type"] == "nginx"
    assert ident["confidence"] == "high"
    assert ident["ambiguous"] is False


def test_server_identification_php_only_does_not_classify_apache(monkeypatch) -> None:
    probe_attempts = [
        ProbeAttempt(
            target=ProbeTarget(scheme="https", host="example.com", port=443, path="/"),
            tcp_open=True,
            status_code=200,
            reason_phrase="OK",
            x_powered_by_header="PHP/8.2.0",
            **_ALL_SECURITY_HEADERS,
        ),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)

    assert result.server_type is None
    ident = result.metadata["server_identification"]
    assert ident["server_type"] is None
    assert ident["confidence"] == "none"
    assert ident["ambiguous"] is False
    assert ident["candidate_server_types"] == []
    assert len(ident["evidence"]) == 1
    assert ident["evidence"][0]["source_url"] == "https://example.com/"
    assert ident["evidence"][0]["signal"] == "x_powered_by_header"
    assert ident["evidence"][0]["indicates"] is None
    assert ident["evidence"][0]["strength"] == "weak"
    assert len(result.issues) == 1
    assert result.issues[0].code == "external_server_type_unknown"


def test_server_identification_conflicting_https_and_http_evidence_is_ambiguous(
    monkeypatch,
) -> None:
    probe_attempts = [
        ProbeAttempt(
            target=ProbeTarget(scheme="https", host="example.com", port=443, path="/"),
            tcp_open=True,
            status_code=200,
            reason_phrase="OK",
            server_header="nginx/1.24.0",
            **_ALL_SECURITY_HEADERS,
        ),
        ProbeAttempt(
            target=ProbeTarget(scheme="http", host="example.com", port=80, path="/"),
            tcp_open=True,
            status_code=200,
            reason_phrase="OK",
            server_header="Apache/2.4.58",
            **_ALL_SECURITY_HEADERS,
        ),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)

    assert result.server_type is None
    ident = result.metadata["server_identification"]
    assert ident["server_type"] is None
    assert ident["confidence"] == "none"
    assert ident["ambiguous"] is True
    assert set(ident["candidate_server_types"]) == {"apache", "nginx"}
    assert {e["source_url"] for e in ident["evidence"]} == {
        "https://example.com/",
        "http://example.com/",
    }
    assert "identification_ambiguous: apache, nginx" in result.diagnostics
    assert len(result.issues) == 1
    assert result.issues[0].code == "external_server_type_ambiguous"


def test_server_identification_preserves_frontend_server_header_with_aspnet_headers(
    monkeypatch,
) -> None:
    probe_attempts = [
        ProbeAttempt(
            target=ProbeTarget(scheme="https", host="example.com", port=443, path="/"),
            tcp_open=True,
            status_code=200,
            reason_phrase="OK",
            server_header="Apache/2.4.58",
            x_powered_by_header="ASP.NET",
            x_aspnet_version_header="4.0.30319",
            **_ALL_SECURITY_HEADERS,
        ),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)

    assert result.server_type == "apache"
    ident = result.metadata["server_identification"]
    assert ident["server_type"] == "apache"
    assert ident["confidence"] == "high"
    assert ident["ambiguous"] is False
    assert ident["candidate_server_types"] == ["apache"]
    assert {e["source_url"] for e in ident["evidence"]} == {"https://example.com/"}
    assert {e["signal"] for e in ident["evidence"]} == {
        "server_header",
        "x_powered_by_header",
        "x_aspnet_version_header",
    }
    assert "probable_server_type: apache" in result.diagnostics
    assert "identification_confidence: high" in result.diagnostics
    assert result.issues == []


def test_server_identification_not_present_when_no_service(monkeypatch) -> None:
    probe_attempts = [
        ProbeAttempt(
            target=ProbeTarget(scheme="https", host="example.com", port=443, path="/"),
            tcp_open=False,
            error_message="TCP connection failed.",
        ),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    assert result.server_type is None
    assert "server_identification" not in result.metadata


# ---------------------------------------------------------------------------
# HSTS max-age too short
# ---------------------------------------------------------------------------


def test_hsts_max_age_too_short_fires_for_low_value(monkeypatch) -> None:
    probe_attempts = [
        ProbeAttempt(
            target=ProbeTarget(scheme="https", host="example.com", port=443, path="/"),
            tcp_open=True,
            status_code=200,
            reason_phrase="OK",
            server_header="nginx",
            strict_transport_security_header="max-age=3600",
            x_frame_options_header="DENY",
            x_content_type_options_header="nosniff",
            content_security_policy_header="default-src 'self'",
            referrer_policy_header="strict-origin-when-cross-origin",
            permissions_policy_header="geolocation=()",
        ),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    rule_ids = {f.rule_id for f in result.findings}
    assert "external.hsts_max_age_too_short" in rule_ids
    finding = next(f for f in result.findings if f.rule_id == "external.hsts_max_age_too_short")
    assert "3600" in finding.description
    assert finding.location.details is not None
    assert "max-age=3600" in finding.location.details


def test_hsts_max_age_not_short_when_one_year(monkeypatch) -> None:
    probe_attempts = [
        ProbeAttempt(
            target=ProbeTarget(scheme="https", host="example.com", port=443, path="/"),
            tcp_open=True,
            status_code=200,
            reason_phrase="OK",
            server_header="nginx",
            **_ALL_SECURITY_HEADERS,
        ),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    rule_ids = {f.rule_id for f in result.findings}
    assert "external.hsts_max_age_too_short" not in rule_ids


def test_hsts_max_age_not_short_when_header_missing(monkeypatch) -> None:
    probe_attempts = [
        ProbeAttempt(
            target=ProbeTarget(scheme="https", host="example.com", port=443, path="/"),
            tcp_open=True,
            status_code=200,
            reason_phrase="OK",
            server_header="nginx",
            x_frame_options_header="DENY",
            x_content_type_options_header="nosniff",
            content_security_policy_header="default-src 'self'",
            referrer_policy_header="strict-origin-when-cross-origin",
            permissions_policy_header="geolocation=()",
        ),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    rule_ids = {f.rule_id for f in result.findings}
    assert "external.hsts_max_age_too_short" not in rule_ids


# ---------------------------------------------------------------------------
# CSP unsafe-inline / unsafe-eval
# ---------------------------------------------------------------------------


def test_csp_unsafe_inline_fires(monkeypatch) -> None:
    probe_attempts = [
        ProbeAttempt(
            target=ProbeTarget(scheme="https", host="example.com", port=443, path="/"),
            tcp_open=True,
            status_code=200,
            reason_phrase="OK",
            server_header="nginx",
            strict_transport_security_header="max-age=31536000",
            x_frame_options_header="DENY",
            x_content_type_options_header="nosniff",
            content_security_policy_header="default-src 'self'; script-src 'unsafe-inline'",
            referrer_policy_header="strict-origin-when-cross-origin",
            permissions_policy_header="geolocation=()",
        ),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    rule_ids = {f.rule_id for f in result.findings}
    assert "external.content_security_policy_unsafe_inline" in rule_ids
    finding = next(f for f in result.findings if f.rule_id == "external.content_security_policy_unsafe_inline")
    assert "'unsafe-inline'" in finding.description
    assert finding.location.details is not None
    assert "Content-Security-Policy:" in finding.location.details


def test_csp_unsafe_eval_fires(monkeypatch) -> None:
    probe_attempts = [
        ProbeAttempt(
            target=ProbeTarget(scheme="https", host="example.com", port=443, path="/"),
            tcp_open=True,
            status_code=200,
            reason_phrase="OK",
            server_header="nginx",
            strict_transport_security_header="max-age=31536000",
            x_frame_options_header="DENY",
            x_content_type_options_header="nosniff",
            content_security_policy_header="default-src 'self'; script-src 'unsafe-eval'",
            referrer_policy_header="strict-origin-when-cross-origin",
            permissions_policy_header="geolocation=()",
        ),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    rule_ids = {f.rule_id for f in result.findings}
    assert "external.content_security_policy_unsafe_eval" in rule_ids


def test_csp_unsafe_inline_and_eval_both_fire(monkeypatch) -> None:
    probe_attempts = [
        ProbeAttempt(
            target=ProbeTarget(scheme="https", host="example.com", port=443, path="/"),
            tcp_open=True,
            status_code=200,
            reason_phrase="OK",
            server_header="nginx",
            strict_transport_security_header="max-age=31536000",
            x_frame_options_header="DENY",
            x_content_type_options_header="nosniff",
            content_security_policy_header="script-src 'unsafe-inline' 'unsafe-eval'",
            referrer_policy_header="strict-origin-when-cross-origin",
            permissions_policy_header="geolocation=()",
        ),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    rule_ids = {f.rule_id for f in result.findings}
    assert "external.content_security_policy_unsafe_inline" in rule_ids
    assert "external.content_security_policy_unsafe_eval" in rule_ids


def test_csp_safe_policy_does_not_fire_unsafe_rules(monkeypatch) -> None:
    probe_attempts = [
        ProbeAttempt(
            target=ProbeTarget(scheme="https", host="example.com", port=443, path="/"),
            tcp_open=True,
            status_code=200,
            reason_phrase="OK",
            server_header="nginx",
            **_ALL_SECURITY_HEADERS,
        ),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    rule_ids = {f.rule_id for f in result.findings}
    assert "external.content_security_policy_unsafe_inline" not in rule_ids
    assert "external.content_security_policy_unsafe_eval" not in rule_ids


def test_csp_missing_does_not_fire_unsafe_rules(monkeypatch) -> None:
    probe_attempts = [
        ProbeAttempt(
            target=ProbeTarget(scheme="https", host="example.com", port=443, path="/"),
            tcp_open=True,
            status_code=200,
            reason_phrase="OK",
            server_header="nginx",
            strict_transport_security_header="max-age=31536000",
            x_frame_options_header="DENY",
            x_content_type_options_header="nosniff",
            referrer_policy_header="strict-origin-when-cross-origin",
            permissions_policy_header="geolocation=()",
        ),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    rule_ids = {f.rule_id for f in result.findings}
    assert "external.content_security_policy_unsafe_inline" not in rule_ids
    assert "external.content_security_policy_unsafe_eval" not in rule_ids


# ---------------------------------------------------------------------------
# TLS certificate self-signed
# ---------------------------------------------------------------------------


def test_tls_self_signed_certificate_fires(monkeypatch) -> None:
    probe_attempts = [
        ProbeAttempt(
            target=ProbeTarget(scheme="https", host="example.com", port=443, path="/"),
            tcp_open=True,
            status_code=200,
            reason_phrase="OK",
            server_header="nginx",
            tls_info=TLSInfo(
                protocol_version="TLSv1.3",
                cert_subject="CN=example.com",
                cert_issuer="CN=example.com",
                cert_not_after="Dec 31 23:59:59 2027 GMT",
            ),
            **_ALL_SECURITY_HEADERS,
        ),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    rule_ids = {f.rule_id for f in result.findings}
    assert "external.tls_certificate_self_signed" in rule_ids
    finding = next(f for f in result.findings if f.rule_id == "external.tls_certificate_self_signed")
    assert finding.location.kind == "tls"
    assert finding.location.details is not None
    assert "CN=example.com" in finding.location.details


def test_tls_ca_signed_certificate_does_not_fire(monkeypatch) -> None:
    probe_attempts = [
        ProbeAttempt(
            target=ProbeTarget(scheme="https", host="example.com", port=443, path="/"),
            tcp_open=True,
            status_code=200,
            reason_phrase="OK",
            server_header="nginx",
            tls_info=TLSInfo(
                protocol_version="TLSv1.3",
                cert_subject="CN=example.com",
                cert_issuer="CN=Let's Encrypt Authority X3, O=Let's Encrypt, C=US",
                cert_not_after="Dec 31 23:59:59 2027 GMT",
            ),
            **_ALL_SECURITY_HEADERS,
        ),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    rule_ids = {f.rule_id for f in result.findings}
    assert "external.tls_certificate_self_signed" not in rule_ids


def test_tls_self_signed_not_fired_when_no_tls_info(monkeypatch) -> None:
    probe_attempts = [
        ProbeAttempt(
            target=ProbeTarget(scheme="https", host="example.com", port=443, path="/"),
            tcp_open=True,
            status_code=200,
            reason_phrase="OK",
            server_header="nginx",
            **_ALL_SECURITY_HEADERS,
        ),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    rule_ids = {f.rule_id for f in result.findings}
    assert "external.tls_certificate_self_signed" not in rule_ids


# ---------------------------------------------------------------------------
# Regression: malformed HSTS numeric-prefix
# ---------------------------------------------------------------------------


def test_hsts_malformed_numeric_prefix_does_not_fire_too_short(monkeypatch) -> None:
    """max-age=3600abc is malformed, not 'too short'."""
    probe_attempts = [
        ProbeAttempt(
            target=ProbeTarget(scheme="https", host="example.com", port=443, path="/"),
            tcp_open=True,
            status_code=200,
            reason_phrase="OK",
            server_header="nginx",
            strict_transport_security_header="max-age=3600abc",
            x_frame_options_header="DENY",
            x_content_type_options_header="nosniff",
            content_security_policy_header="default-src 'self'",
            referrer_policy_header="strict-origin-when-cross-origin",
            permissions_policy_header="geolocation=()",
        ),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    rule_ids = {f.rule_id for f in result.findings}
    # Malformed value should NOT trigger the too-short rule.
    assert "external.hsts_max_age_too_short" not in rule_ids
    # Malformed value SHOULD trigger the invalid-header rule.
    assert "external.hsts_header_invalid" in rule_ids


# ---------------------------------------------------------------------------
# Regression: CSP mixed-scheme intent
# ---------------------------------------------------------------------------


def test_csp_unsafe_inline_on_http_only_does_not_fire(monkeypatch) -> None:
    """CSP unsafe rules are HTTPS-only; HTTP-only unsafe CSP is not flagged."""
    probe_attempts = [
        ProbeAttempt(
            target=ProbeTarget(scheme="http", host="example.com", port=80, path="/"),
            tcp_open=True,
            status_code=200,
            reason_phrase="OK",
            server_header="nginx",
            content_security_policy_header="script-src 'unsafe-inline' 'unsafe-eval'",
        ),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    rule_ids = {f.rule_id for f in result.findings}
    assert "external.content_security_policy_unsafe_inline" not in rule_ids
    assert "external.content_security_policy_unsafe_eval" not in rule_ids


def test_csp_mixed_scheme_only_https_unsafe_fires(monkeypatch) -> None:
    """HTTPS with unsafe CSP fires; HTTP with unsafe CSP on same target does not."""
    probe_attempts = [
        ProbeAttempt(
            target=ProbeTarget(scheme="https", host="example.com", port=443, path="/"),
            tcp_open=True,
            status_code=200,
            reason_phrase="OK",
            server_header="nginx",
            strict_transport_security_header="max-age=31536000",
            x_frame_options_header="DENY",
            x_content_type_options_header="nosniff",
            content_security_policy_header="default-src 'self'",
            referrer_policy_header="strict-origin-when-cross-origin",
            permissions_policy_header="geolocation=()",
        ),
        ProbeAttempt(
            target=ProbeTarget(scheme="http", host="example.com", port=80, path="/"),
            tcp_open=True,
            status_code=200,
            reason_phrase="OK",
            server_header="nginx",
            content_security_policy_header="script-src 'unsafe-inline' 'unsafe-eval'",
        ),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    rule_ids = {f.rule_id for f in result.findings}
    # HTTPS endpoint has a safe CSP, so no unsafe findings from it.
    assert "external.content_security_policy_unsafe_inline" not in rule_ids
    assert "external.content_security_policy_unsafe_eval" not in rule_ids


# ---------------------------------------------------------------------------
# Regression: new findings coexist with server_identification metadata
# ---------------------------------------------------------------------------


def test_new_external_findings_coexist_with_server_identification(monkeypatch) -> None:
    """New external findings do not break or erase server_identification."""
    probe_attempts = [
        ProbeAttempt(
            target=ProbeTarget(scheme="https", host="example.com", port=443, path="/"),
            tcp_open=True,
            status_code=200,
            reason_phrase="OK",
            server_header="nginx/1.24.0",
            strict_transport_security_header="max-age=3600",
            x_frame_options_header="DENY",
            x_content_type_options_header="nosniff",
            content_security_policy_header="default-src 'self'; script-src 'unsafe-inline'",
            referrer_policy_header="strict-origin-when-cross-origin",
            permissions_policy_header="geolocation=()",
            tls_info=TLSInfo(
                protocol_version="TLSv1.3",
                cert_subject="CN=example.com",
                cert_issuer="CN=example.com",
                cert_not_after="Dec 31 23:59:59 2027 GMT",
            ),
        ),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)

    # Server identification is present and correct.
    assert result.server_type == "nginx"
    ident = result.metadata["server_identification"]
    assert ident["server_type"] == "nginx"
    assert ident["confidence"] == "high"
    assert "probable_server_type: nginx" in result.diagnostics
    assert "identification_confidence: high" in result.diagnostics

    # New findings fire alongside identification.
    rule_ids = {f.rule_id for f in result.findings}
    assert "external.hsts_max_age_too_short" in rule_ids
    assert "external.content_security_policy_unsafe_inline" in rule_ids
    assert "external.tls_certificate_self_signed" in rule_ids

    # Probe metadata is also preserved.
    assert "probe_attempts" in result.metadata
    assert len(result.metadata["probe_attempts"]) == 1


# ---------------------------------------------------------------------------
# HSTS missing includeSubDomains
# ---------------------------------------------------------------------------


def test_hsts_missing_include_subdomains_fires(monkeypatch) -> None:
    probe_attempts = [
        ProbeAttempt(
            target=ProbeTarget(scheme="https", host="example.com", port=443, path="/"),
            tcp_open=True,
            status_code=200,
            reason_phrase="OK",
            server_header="nginx",
            strict_transport_security_header="max-age=31536000",
            x_frame_options_header="DENY",
            x_content_type_options_header="nosniff",
            content_security_policy_header="default-src 'self'",
            referrer_policy_header="strict-origin-when-cross-origin",
            permissions_policy_header="geolocation=()",
        ),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    rule_ids = {f.rule_id for f in result.findings}
    assert "external.hsts_missing_include_subdomains" in rule_ids
    finding = next(f for f in result.findings if f.rule_id == "external.hsts_missing_include_subdomains")
    assert finding.location.details is not None
    assert "max-age=31536000" in finding.location.details


def test_hsts_with_include_subdomains_does_not_fire(monkeypatch) -> None:
    probe_attempts = [
        ProbeAttempt(
            target=ProbeTarget(scheme="https", host="example.com", port=443, path="/"),
            tcp_open=True,
            status_code=200,
            reason_phrase="OK",
            server_header="nginx",
            strict_transport_security_header="max-age=31536000; includeSubDomains",
            x_frame_options_header="DENY",
            x_content_type_options_header="nosniff",
            content_security_policy_header="default-src 'self'",
            referrer_policy_header="strict-origin-when-cross-origin",
            permissions_policy_header="geolocation=()",
        ),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    rule_ids = {f.rule_id for f in result.findings}
    assert "external.hsts_missing_include_subdomains" not in rule_ids


def test_hsts_include_subdomains_not_fired_when_hsts_invalid(monkeypatch) -> None:
    """Don't fire includeSubDomains rule when HSTS itself is invalid."""
    probe_attempts = [
        ProbeAttempt(
            target=ProbeTarget(scheme="https", host="example.com", port=443, path="/"),
            tcp_open=True,
            status_code=200,
            reason_phrase="OK",
            server_header="nginx",
            strict_transport_security_header="max-age=3600abc",
            x_frame_options_header="DENY",
            x_content_type_options_header="nosniff",
            content_security_policy_header="default-src 'self'",
            referrer_policy_header="strict-origin-when-cross-origin",
            permissions_policy_header="geolocation=()",
        ),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    rule_ids = {f.rule_id for f in result.findings}
    assert "external.hsts_missing_include_subdomains" not in rule_ids


def test_hsts_include_subdomains_not_fired_when_hsts_missing(monkeypatch) -> None:
    probe_attempts = [
        ProbeAttempt(
            target=ProbeTarget(scheme="https", host="example.com", port=443, path="/"),
            tcp_open=True,
            status_code=200,
            reason_phrase="OK",
            server_header="nginx",
            x_frame_options_header="DENY",
            x_content_type_options_header="nosniff",
            content_security_policy_header="default-src 'self'",
            referrer_policy_header="strict-origin-when-cross-origin",
            permissions_policy_header="geolocation=()",
        ),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    rule_ids = {f.rule_id for f in result.findings}
    assert "external.hsts_missing_include_subdomains" not in rule_ids


# ---------------------------------------------------------------------------
# HTTP redirect not permanent
# ---------------------------------------------------------------------------


def test_http_redirect_302_fires_not_permanent(monkeypatch) -> None:
    probe_attempts = [
        ProbeAttempt(
            target=ProbeTarget(scheme="https", host="example.com", port=443, path="/"),
            tcp_open=True,
            status_code=200,
            reason_phrase="OK",
            server_header="nginx",
            **_ALL_SECURITY_HEADERS,
        ),
        ProbeAttempt(
            target=ProbeTarget(scheme="http", host="example.com", port=80, path="/"),
            tcp_open=True,
            status_code=302,
            reason_phrase="Found",
            server_header="nginx",
            location_header="https://example.com/",
        ),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    rule_ids = {f.rule_id for f in result.findings}
    assert "external.http_redirect_not_permanent" in rule_ids
    # Should NOT also fire http_not_redirected_to_https — it is redirecting.
    assert "external.http_not_redirected_to_https" not in rule_ids
    finding = next(f for f in result.findings if f.rule_id == "external.http_redirect_not_permanent")
    assert "302" in finding.description
    assert finding.location.details is not None
    assert "302" in finding.location.details


def test_http_redirect_301_does_not_fire_not_permanent(monkeypatch) -> None:
    probe_attempts = [
        ProbeAttempt(
            target=ProbeTarget(scheme="https", host="example.com", port=443, path="/"),
            tcp_open=True,
            status_code=200,
            reason_phrase="OK",
            server_header="nginx",
            **_ALL_SECURITY_HEADERS,
        ),
        ProbeAttempt(
            target=ProbeTarget(scheme="http", host="example.com", port=80, path="/"),
            tcp_open=True,
            status_code=301,
            reason_phrase="Moved Permanently",
            server_header="nginx",
            location_header="https://example.com/",
        ),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    rule_ids = {f.rule_id for f in result.findings}
    assert "external.http_redirect_not_permanent" not in rule_ids


def test_http_redirect_308_does_not_fire_not_permanent(monkeypatch) -> None:
    probe_attempts = [
        ProbeAttempt(
            target=ProbeTarget(scheme="https", host="example.com", port=443, path="/"),
            tcp_open=True,
            status_code=200,
            reason_phrase="OK",
            server_header="nginx",
            **_ALL_SECURITY_HEADERS,
        ),
        ProbeAttempt(
            target=ProbeTarget(scheme="http", host="example.com", port=80, path="/"),
            tcp_open=True,
            status_code=308,
            reason_phrase="Permanent Redirect",
            server_header="nginx",
            location_header="https://example.com/",
        ),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    rule_ids = {f.rule_id for f in result.findings}
    assert "external.http_redirect_not_permanent" not in rule_ids


def test_http_no_redirect_does_not_fire_not_permanent(monkeypatch) -> None:
    """Non-redirecting HTTP does not trigger the redirect-permanence rule."""
    probe_attempts = [
        ProbeAttempt(
            target=ProbeTarget(scheme="http", host="example.com", port=80, path="/"),
            tcp_open=True,
            status_code=200,
            reason_phrase="OK",
            server_header="nginx",
        ),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    rule_ids = {f.rule_id for f in result.findings}
    assert "external.http_redirect_not_permanent" not in rule_ids


# ---------------------------------------------------------------------------
# Cookie SameSite=None without Secure
# ---------------------------------------------------------------------------


def test_cookie_samesite_none_without_secure_fires(monkeypatch) -> None:
    probe_attempts = [
        ProbeAttempt(
            target=ProbeTarget(scheme="https", host="example.com", port=443, path="/"),
            tcp_open=True,
            status_code=200,
            reason_phrase="OK",
            server_header="nginx",
            set_cookie_headers=("session_id=abc123; SameSite=None",),
            **_ALL_SECURITY_HEADERS,
        ),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    rule_ids = {f.rule_id for f in result.findings}
    assert "external.cookie_samesite_none_without_secure" in rule_ids
    finding = next(f for f in result.findings if f.rule_id == "external.cookie_samesite_none_without_secure")
    assert "session_id" in finding.description


def test_cookie_samesite_none_with_secure_does_not_fire(monkeypatch) -> None:
    probe_attempts = [
        ProbeAttempt(
            target=ProbeTarget(scheme="https", host="example.com", port=443, path="/"),
            tcp_open=True,
            status_code=200,
            reason_phrase="OK",
            server_header="nginx",
            set_cookie_headers=("session_id=abc123; SameSite=None; Secure",),
            **_ALL_SECURITY_HEADERS,
        ),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    rule_ids = {f.rule_id for f in result.findings}
    assert "external.cookie_samesite_none_without_secure" not in rule_ids


def test_cookie_samesite_lax_without_secure_does_not_fire(monkeypatch) -> None:
    """Only SameSite=None triggers this rule, not Lax or Strict."""
    probe_attempts = [
        ProbeAttempt(
            target=ProbeTarget(scheme="https", host="example.com", port=443, path="/"),
            tcp_open=True,
            status_code=200,
            reason_phrase="OK",
            server_header="nginx",
            set_cookie_headers=("session_id=abc123; SameSite=Lax",),
            **_ALL_SECURITY_HEADERS,
        ),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    rule_ids = {f.rule_id for f in result.findings}
    assert "external.cookie_samesite_none_without_secure" not in rule_ids


def test_cookie_samesite_none_on_non_session_cookie_does_not_fire(monkeypatch) -> None:
    """Non-session cookies are not checked."""
    probe_attempts = [
        ProbeAttempt(
            target=ProbeTarget(scheme="https", host="example.com", port=443, path="/"),
            tcp_open=True,
            status_code=200,
            reason_phrase="OK",
            server_header="nginx",
            set_cookie_headers=("theme=dark; SameSite=None",),
            **_ALL_SECURITY_HEADERS,
        ),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    rule_ids = {f.rule_id for f in result.findings}
    assert "external.cookie_samesite_none_without_secure" not in rule_ids


def test_cookie_samesite_none_mixed_scheme_only_fires_once(monkeypatch) -> None:
    """SameSite=None without Secure fires on the endpoint that set the cookie."""
    probe_attempts = [
        ProbeAttempt(
            target=ProbeTarget(scheme="https", host="example.com", port=443, path="/"),
            tcp_open=True,
            status_code=200,
            reason_phrase="OK",
            server_header="nginx",
            set_cookie_headers=("session_id=abc; SameSite=None; Secure",),
            **_ALL_SECURITY_HEADERS,
        ),
        ProbeAttempt(
            target=ProbeTarget(scheme="http", host="example.com", port=80, path="/"),
            tcp_open=True,
            status_code=200,
            reason_phrase="OK",
            server_header="nginx",
            set_cookie_headers=("session_id=abc; SameSite=None",),
        ),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    samesite_findings = [
        f for f in result.findings
        if f.rule_id == "external.cookie_samesite_none_without_secure"
    ]
    # Only the HTTP endpoint's cookie should fire (HTTPS one has Secure).
    assert len(samesite_findings) == 1
    assert "http://example.com/" in samesite_findings[0].location.target


# ---------------------------------------------------------------------------
# Regression: 307 temporary redirect must fire not-permanent
# ---------------------------------------------------------------------------


def test_http_redirect_307_fires_not_permanent(monkeypatch) -> None:
    """307 Temporary Redirect to HTTPS must trigger the not-permanent rule."""
    probe_attempts = [
        ProbeAttempt(
            target=ProbeTarget(scheme="https", host="example.com", port=443, path="/"),
            tcp_open=True,
            status_code=200,
            reason_phrase="OK",
            server_header="nginx",
            **_ALL_SECURITY_HEADERS,
        ),
        ProbeAttempt(
            target=ProbeTarget(scheme="http", host="example.com", port=80, path="/"),
            tcp_open=True,
            status_code=307,
            reason_phrase="Temporary Redirect",
            server_header="nginx",
            location_header="https://example.com/",
        ),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    rule_ids = {f.rule_id for f in result.findings}
    assert "external.http_redirect_not_permanent" in rule_ids
    assert "external.http_not_redirected_to_https" not in rule_ids


# ---------------------------------------------------------------------------
# Regression: malformed includeSubDomains must not count as present
# ---------------------------------------------------------------------------


def test_hsts_malformed_include_subdomains_fires(monkeypatch) -> None:
    """includeSubDomains=false is malformed and must not suppress the rule."""
    probe_attempts = [
        ProbeAttempt(
            target=ProbeTarget(scheme="https", host="example.com", port=443, path="/"),
            tcp_open=True,
            status_code=200,
            reason_phrase="OK",
            server_header="nginx",
            strict_transport_security_header="max-age=31536000; includeSubDomains=false",
            x_frame_options_header="DENY",
            x_content_type_options_header="nosniff",
            content_security_policy_header="default-src 'self'",
            referrer_policy_header="strict-origin-when-cross-origin",
            permissions_policy_header="geolocation=()",
        ),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    rule_ids = {f.rule_id for f in result.findings}
    assert "external.hsts_missing_include_subdomains" in rule_ids


# ---------------------------------------------------------------------------
# Regression: second-batch rules coexist with server_identification
# ---------------------------------------------------------------------------


def test_second_batch_rules_coexist_with_server_identification(monkeypatch) -> None:
    """New rules fire alongside traceable server identification metadata."""
    probe_attempts = [
        ProbeAttempt(
            target=ProbeTarget(scheme="https", host="example.com", port=443, path="/"),
            tcp_open=True,
            status_code=200,
            reason_phrase="OK",
            server_header="nginx/1.24.0",
            strict_transport_security_header="max-age=31536000",
            x_frame_options_header="DENY",
            x_content_type_options_header="nosniff",
            content_security_policy_header="default-src 'self'",
            referrer_policy_header="strict-origin-when-cross-origin",
            permissions_policy_header="geolocation=()",
            set_cookie_headers=("session_id=abc; SameSite=None",),
        ),
        ProbeAttempt(
            target=ProbeTarget(scheme="http", host="example.com", port=80, path="/"),
            tcp_open=True,
            status_code=302,
            reason_phrase="Found",
            server_header="nginx/1.24.0",
            location_header="https://example.com/",
        ),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)

    # Server identification is present and correct.
    assert result.server_type == "nginx"
    ident = result.metadata["server_identification"]
    assert ident["server_type"] == "nginx"
    assert ident["confidence"] == "high"
    assert "probable_server_type: nginx" in result.diagnostics

    # Second-batch rules fire.
    rule_ids = {f.rule_id for f in result.findings}
    assert "external.hsts_missing_include_subdomains" in rule_ids
    assert "external.http_redirect_not_permanent" in rule_ids
    assert "external.cookie_samesite_none_without_secure" in rule_ids


# ---------------------------------------------------------------------------
# Allow header dangerous methods (non-TRACE)
# ---------------------------------------------------------------------------


def test_allow_header_dangerous_methods_fires_for_put_delete(monkeypatch) -> None:
    probe_attempts = [
        ProbeAttempt(
            target=ProbeTarget(scheme="https", host="example.com", port=443, path="/"),
            tcp_open=True,
            status_code=200,
            reason_phrase="OK",
            server_header="nginx",
            allow_header="GET, HEAD, PUT, DELETE",
            **_ALL_SECURITY_HEADERS,
        ),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    rule_ids = {f.rule_id for f in result.findings}
    assert "external.allow_header_dangerous_methods" in rule_ids
    finding = next(
        f for f in result.findings
        if f.rule_id == "external.allow_header_dangerous_methods"
    )
    assert "PUT" in finding.description
    assert "DELETE" in finding.description
    assert finding.location.details is not None
    assert "Allow:" in finding.location.details


def test_allow_header_dangerous_methods_does_not_fire_for_safe_methods(monkeypatch) -> None:
    probe_attempts = [
        ProbeAttempt(
            target=ProbeTarget(scheme="https", host="example.com", port=443, path="/"),
            tcp_open=True,
            status_code=200,
            reason_phrase="OK",
            server_header="nginx",
            allow_header="GET, HEAD, POST, OPTIONS",
            **_ALL_SECURITY_HEADERS,
        ),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    rule_ids = {f.rule_id for f in result.findings}
    assert "external.allow_header_dangerous_methods" not in rule_ids


def test_allow_header_dangerous_methods_does_not_fire_for_trace_only(monkeypatch) -> None:
    """TRACE in Allow is covered by trace_method_allowed, not this rule."""
    probe_attempts = [
        ProbeAttempt(
            target=ProbeTarget(scheme="https", host="example.com", port=443, path="/"),
            tcp_open=True,
            status_code=200,
            reason_phrase="OK",
            server_header="nginx",
            allow_header="GET, HEAD, TRACE",
            **_ALL_SECURITY_HEADERS,
        ),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    rule_ids = {f.rule_id for f in result.findings}
    assert "external.allow_header_dangerous_methods" not in rule_ids
    assert "external.trace_method_allowed" in rule_ids


def test_allow_header_dangerous_methods_case_insensitive(monkeypatch) -> None:
    probe_attempts = [
        ProbeAttempt(
            target=ProbeTarget(scheme="https", host="example.com", port=443, path="/"),
            tcp_open=True,
            status_code=200,
            reason_phrase="OK",
            server_header="nginx",
            allow_header="get, head, put, connect",
            **_ALL_SECURITY_HEADERS,
        ),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    rule_ids = {f.rule_id for f in result.findings}
    assert "external.allow_header_dangerous_methods" in rule_ids


def test_allow_header_dangerous_methods_absent_allow_header(monkeypatch) -> None:
    probe_attempts = [
        ProbeAttempt(
            target=ProbeTarget(scheme="https", host="example.com", port=443, path="/"),
            tcp_open=True,
            status_code=200,
            reason_phrase="OK",
            server_header="nginx",
            **_ALL_SECURITY_HEADERS,
        ),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    rule_ids = {f.rule_id for f in result.findings}
    assert "external.allow_header_dangerous_methods" not in rule_ids


# ---------------------------------------------------------------------------
# WebDAV methods exposed
# ---------------------------------------------------------------------------


def test_webdav_methods_in_allow_header_fires(monkeypatch) -> None:
    probe_attempts = [
        ProbeAttempt(
            target=ProbeTarget(scheme="https", host="example.com", port=443, path="/"),
            tcp_open=True,
            status_code=200,
            reason_phrase="OK",
            server_header="nginx",
            allow_header="GET, HEAD, PROPFIND, MKCOL",
            **_ALL_SECURITY_HEADERS,
        ),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    rule_ids = {f.rule_id for f in result.findings}
    assert "external.webdav_methods_exposed" in rule_ids
    finding = next(
        f for f in result.findings
        if f.rule_id == "external.webdav_methods_exposed"
    )
    assert "PROPFIND" in finding.description
    assert "MKCOL" in finding.description
    assert "Allow" in finding.description


def test_webdav_methods_in_options_fires(monkeypatch) -> None:
    probe_attempts = [
        ProbeAttempt(
            target=ProbeTarget(scheme="https", host="example.com", port=443, path="/"),
            tcp_open=True,
            status_code=200,
            reason_phrase="OK",
            server_header="nginx",
            options_observation=OptionsObservation(
                status_code=200,
                allow_header="GET, HEAD, PROPFIND, COPY, MOVE",
            ),
            **_ALL_SECURITY_HEADERS,
        ),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    rule_ids = {f.rule_id for f in result.findings}
    assert "external.webdav_methods_exposed" in rule_ids
    finding = next(
        f for f in result.findings
        if f.rule_id == "external.webdav_methods_exposed"
    )
    assert "PROPFIND" in finding.description


def test_webdav_methods_not_fired_for_standard_methods(monkeypatch) -> None:
    probe_attempts = [
        ProbeAttempt(
            target=ProbeTarget(scheme="https", host="example.com", port=443, path="/"),
            tcp_open=True,
            status_code=200,
            reason_phrase="OK",
            server_header="nginx",
            allow_header="GET, HEAD, POST, OPTIONS",
            options_observation=OptionsObservation(
                status_code=200,
                allow_header="GET, HEAD, POST, OPTIONS",
            ),
            **_ALL_SECURITY_HEADERS,
        ),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    rule_ids = {f.rule_id for f in result.findings}
    assert "external.webdav_methods_exposed" not in rule_ids


def test_webdav_methods_absent_observations(monkeypatch) -> None:
    """No Allow header and no OPTIONS -> no WebDAV finding."""
    probe_attempts = [
        ProbeAttempt(
            target=ProbeTarget(scheme="https", host="example.com", port=443, path="/"),
            tcp_open=True,
            status_code=200,
            reason_phrase="OK",
            server_header="nginx",
            **_ALL_SECURITY_HEADERS,
        ),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    rule_ids = {f.rule_id for f in result.findings}
    assert "external.webdav_methods_exposed" not in rule_ids


def test_webdav_methods_case_insensitive(monkeypatch) -> None:
    probe_attempts = [
        ProbeAttempt(
            target=ProbeTarget(scheme="https", host="example.com", port=443, path="/"),
            tcp_open=True,
            status_code=200,
            reason_phrase="OK",
            server_header="nginx",
            allow_header="get, head, propfind, lock, unlock",
            **_ALL_SECURITY_HEADERS,
        ),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    rule_ids = {f.rule_id for f in result.findings}
    assert "external.webdav_methods_exposed" in rule_ids


def test_method_rules_coexist_with_identification(monkeypatch) -> None:
    """Method-exposure rules fire alongside traceable server identification."""
    probe_attempts = [
        ProbeAttempt(
            target=ProbeTarget(scheme="https", host="example.com", port=443, path="/"),
            tcp_open=True,
            status_code=200,
            reason_phrase="OK",
            server_header="Microsoft-IIS/10.0",
            allow_header="GET, HEAD, PUT, DELETE, PROPFIND, LOCK",
            options_observation=OptionsObservation(
                status_code=200,
                allow_header="GET, HEAD, PUT, DELETE, TRACE, PROPFIND, LOCK",
            ),
            **_ALL_SECURITY_HEADERS,
        ),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)

    # Server identification works.
    assert result.server_type == "iis"
    ident = result.metadata["server_identification"]
    assert ident["server_type"] == "iis"

    # Method rules fire.
    rule_ids = {f.rule_id for f in result.findings}
    assert "external.allow_header_dangerous_methods" in rule_ids
    assert "external.webdav_methods_exposed" in rule_ids
    assert "external.dangerous_http_methods_enabled" in rule_ids


# ---------------------------------------------------------------------------
# WebDAV via OPTIONS Public regression
# ---------------------------------------------------------------------------


def test_webdav_methods_via_options_public_fires(monkeypatch) -> None:
    """WebDAV methods exposed only through OPTIONS Public header."""
    probe_attempts = [
        ProbeAttempt(
            target=ProbeTarget(scheme="https", host="example.com", port=443, path="/"),
            tcp_open=True,
            status_code=200,
            reason_phrase="OK",
            server_header="Microsoft-IIS/10.0",
            options_observation=OptionsObservation(
                status_code=200,
                public_header="GET, HEAD, PROPFIND, LOCK, UNLOCK",
            ),
            **_ALL_SECURITY_HEADERS,
        ),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    rule_ids = {f.rule_id for f in result.findings}
    assert "external.webdav_methods_exposed" in rule_ids
    finding = next(
        f for f in result.findings
        if f.rule_id == "external.webdav_methods_exposed"
    )
    assert "PROPFIND" in finding.description
    assert "OPTIONS Public" in finding.description
    assert "OPTIONS Public" in finding.location.details


# ---------------------------------------------------------------------------
# Mixed HTTP/HTTPS method exposure regression
# ---------------------------------------------------------------------------


def test_mixed_scheme_method_exposure(monkeypatch) -> None:
    """HTTPS is clean, HTTP exposes dangerous methods - finding only on HTTP."""
    probe_attempts = [
        ProbeAttempt(
            target=ProbeTarget(scheme="https", host="example.com", port=443, path="/"),
            tcp_open=True,
            status_code=200,
            reason_phrase="OK",
            server_header="nginx",
            allow_header="GET, HEAD, POST",
            **_ALL_SECURITY_HEADERS,
        ),
        ProbeAttempt(
            target=ProbeTarget(scheme="http", host="example.com", port=80, path="/"),
            tcp_open=True,
            status_code=200,
            reason_phrase="OK",
            server_header="nginx",
            allow_header="GET, HEAD, PUT, DELETE, PROPFIND",
        ),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)

    dangerous_findings = [
        f for f in result.findings
        if f.rule_id == "external.allow_header_dangerous_methods"
    ]
    assert len(dangerous_findings) == 1
    assert "http://example.com/" in dangerous_findings[0].location.target

    webdav_findings = [
        f for f in result.findings
        if f.rule_id == "external.webdav_methods_exposed"
    ]
    assert len(webdav_findings) == 1
    assert "http://example.com/" in webdav_findings[0].location.target


# ---------------------------------------------------------------------------
# HEAD->GET fallback preserving Allow header with dangerous methods
# ---------------------------------------------------------------------------


def test_allow_header_dangerous_methods_via_head_get_fallback(monkeypatch) -> None:
    """Allow header preserved from HEAD 405 fallback triggers dangerous method rule.

    Simulates the real probe path: HEAD returns 405 with an Allow header
    containing dangerous methods, GET succeeds, and _preserve_head_allow_header
    copies the Allow value onto the final ProbeAttempt.
    """
    probe_attempts = [
        ProbeAttempt(
            target=ProbeTarget(scheme="https", host="example.com", port=443, path="/"),
            tcp_open=True,
            effective_method="GET",
            status_code=200,
            reason_phrase="OK",
            server_header="nginx",
            allow_header="GET, HEAD, PUT, DELETE, CONNECT",
            **_ALL_SECURITY_HEADERS,
        ),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    rule_ids = {f.rule_id for f in result.findings}
    assert "external.allow_header_dangerous_methods" in rule_ids
    finding = next(
        f for f in result.findings
        if f.rule_id == "external.allow_header_dangerous_methods"
    )
    assert "PUT" in finding.description
    assert "DELETE" in finding.description
    assert "CONNECT" in finding.description
    assert "Allow: GET, HEAD, PUT, DELETE, CONNECT" in finding.location.details


# ---------------------------------------------------------------------------
# --- TLS 1.0 supported rule (active probing) ---
# ---------------------------------------------------------------------------


def test_tls_1_0_supported_fires(monkeypatch) -> None:
    tls = TLSInfo(protocol_version="TLSv1.3", supported_protocols=("TLSv1", "TLSv1.2", "TLSv1.3"))
    probe_attempts = [_https_probe_with_headers(tls_info=tls), _http_redirect_probe()]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    assert "external.tls_1_0_supported" in {f.rule_id for f in result.findings}


def test_tls_1_0_supported_does_not_fire_when_absent(monkeypatch) -> None:
    tls = TLSInfo(protocol_version="TLSv1.3", supported_protocols=("TLSv1.2", "TLSv1.3"))
    probe_attempts = [_https_probe_with_headers(tls_info=tls), _http_redirect_probe()]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    assert "external.tls_1_0_supported" not in {f.rule_id for f in result.findings}


def test_tls_1_0_supported_does_not_fire_empty_protocols(monkeypatch) -> None:
    tls = TLSInfo(protocol_version="TLSv1.3", supported_protocols=())
    probe_attempts = [_https_probe_with_headers(tls_info=tls), _http_redirect_probe()]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    assert "external.tls_1_0_supported" not in {f.rule_id for f in result.findings}


# ---------------------------------------------------------------------------
# --- TLS 1.1 supported rule (active probing) ---
# ---------------------------------------------------------------------------


def test_tls_1_1_supported_fires(monkeypatch) -> None:
    tls = TLSInfo(protocol_version="TLSv1.3", supported_protocols=("TLSv1.1", "TLSv1.2", "TLSv1.3"))
    probe_attempts = [_https_probe_with_headers(tls_info=tls), _http_redirect_probe()]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    assert "external.tls_1_1_supported" in {f.rule_id for f in result.findings}


def test_tls_1_1_supported_does_not_fire_when_absent(monkeypatch) -> None:
    tls = TLSInfo(protocol_version="TLSv1.3", supported_protocols=("TLSv1.2", "TLSv1.3"))
    probe_attempts = [_https_probe_with_headers(tls_info=tls), _http_redirect_probe()]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    assert "external.tls_1_1_supported" not in {f.rule_id for f in result.findings}


def test_tls_1_1_supported_severity_is_medium(monkeypatch) -> None:
    tls = TLSInfo(protocol_version="TLSv1.3", supported_protocols=("TLSv1.1", "TLSv1.2"))
    probe_attempts = [_https_probe_with_headers(tls_info=tls), _http_redirect_probe()]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    finding = next(f for f in result.findings if f.rule_id == "external.tls_1_1_supported")
    assert finding.severity == "medium"


# ---------------------------------------------------------------------------
# --- TLS 1.3 not supported rule ---
# ---------------------------------------------------------------------------


def test_tls_1_3_not_supported_fires(monkeypatch) -> None:
    tls = TLSInfo(protocol_version="TLSv1.2", supported_protocols=("TLSv1.2",))
    probe_attempts = [_https_probe_with_headers(tls_info=tls), _http_redirect_probe()]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    assert "external.tls_1_3_not_supported" in {f.rule_id for f in result.findings}


def test_tls_1_3_not_supported_does_not_fire_when_supported(monkeypatch) -> None:
    tls = TLSInfo(protocol_version="TLSv1.3", supported_protocols=("TLSv1.2", "TLSv1.3"))
    probe_attempts = [_https_probe_with_headers(tls_info=tls), _http_redirect_probe()]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    assert "external.tls_1_3_not_supported" not in {f.rule_id for f in result.findings}


def test_tls_1_3_not_supported_skips_empty_protocols(monkeypatch) -> None:
    """When active probing did not run, do not fire this rule."""
    tls = TLSInfo(protocol_version="TLSv1.2", supported_protocols=())
    probe_attempts = [_https_probe_with_headers(tls_info=tls), _http_redirect_probe()]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    assert "external.tls_1_3_not_supported" not in {f.rule_id for f in result.findings}


def test_tls_1_3_not_supported_severity_is_low(monkeypatch) -> None:
    tls = TLSInfo(protocol_version="TLSv1.2", supported_protocols=("TLSv1.2",))
    probe_attempts = [_https_probe_with_headers(tls_info=tls), _http_redirect_probe()]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    finding = next(f for f in result.findings if f.rule_id == "external.tls_1_3_not_supported")
    assert finding.severity == "low"


# ---------------------------------------------------------------------------
# --- Weak cipher suite rule ---
# ---------------------------------------------------------------------------


def test_weak_cipher_fires_for_rc4(monkeypatch) -> None:
    tls = TLSInfo(protocol_version="TLSv1.2", cipher_name="RC4-SHA")
    probe_attempts = [_https_probe_with_headers(tls_info=tls), _http_redirect_probe()]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    assert "external.weak_cipher_suite" in {f.rule_id for f in result.findings}


def test_weak_cipher_fires_for_des(monkeypatch) -> None:
    tls = TLSInfo(protocol_version="TLSv1.2", cipher_name="DES-CBC3-SHA")
    probe_attempts = [_https_probe_with_headers(tls_info=tls), _http_redirect_probe()]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    rule_ids = {f.rule_id for f in result.findings}
    assert "external.weak_cipher_suite" in rule_ids


def test_weak_cipher_fires_for_null(monkeypatch) -> None:
    tls = TLSInfo(protocol_version="TLSv1.2", cipher_name="NULL-SHA256")
    probe_attempts = [_https_probe_with_headers(tls_info=tls), _http_redirect_probe()]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    assert "external.weak_cipher_suite" in {f.rule_id for f in result.findings}


def test_weak_cipher_fires_for_export(monkeypatch) -> None:
    tls = TLSInfo(protocol_version="TLSv1.2", cipher_name="EXP-RC4-MD5")
    probe_attempts = [_https_probe_with_headers(tls_info=tls), _http_redirect_probe()]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    rule_ids = {f.rule_id for f in result.findings}
    assert "external.weak_cipher_suite" in rule_ids


def test_weak_cipher_does_not_fire_for_aes_gcm(monkeypatch) -> None:
    tls = TLSInfo(protocol_version="TLSv1.3", cipher_name="TLS_AES_256_GCM_SHA384")
    probe_attempts = [_https_probe_with_headers(tls_info=tls), _http_redirect_probe()]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    assert "external.weak_cipher_suite" not in {f.rule_id for f in result.findings}


def test_weak_cipher_does_not_fire_for_chacha20(monkeypatch) -> None:
    tls = TLSInfo(protocol_version="TLSv1.3", cipher_name="TLS_CHACHA20_POLY1305_SHA256")
    probe_attempts = [_https_probe_with_headers(tls_info=tls), _http_redirect_probe()]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    assert "external.weak_cipher_suite" not in {f.rule_id for f in result.findings}


def test_weak_cipher_does_not_fire_when_cipher_absent(monkeypatch) -> None:
    tls = TLSInfo(protocol_version="TLSv1.3")
    probe_attempts = [_https_probe_with_headers(tls_info=tls), _http_redirect_probe()]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    assert "external.weak_cipher_suite" not in {f.rule_id for f in result.findings}


def test_weak_cipher_description_lists_matched_keywords(monkeypatch) -> None:
    tls = TLSInfo(protocol_version="TLSv1.2", cipher_name="EXP-RC4-MD5")
    probe_attempts = [_https_probe_with_headers(tls_info=tls), _http_redirect_probe()]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    finding = next(f for f in result.findings if f.rule_id == "external.weak_cipher_suite")
    assert "RC4" in finding.description
    assert "EXP" in finding.description
    assert "MD5" in finding.description


# ---------------------------------------------------------------------------
# --- Certificate chain incomplete rule ---
# ---------------------------------------------------------------------------


def test_cert_chain_incomplete_fires(monkeypatch) -> None:
    tls = TLSInfo(
        protocol_version="TLSv1.3",
        cert_chain_complete=False,
        cert_chain_error="certificate verify failed: unable to get local issuer certificate",
    )
    probe_attempts = [_https_probe_with_headers(tls_info=tls), _http_redirect_probe()]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    assert "external.cert_chain_incomplete" in {f.rule_id for f in result.findings}


def test_cert_chain_incomplete_does_not_fire_when_verified(monkeypatch) -> None:
    tls = TLSInfo(protocol_version="TLSv1.3", cert_chain_complete=True)
    probe_attempts = [_https_probe_with_headers(tls_info=tls), _http_redirect_probe()]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    assert "external.cert_chain_incomplete" not in {f.rule_id for f in result.findings}


def test_cert_chain_incomplete_skips_when_none(monkeypatch) -> None:
    """When chain verification did not run, do not fire."""
    tls = TLSInfo(protocol_version="TLSv1.3", cert_chain_complete=None)
    probe_attempts = [_https_probe_with_headers(tls_info=tls), _http_redirect_probe()]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    assert "external.cert_chain_incomplete" not in {f.rule_id for f in result.findings}


def test_cert_chain_incomplete_includes_error_in_description(monkeypatch) -> None:
    tls = TLSInfo(
        protocol_version="TLSv1.3",
        cert_chain_complete=False,
        cert_chain_error="self-signed certificate",
    )
    probe_attempts = [_https_probe_with_headers(tls_info=tls), _http_redirect_probe()]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    finding = next(f for f in result.findings if f.rule_id == "external.cert_chain_incomplete")
    assert "self-signed certificate" in finding.description


def test_cert_chain_incomplete_does_not_fire_on_indeterminate(monkeypatch) -> None:
    """When chain verification is indeterminate (None), do not fire."""
    tls = TLSInfo(protocol_version="TLSv1.3", cert_chain_complete=None)
    probe_attempts = [_https_probe_with_headers(tls_info=tls), _http_redirect_probe()]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    assert "external.cert_chain_incomplete" not in {f.rule_id for f in result.findings}


def test_cert_chain_incomplete_does_not_overlap_with_san_mismatch(monkeypatch) -> None:
    """SAN mismatch with a valid trust chain should NOT trigger cert_chain_incomplete.

    This verifies that verify_certificate_chain uses check_hostname=False,
    so hostname mismatch alone does not produce a false chain_incomplete finding.
    """
    tls = TLSInfo(
        protocol_version="TLSv1.3",
        cert_san=("other.com",),
        cert_chain_complete=True,  # chain is fine, hostname mismatches
    )
    probe_attempts = [_https_probe_with_headers(tls_info=tls), _http_redirect_probe()]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts, target="example.com")
    rule_ids = {f.rule_id for f in result.findings}
    assert "external.cert_san_mismatch" in rule_ids
    assert "external.cert_chain_incomplete" not in rule_ids


def test_cert_chain_incomplete_does_not_fire_on_expired_cert(monkeypatch) -> None:
    """An expired certificate should fire certificate_expired but NOT cert_chain_incomplete.

    Expired leaf certs are a validity issue, not a chain-completeness issue.
    verify_certificate_chain treats expiry as indeterminate (cert_chain_complete=None).
    """
    tls = TLSInfo(
        protocol_version="TLSv1.3",
        cert_not_after="Jan  1 00:00:00 2020 GMT",
        cert_subject="commonName=example.com",
        cert_issuer="commonName=Test CA",
        cert_chain_complete=None,  # expired → indeterminate for chain
    )
    probe_attempts = [_https_probe_with_headers(tls_info=tls), _http_redirect_probe()]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    rule_ids = {f.rule_id for f in result.findings}
    assert "external.certificate_expired" in rule_ids
    assert "external.cert_chain_incomplete" not in rule_ids


# ---------------------------------------------------------------------------
# --- Certificate chain length unusual rule ---
# ---------------------------------------------------------------------------


def test_cert_chain_length_unusual_fires_for_leaf_only(monkeypatch) -> None:
    """depth=1 (leaf-only, no intermediates) must fire the rule."""
    tls = TLSInfo(protocol_version="TLSv1.3", cert_chain_depth=1)
    probe_attempts = [_https_probe_with_headers(tls_info=tls), _http_redirect_probe()]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    rule_ids = {f.rule_id for f in result.findings}
    assert "external.cert_chain_length_unusual" in rule_ids


def test_cert_chain_length_unusual_leaf_only_description(monkeypatch) -> None:
    """depth=1 finding description must mention 'intermediate'."""
    tls = TLSInfo(protocol_version="TLSv1.3", cert_chain_depth=1)
    probe_attempts = [_https_probe_with_headers(tls_info=tls), _http_redirect_probe()]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    finding = next(f for f in result.findings if f.rule_id == "external.cert_chain_length_unusual")
    assert "intermediate" in finding.description.lower()


def test_cert_chain_length_unusual_fires_for_depth_five(monkeypatch) -> None:
    """depth=5 exceeds max of 4 — rule must fire."""
    tls = TLSInfo(protocol_version="TLSv1.3", cert_chain_depth=5)
    probe_attempts = [_https_probe_with_headers(tls_info=tls), _http_redirect_probe()]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    rule_ids = {f.rule_id for f in result.findings}
    assert "external.cert_chain_length_unusual" in rule_ids


def test_cert_chain_length_unusual_long_chain_description(monkeypatch) -> None:
    """depth > max finding description must mention depth value."""
    tls = TLSInfo(protocol_version="TLSv1.3", cert_chain_depth=6)
    probe_attempts = [_https_probe_with_headers(tls_info=tls), _http_redirect_probe()]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    finding = next(f for f in result.findings if f.rule_id == "external.cert_chain_length_unusual")
    assert "6" in finding.description


def test_cert_chain_length_unusual_does_not_fire_for_depth_two(monkeypatch) -> None:
    """depth=2 (leaf + one intermediate) is normal — rule must not fire."""
    tls = TLSInfo(protocol_version="TLSv1.3", cert_chain_depth=2)
    probe_attempts = [_https_probe_with_headers(tls_info=tls), _http_redirect_probe()]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    rule_ids = {f.rule_id for f in result.findings}
    assert "external.cert_chain_length_unusual" not in rule_ids


def test_cert_chain_length_unusual_does_not_fire_for_depth_three(monkeypatch) -> None:
    """depth=3 is within normal range — rule must not fire."""
    tls = TLSInfo(protocol_version="TLSv1.3", cert_chain_depth=3)
    probe_attempts = [_https_probe_with_headers(tls_info=tls), _http_redirect_probe()]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    rule_ids = {f.rule_id for f in result.findings}
    assert "external.cert_chain_length_unusual" not in rule_ids


def test_cert_chain_length_unusual_does_not_fire_for_depth_four(monkeypatch) -> None:
    """depth=4 is at the boundary (allowed) — rule must not fire."""
    tls = TLSInfo(protocol_version="TLSv1.3", cert_chain_depth=4)
    probe_attempts = [_https_probe_with_headers(tls_info=tls), _http_redirect_probe()]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    rule_ids = {f.rule_id for f in result.findings}
    assert "external.cert_chain_length_unusual" not in rule_ids


def test_cert_chain_length_unusual_skips_when_none(monkeypatch) -> None:
    """depth=None (probe failed) must not fire the rule."""
    tls = TLSInfo(protocol_version="TLSv1.3", cert_chain_depth=None)
    probe_attempts = [_https_probe_with_headers(tls_info=tls), _http_redirect_probe()]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    rule_ids = {f.rule_id for f in result.findings}
    assert "external.cert_chain_length_unusual" not in rule_ids


def test_cert_chain_length_unusual_severity_is_low(monkeypatch) -> None:
    """Rule severity must be 'low' (informational misconfiguration signal)."""
    tls = TLSInfo(protocol_version="TLSv1.3", cert_chain_depth=1)
    probe_attempts = [_https_probe_with_headers(tls_info=tls), _http_redirect_probe()]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    finding = next(f for f in result.findings if f.rule_id == "external.cert_chain_length_unusual")
    assert finding.severity == "low"


def test_cert_chain_length_unusual_does_not_fire_for_depth_zero(monkeypatch) -> None:
    """depth=0 (no certs received, indeterminate) must not fire."""
    tls = TLSInfo(protocol_version="TLSv1.3", cert_chain_depth=0)
    probe_attempts = [_https_probe_with_headers(tls_info=tls), _http_redirect_probe()]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    rule_ids = {f.rule_id for f in result.findings}
    assert "external.cert_chain_length_unusual" not in rule_ids


def test_no_duplicate_tls_legacy_and_active_probe_findings(monkeypatch) -> None:
    """The removed external.tls_legacy_protocol must never appear in findings."""
    tls = TLSInfo(
        protocol_version="TLSv1",
        supported_protocols=("TLSv1", "TLSv1.2"),
    )
    probe_attempts = [_https_probe_with_headers(tls_info=tls), _http_redirect_probe()]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    rule_ids = {f.rule_id for f in result.findings}
    assert "external.tls_legacy_protocol" not in rule_ids
    assert "external.tls_1_0_supported" in rule_ids


# ---------------------------------------------------------------------------
# --- Certificate SAN mismatch rule ---
# ---------------------------------------------------------------------------


def test_cert_san_mismatch_fires(monkeypatch) -> None:
    tls = TLSInfo(protocol_version="TLSv1.3", cert_san=("other.com", "www.other.com"))
    probe_attempts = [_https_probe_with_headers(tls_info=tls), _http_redirect_probe()]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts, target="example.com")
    assert "external.cert_san_mismatch" in {f.rule_id for f in result.findings}


def test_cert_san_mismatch_does_not_fire_exact_match(monkeypatch) -> None:
    tls = TLSInfo(protocol_version="TLSv1.3", cert_san=("example.com", "www.example.com"))
    probe_attempts = [_https_probe_with_headers(tls_info=tls), _http_redirect_probe()]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts, target="example.com")
    assert "external.cert_san_mismatch" not in {f.rule_id for f in result.findings}


def test_cert_san_mismatch_does_not_fire_wildcard_match(monkeypatch) -> None:
    tls = TLSInfo(protocol_version="TLSv1.3", cert_san=("*.example.com",))
    probe_attempts = [_https_probe_with_headers(tls_info=tls), _http_redirect_probe()]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts, target="www.example.com")
    assert "external.cert_san_mismatch" not in {f.rule_id for f in result.findings}


def test_cert_san_mismatch_wildcard_does_not_match_apex(monkeypatch) -> None:
    """*.example.com should NOT match example.com itself."""
    tls = TLSInfo(protocol_version="TLSv1.3", cert_san=("*.example.com",))
    probe_attempts = [_https_probe_with_headers(tls_info=tls), _http_redirect_probe()]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts, target="example.com")
    assert "external.cert_san_mismatch" in {f.rule_id for f in result.findings}


def test_cert_san_mismatch_wildcard_does_not_match_nested(monkeypatch) -> None:
    """*.example.com should NOT match a.b.example.com."""
    tls = TLSInfo(protocol_version="TLSv1.3", cert_san=("*.example.com",))
    probe_attempts = [_https_probe_with_headers(tls_info=tls), _http_redirect_probe()]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts, target="a.b.example.com")
    assert "external.cert_san_mismatch" in {f.rule_id for f in result.findings}


def test_cert_san_mismatch_case_insensitive(monkeypatch) -> None:
    tls = TLSInfo(protocol_version="TLSv1.3", cert_san=("Example.COM",))
    probe_attempts = [_https_probe_with_headers(tls_info=tls), _http_redirect_probe()]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts, target="example.com")
    assert "external.cert_san_mismatch" not in {f.rule_id for f in result.findings}


def test_cert_san_mismatch_skips_empty_san(monkeypatch) -> None:
    """When SAN list is empty, do not fire (no data to compare)."""
    tls = TLSInfo(protocol_version="TLSv1.3", cert_san=())
    probe_attempts = [_https_probe_with_headers(tls_info=tls), _http_redirect_probe()]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts, target="example.com")
    assert "external.cert_san_mismatch" not in {f.rule_id for f in result.findings}


def test_cert_san_mismatch_with_url_target(monkeypatch) -> None:
    """When target is a full URL, hostname is extracted correctly."""
    tls = TLSInfo(protocol_version="TLSv1.3", cert_san=("other.com",))
    probe_attempts = [_https_probe_with_headers(tls_info=tls)]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts, target="https://example.com/path")
    assert "external.cert_san_mismatch" in {f.rule_id for f in result.findings}


def test_cert_san_mismatch_with_host_port_target(monkeypatch) -> None:
    """When target is host:port, hostname is extracted correctly."""
    tls = TLSInfo(protocol_version="TLSv1.3", cert_san=("other.com",))
    probe_attempts = [_https_probe_with_headers(tls_info=tls)]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts, target="example.com:8443")
    assert "external.cert_san_mismatch" in {f.rule_id for f in result.findings}


def test_cert_san_mismatch_skips_ip_literal_targets(monkeypatch) -> None:
    tls = TLSInfo(protocol_version="TLSv1.3", cert_san=("example.com",))
    probe_attempts = [_https_probe_with_headers(tls_info=tls)]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts, target="192.0.2.10")
    assert "external.cert_san_mismatch" not in {f.rule_id for f in result.findings}


# ---------------------------------------------------------------------------
# --- _hostname_matches_san unit tests ---
# ---------------------------------------------------------------------------


def test_hostname_matches_san_exact() -> None:
    assert hostname_matches_san("example.com", ("example.com",)) is True


def test_hostname_matches_san_case_insensitive() -> None:
    assert hostname_matches_san("example.com", ("EXAMPLE.COM",)) is True


def test_hostname_matches_san_normalizes_hostname_case() -> None:
    assert hostname_matches_san("WWW.Example.com", ("*.example.com",)) is True


def test_hostname_matches_san_wildcard_one_level() -> None:
    assert hostname_matches_san("www.example.com", ("*.example.com",)) is True


def test_hostname_matches_san_wildcard_does_not_match_apex() -> None:
    assert hostname_matches_san("example.com", ("*.example.com",)) is False


def test_hostname_matches_san_wildcard_does_not_match_nested() -> None:
    assert hostname_matches_san("a.b.example.com", ("*.example.com",)) is False


def test_hostname_matches_san_no_match() -> None:
    assert hostname_matches_san("evil.com", ("example.com", "*.example.com")) is False


def test_hostname_matches_san_empty_entries() -> None:
    assert hostname_matches_san("example.com", ()) is False


def test_hostname_matches_san_multiple_entries() -> None:
    assert hostname_matches_san("api.example.com", ("example.com", "*.example.com")) is True


def test_parse_cert_date_returns_utc_for_gmt_timestamp() -> None:
    parsed = _parse_cert_date("Mar 15 12:00:00 2026 GMT")
    assert parsed is not None
    assert parsed.tzinfo == timezone.utc
    assert parsed.isoformat() == "2026-03-15T12:00:00+00:00"


def test_parse_cert_date_rejects_unknown_timezone() -> None:
    assert _parse_cert_date("Mar 15 12:00:00 2026 PST") is None


# ---------------------------------------------------------------------------
# --- Combination / edge-case tests for 1.2 block ---
# ---------------------------------------------------------------------------


def test_tls_1_0_and_1_1_both_fire(monkeypatch) -> None:
    """When both TLS 1.0 and 1.1 are supported, both rules fire."""
    tls = TLSInfo(
        protocol_version="TLSv1.3",
        supported_protocols=("TLSv1", "TLSv1.1", "TLSv1.2", "TLSv1.3"),
    )
    probe_attempts = [_https_probe_with_headers(tls_info=tls), _http_redirect_probe()]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    rule_ids = {f.rule_id for f in result.findings}
    assert "external.tls_1_0_supported" in rule_ids
    assert "external.tls_1_1_supported" in rule_ids
    assert "external.tls_1_3_not_supported" not in rule_ids


def test_weak_cipher_adh_no_anon_keyword(monkeypatch) -> None:
    """ADH cipher name doesn't literally contain 'anon', verify no false positive."""
    tls = TLSInfo(protocol_version="TLSv1.2", cipher_name="ADH-AES256-SHA")
    probe_attempts = [_https_probe_with_headers(tls_info=tls), _http_redirect_probe()]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    assert "external.weak_cipher_suite" not in {f.rule_id for f in result.findings}


def test_weak_cipher_null_in_name(monkeypatch) -> None:
    """AECDH-NULL-SHA contains NULL keyword."""
    tls = TLSInfo(protocol_version="TLSv1.2", cipher_name="AECDH-NULL-SHA")
    probe_attempts = [_https_probe_with_headers(tls_info=tls), _http_redirect_probe()]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    assert "external.weak_cipher_suite" in {f.rule_id for f in result.findings}


def test_chain_incomplete_and_san_mismatch_both_fire(monkeypatch) -> None:
    """Multiple TLS issues on the same endpoint should all fire."""
    tls = TLSInfo(
        protocol_version="TLSv1.3",
        cert_san=("other.com",),
        cert_chain_complete=False,
        cert_chain_error="self-signed certificate",
    )
    probe_attempts = [_https_probe_with_headers(tls_info=tls), _http_redirect_probe()]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts, target="example.com")
    rule_ids = {f.rule_id for f in result.findings}
    assert "external.cert_chain_incomplete" in rule_ids
    assert "external.cert_san_mismatch" in rule_ids


def test_tls_info_default_values() -> None:
    """Verify all new TLSInfo fields have correct defaults."""
    tls = TLSInfo()
    assert tls.cipher_name is None
    assert tls.cipher_bits is None
    assert tls.cipher_protocol is None
    assert tls.cert_san == ()
    assert tls.supported_protocols == ()
    assert tls.cert_chain_complete is None
    assert tls.cert_chain_error is None


def test_tls_info_metadata_includes_all_new_fields(monkeypatch) -> None:
    """Metadata dict for TLSInfo should contain all 1.2 fields."""
    tls = TLSInfo(
        protocol_version="TLSv1.3",
        cipher_name="TLS_AES_256_GCM_SHA384",
        cipher_bits=256,
        cipher_protocol="TLSv1.3",
        cert_san=("example.com", "www.example.com"),
        supported_protocols=("TLSv1.2", "TLSv1.3"),
        cert_chain_complete=True,
        cert_chain_error=None,
    )
    probe_attempts = [_https_probe_with_headers(tls_info=tls), _http_redirect_probe()]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    tls_meta = result.metadata["probe_attempts"][0]["tls_info"]
    assert tls_meta["cipher_name"] == "TLS_AES_256_GCM_SHA384"
    assert tls_meta["cipher_bits"] == 256
    assert tls_meta["cipher_protocol"] == "TLSv1.3"
    assert tls_meta["cert_san"] == ["example.com", "www.example.com"]
    assert tls_meta["supported_protocols"] == ["TLSv1.2", "TLSv1.3"]
    assert tls_meta["cert_chain_complete"] is True
    assert tls_meta["cert_chain_error"] is None


def test_no_tls_rules_fire_for_http_only(monkeypatch) -> None:
    """HTTP-only probes should not trigger any TLS rules."""
    probe_attempts = [
        ProbeAttempt(
            target=ProbeTarget(scheme="http", host="example.com", port=80, path="/"),
            tcp_open=True,
            effective_method="GET",
            status_code=200,
            reason_phrase="OK",
            server_header="nginx",
            **_ALL_SECURITY_HEADERS,
        ),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)
    tls_rule_ids = {
        f.rule_id for f in result.findings
        if f.rule_id.startswith("external.tls_")
        or f.rule_id.startswith("external.cert_")
        or f.rule_id == "external.weak_cipher_suite"
    }
    assert tls_rule_ids == set()


# ---------------------------------------------------------------------------
# 1.3.1 — Error page fingerprinting
# ---------------------------------------------------------------------------

from webconf_audit.external.recon import _match_error_page_body  # noqa: E402


def test_match_error_page_body_nginx_center_tag() -> None:
    body = "<html><body><center>nginx</center></body></html>"
    assert _match_error_page_body(body) == "nginx"


def test_match_error_page_body_nginx_with_version() -> None:
    body = '<hr><center>nginx/1.24.0</center></body>'
    assert _match_error_page_body(body) == "nginx"


def test_match_error_page_body_openresty() -> None:
    body = "<html><body><center>openresty/1.21.4.3</center></body></html>"
    assert _match_error_page_body(body) == "nginx"


def test_match_error_page_body_apache() -> None:
    body = '<address>Apache Server at example.com Port 80</address>'
    assert _match_error_page_body(body) == "apache"


def test_match_error_page_body_apache_version_string() -> None:
    body = '<p>Apache/2.4.58 (Ubuntu) Server</p>'
    assert _match_error_page_body(body) == "apache"


def test_match_error_page_body_lighttpd() -> None:
    body = '<p>powered by lighttpd</p>'
    assert _match_error_page_body(body) == "lighttpd"


def test_match_error_page_body_lighttpd_version() -> None:
    body = '<h1>404 Not Found</h1><p>lighttpd/1.4.71</p>'
    assert _match_error_page_body(body) == "lighttpd"


def test_match_error_page_body_iis_detailed() -> None:
    body = '<h2>IIS Detailed Error - 404.0 - Not Found</h2>'
    assert _match_error_page_body(body) == "iis"


def test_match_error_page_body_iis_server_error_in() -> None:
    body = "<h1>Server Error in '/' Application.</h1>"
    assert _match_error_page_body(body) == "iis"


def test_match_error_page_body_iis_version_string() -> None:
    body = '<p>Microsoft-IIS/10.0</p>'
    assert _match_error_page_body(body) == "iis"


def test_match_error_page_body_no_match() -> None:
    body = '<html><body><h1>404 Not Found</h1></body></html>'
    assert _match_error_page_body(body) is None


def test_match_error_page_body_empty() -> None:
    assert _match_error_page_body("") is None


# --- Integration: error page evidence wired into identification ---


def test_error_page_nginx_contributes_to_identification_when_no_server_header(
    monkeypatch,
) -> None:
    """Error page body alone (no Server header) should produce identification."""
    probe_attempts = [
        ProbeAttempt(
            target=ProbeTarget(scheme="https", host="example.com", port=443, path="/"),
            tcp_open=True,
            status_code=200,
            reason_phrase="OK",
            **_ALL_SECURITY_HEADERS,
        ),
    ]
    error_pages = [
        ErrorPageProbe(
            url="https://example.com/_wca_nonexistent_404_probe",
            status_code=404,
            body_snippet="<html><body><center>nginx/1.24.0</center></body></html>",
        ),
    ]
    result = _analyze_with_probe_attempts(
        monkeypatch, probe_attempts, error_page_probes=error_pages,
    )

    assert result.server_type == "nginx"
    ident = result.metadata["server_identification"]
    assert ident["server_type"] == "nginx"
    # Single error page vote → low confidence (moderate evidence, not strong).
    assert ident["confidence"] == "low"
    evidence_signals = [e["signal"] for e in ident["evidence"]]
    assert "error_page_body" in evidence_signals


def test_error_page_evidence_reinforces_server_header(monkeypatch) -> None:
    """Error page body + Server header → both appear in evidence."""
    probe_attempts = [
        ProbeAttempt(
            target=ProbeTarget(scheme="https", host="example.com", port=443, path="/"),
            tcp_open=True,
            status_code=200,
            reason_phrase="OK",
            server_header="nginx/1.24.0",
            **_ALL_SECURITY_HEADERS,
        ),
    ]
    error_pages = [
        ErrorPageProbe(
            url="https://example.com/_wca_nonexistent_404_probe",
            status_code=404,
            body_snippet="<html><body><center>nginx</center></body></html>",
        ),
    ]
    result = _analyze_with_probe_attempts(
        monkeypatch, probe_attempts, error_page_probes=error_pages,
    )

    assert result.server_type == "nginx"
    ident = result.metadata["server_identification"]
    evidence_signals = [e["signal"] for e in ident["evidence"]]
    assert "server_header" in evidence_signals
    assert "error_page_body" in evidence_signals


def test_error_page_iis_identification(monkeypatch) -> None:
    probe_attempts = [
        ProbeAttempt(
            target=ProbeTarget(scheme="https", host="example.com", port=443, path="/"),
            tcp_open=True,
            status_code=200,
            reason_phrase="OK",
            **_ALL_SECURITY_HEADERS,
        ),
    ]
    error_pages = [
        ErrorPageProbe(
            url="https://example.com/_wca_nonexistent_404_probe",
            status_code=404,
            body_snippet='<h2>IIS Detailed Error - 404.0 - Not Found</h2>',
        ),
    ]
    result = _analyze_with_probe_attempts(
        monkeypatch, probe_attempts, error_page_probes=error_pages,
    )

    assert result.server_type == "iis"
    ident = result.metadata["server_identification"]
    assert ident["server_type"] == "iis"


def test_error_page_lighttpd_identification(monkeypatch) -> None:
    probe_attempts = [
        ProbeAttempt(
            target=ProbeTarget(scheme="https", host="example.com", port=443, path="/"),
            tcp_open=True,
            status_code=200,
            reason_phrase="OK",
            **_ALL_SECURITY_HEADERS,
        ),
    ]
    error_pages = [
        ErrorPageProbe(
            url="https://example.com/_wca_nonexistent_404_probe",
            status_code=404,
            body_snippet="<h1>404 Not Found</h1><p>lighttpd/1.4.71</p>",
        ),
    ]
    result = _analyze_with_probe_attempts(
        monkeypatch, probe_attempts, error_page_probes=error_pages,
    )

    assert result.server_type == "lighttpd"
    ident = result.metadata["server_identification"]
    assert ident["server_type"] == "lighttpd"
    assert ident["confidence"] == "low"


def test_error_page_no_body_does_not_add_evidence(monkeypatch) -> None:
    """Error page with None body should not create evidence."""
    probe_attempts = [
        ProbeAttempt(
            target=ProbeTarget(scheme="https", host="example.com", port=443, path="/"),
            tcp_open=True,
            status_code=200,
            reason_phrase="OK",
            **_ALL_SECURITY_HEADERS,
        ),
    ]
    error_pages = [
        ErrorPageProbe(
            url="https://example.com/_wca_nonexistent_404_probe",
            status_code=404,
            body_snippet=None,
        ),
    ]
    result = _analyze_with_probe_attempts(
        monkeypatch, probe_attempts, error_page_probes=error_pages,
    )

    # No Server header + no error page match → unknown.
    assert result.server_type is None


def test_error_page_unrecognized_body_does_not_add_evidence(monkeypatch) -> None:
    probe_attempts = [
        ProbeAttempt(
            target=ProbeTarget(scheme="https", host="example.com", port=443, path="/"),
            tcp_open=True,
            status_code=200,
            reason_phrase="OK",
            **_ALL_SECURITY_HEADERS,
        ),
    ]
    error_pages = [
        ErrorPageProbe(
            url="https://example.com/_wca_nonexistent_404_probe",
            status_code=404,
            body_snippet="<html><body>Custom 404 page</body></html>",
        ),
    ]
    result = _analyze_with_probe_attempts(
        monkeypatch, probe_attempts, error_page_probes=error_pages,
    )
    assert result.server_type is None


def test_error_page_status_200_does_not_add_evidence(monkeypatch) -> None:
    """Only actual error responses should contribute error-page evidence."""
    probe_attempts = [
        ProbeAttempt(
            target=ProbeTarget(scheme="https", host="example.com", port=443, path="/"),
            tcp_open=True,
            status_code=200,
            reason_phrase="OK",
            **_ALL_SECURITY_HEADERS,
        ),
    ]
    error_pages = [
        ErrorPageProbe(
            url="https://example.com/_wca_nonexistent_404_probe",
            status_code=200,
            body_snippet="<html><body><center>nginx</center></body></html>",
        ),
    ]
    result = _analyze_with_probe_attempts(
        monkeypatch, probe_attempts, error_page_probes=error_pages,
    )

    assert result.server_type is None
    evidence_signals = [e["signal"] for e in result.metadata["server_identification"]["evidence"]]
    assert "error_page_body" not in evidence_signals


def test_error_page_metadata_present(monkeypatch) -> None:
    """Error page probes appear in metadata."""
    probe_attempts = [
        ProbeAttempt(
            target=ProbeTarget(scheme="https", host="example.com", port=443, path="/"),
            tcp_open=True,
            status_code=200,
            reason_phrase="OK",
            server_header="nginx",
            **_ALL_SECURITY_HEADERS,
        ),
    ]
    error_pages = [
        ErrorPageProbe(
            url="https://example.com/_wca_nonexistent_404_probe",
            status_code=404,
            server_header="nginx",
            body_snippet="<center>nginx</center>",
        ),
    ]
    result = _analyze_with_probe_attempts(
        monkeypatch, probe_attempts, error_page_probes=error_pages,
    )

    assert "error_page_probes" in result.metadata
    ep_meta = result.metadata["error_page_probes"]
    assert len(ep_meta) == 1
    assert ep_meta[0]["status_code"] == 404
    assert ep_meta[0]["server_header"] == "nginx"


def test_error_page_conflicting_with_server_header_strong_wins(
    monkeypatch,
) -> None:
    """Error page says IIS but Server header says nginx → strong signal wins."""
    probe_attempts = [
        ProbeAttempt(
            target=ProbeTarget(scheme="https", host="example.com", port=443, path="/"),
            tcp_open=True,
            status_code=200,
            reason_phrase="OK",
            server_header="nginx/1.24.0",
            **_ALL_SECURITY_HEADERS,
        ),
    ]
    error_pages = [
        ErrorPageProbe(
            url="https://example.com/_wca_nonexistent_404_probe",
            status_code=404,
            body_snippet='<h2>IIS Detailed Error - 404.0</h2>',
        ),
    ]
    result = _analyze_with_probe_attempts(
        monkeypatch, probe_attempts, error_page_probes=error_pages,
    )

    # Server header is strong/direct evidence → takes precedence over error page.
    # Error page evidence is still collected but doesn't override.
    ident = result.metadata["server_identification"]
    assert ident["server_type"] == "nginx"
    assert ident["confidence"] == "high"
    # Both evidence entries are preserved for traceability.
    evidence_signals = [e["signal"] for e in ident["evidence"]]
    assert "server_header" in evidence_signals
    assert "error_page_body" in evidence_signals


def test_error_page_probe_error_does_not_crash(monkeypatch) -> None:
    """Error page probe that failed with OSError should not crash pipeline."""
    probe_attempts = [
        ProbeAttempt(
            target=ProbeTarget(scheme="https", host="example.com", port=443, path="/"),
            tcp_open=True,
            status_code=200,
            reason_phrase="OK",
            server_header="nginx",
            **_ALL_SECURITY_HEADERS,
        ),
    ]
    error_pages = [
        ErrorPageProbe(
            url="https://example.com/_wca_nonexistent_404_probe",
            error_message="Connection reset by peer",
        ),
    ]
    result = _analyze_with_probe_attempts(
        monkeypatch, probe_attempts, error_page_probes=error_pages,
    )

    # Should still identify via server header.
    assert result.server_type == "nginx"


# ---------------------------------------------------------------------------
# 1.3.2 — Malformed request fingerprinting
# ---------------------------------------------------------------------------

from webconf_audit.external.recon import (  # noqa: E402
    _match_malformed_response_body,
    _parse_malformed_response,
)


# --- Unit: _match_malformed_response_body ---


def test_match_malformed_body_nginx() -> None:
    body = "<html><body><center>nginx</center></body></html>"
    assert _match_malformed_response_body(body) == "nginx"


def test_match_malformed_body_apache_your_browser() -> None:
    body = "Your browser sent a request that this server could not understand."
    assert _match_malformed_response_body(body) == "apache"


def test_match_malformed_body_iis_bad_request() -> None:
    body = "<h2>Bad Request - Invalid URL</h2>"
    assert _match_malformed_response_body(body) == "iis"


def test_match_malformed_body_lighttpd() -> None:
    body = "<p>lighttpd/1.4.71</p>"
    assert _match_malformed_response_body(body) == "lighttpd"


def test_match_malformed_body_no_match() -> None:
    assert _match_malformed_response_body("<h1>400 Bad Request</h1>") is None


def test_match_malformed_body_empty() -> None:
    assert _match_malformed_response_body("") is None


# --- Unit: _parse_malformed_response ---


def test_parse_malformed_response_full() -> None:
    raw = (
        b"HTTP/1.1 400 Bad Request\r\n"
        b"Server: nginx/1.24.0\r\n"
        b"Content-Type: text/html\r\n"
        b"\r\n"
        b"<html><body><center>nginx</center></body></html>"
    )
    result = _parse_malformed_response("https://example.com/", raw)
    assert result.status_code == 400
    assert result.reason_phrase == "Bad Request"
    assert result.server_header == "nginx/1.24.0"
    assert result.body_snippet is not None
    assert "nginx" in result.body_snippet


def test_parse_malformed_response_no_body() -> None:
    raw = b"HTTP/1.1 400 Bad Request\r\nServer: Apache\r\n\r\n"
    result = _parse_malformed_response("https://example.com/", raw)
    assert result.status_code == 400
    assert result.server_header == "Apache"
    assert result.body_snippet is None


def test_parse_malformed_response_no_headers_separator() -> None:
    raw = b"HTTP/1.1 400 Bad Request"
    result = _parse_malformed_response("https://example.com/", raw)
    # No \r\n\r\n separator → entire response treated as body snippet.
    assert result.body_snippet is not None


def test_parse_malformed_response_iis_style() -> None:
    raw = (
        b"HTTP/1.1 400 Bad Request\r\n"
        b"Server: Microsoft-IIS/10.0\r\n"
        b"\r\n"
        b"<h2>Bad Request - Invalid URL</h2>"
    )
    result = _parse_malformed_response("https://example.com/", raw)
    assert result.status_code == 400
    assert result.server_header == "Microsoft-IIS/10.0"
    assert "Bad Request - Invalid URL" in (result.body_snippet or "")


def test_parse_malformed_response_empty_bytes() -> None:
    result = _parse_malformed_response("https://example.com/", b"")
    assert result.status_code is None
    assert result.body_snippet is None


# --- Integration: malformed request evidence in identification ---


def test_malformed_server_header_contributes_strong_evidence(monkeypatch) -> None:
    """Malformed response Server header should produce strong/direct evidence."""
    probe_attempts = [
        ProbeAttempt(
            target=ProbeTarget(scheme="https", host="example.com", port=443, path="/"),
            tcp_open=True,
            status_code=200,
            reason_phrase="OK",
            **_ALL_SECURITY_HEADERS,
        ),
    ]
    malformed = [
        MalformedRequestProbe(
            url="https://example.com/",
            status_code=400,
            reason_phrase="Bad Request",
            server_header="nginx/1.24.0",
            body_snippet="<html><body>400 Bad Request</body></html>",
        ),
    ]
    result = _analyze_with_probe_attempts(
        monkeypatch, probe_attempts, malformed_request_probes=malformed,
    )

    assert result.server_type == "nginx"
    ident = result.metadata["server_identification"]
    # Server header from malformed response is strong → high confidence.
    assert ident["confidence"] == "high"
    evidence_signals = [e["signal"] for e in ident["evidence"]]
    assert "malformed_response_server_header" in evidence_signals


def test_malformed_body_only_contributes_moderate_evidence(monkeypatch) -> None:
    """Malformed response body (no Server header) → moderate/low evidence."""
    probe_attempts = [
        ProbeAttempt(
            target=ProbeTarget(scheme="https", host="example.com", port=443, path="/"),
            tcp_open=True,
            status_code=200,
            reason_phrase="OK",
            **_ALL_SECURITY_HEADERS,
        ),
    ]
    malformed = [
        MalformedRequestProbe(
            url="https://example.com/",
            status_code=400,
            reason_phrase="Bad Request",
            body_snippet="Your browser sent a request that this server could not understand.",
        ),
    ]
    result = _analyze_with_probe_attempts(
        monkeypatch, probe_attempts, malformed_request_probes=malformed,
    )

    assert result.server_type == "apache"
    ident = result.metadata["server_identification"]
    # Body-only → low confidence (moderate evidence, single vote).
    assert ident["confidence"] == "low"
    evidence_signals = [e["signal"] for e in ident["evidence"]]
    assert "malformed_response_body" in evidence_signals


def test_malformed_body_iis_contributes_moderate_evidence(monkeypatch) -> None:
    probe_attempts = [
        ProbeAttempt(
            target=ProbeTarget(scheme="https", host="example.com", port=443, path="/"),
            tcp_open=True,
            status_code=200,
            reason_phrase="OK",
            **_ALL_SECURITY_HEADERS,
        ),
    ]
    malformed = [
        MalformedRequestProbe(
            url="https://example.com/",
            status_code=400,
            reason_phrase="Bad Request",
            body_snippet="<h2>Bad Request - Invalid URL</h2>",
        ),
    ]
    result = _analyze_with_probe_attempts(
        monkeypatch, probe_attempts, malformed_request_probes=malformed,
    )

    assert result.server_type == "iis"
    ident = result.metadata["server_identification"]
    assert ident["confidence"] == "low"
    evidence_signals = [e["signal"] for e in ident["evidence"]]
    assert "malformed_response_body" in evidence_signals


def test_malformed_server_header_plus_body_both_evidence(monkeypatch) -> None:
    """Malformed response with both Server header and body match → two evidence entries."""
    probe_attempts = [
        ProbeAttempt(
            target=ProbeTarget(scheme="https", host="example.com", port=443, path="/"),
            tcp_open=True,
            status_code=200,
            reason_phrase="OK",
            **_ALL_SECURITY_HEADERS,
        ),
    ]
    malformed = [
        MalformedRequestProbe(
            url="https://example.com/",
            status_code=400,
            server_header="nginx/1.24.0",
            body_snippet="<html><body><center>nginx</center></body></html>",
        ),
    ]
    result = _analyze_with_probe_attempts(
        monkeypatch, probe_attempts, malformed_request_probes=malformed,
    )

    assert result.server_type == "nginx"
    ident = result.metadata["server_identification"]
    evidence_signals = [e["signal"] for e in ident["evidence"]]
    assert "malformed_response_server_header" in evidence_signals
    assert "malformed_response_body" in evidence_signals


def test_malformed_reinforces_normal_server_header(monkeypatch) -> None:
    """Normal Server header + malformed Server header → both evidence, high confidence."""
    probe_attempts = [
        ProbeAttempt(
            target=ProbeTarget(scheme="https", host="example.com", port=443, path="/"),
            tcp_open=True,
            status_code=200,
            reason_phrase="OK",
            server_header="Apache/2.4.58",
            **_ALL_SECURITY_HEADERS,
        ),
    ]
    malformed = [
        MalformedRequestProbe(
            url="https://example.com/",
            status_code=400,
            server_header="Apache/2.4.58",
            body_snippet="Apache Server at example.com Port 443",
        ),
    ]
    result = _analyze_with_probe_attempts(
        monkeypatch, probe_attempts, malformed_request_probes=malformed,
    )

    assert result.server_type == "apache"
    ident = result.metadata["server_identification"]
    assert ident["confidence"] == "high"


def test_malformed_no_body_no_server_header_no_evidence(monkeypatch) -> None:
    """Malformed probe with no useful data should not add evidence."""
    probe_attempts = [
        ProbeAttempt(
            target=ProbeTarget(scheme="https", host="example.com", port=443, path="/"),
            tcp_open=True,
            status_code=200,
            reason_phrase="OK",
            **_ALL_SECURITY_HEADERS,
        ),
    ]
    malformed = [
        MalformedRequestProbe(
            url="https://example.com/",
            status_code=400,
            body_snippet="<h1>400</h1>",
        ),
    ]
    result = _analyze_with_probe_attempts(
        monkeypatch, probe_attempts, malformed_request_probes=malformed,
    )
    assert result.server_type is None


def test_malformed_status_200_does_not_add_evidence(monkeypatch) -> None:
    """Malformed-response fingerprinting must ignore non-error responses."""
    probe_attempts = [
        ProbeAttempt(
            target=ProbeTarget(scheme="https", host="example.com", port=443, path="/"),
            tcp_open=True,
            status_code=200,
            reason_phrase="OK",
            **_ALL_SECURITY_HEADERS,
        ),
    ]
    malformed = [
        MalformedRequestProbe(
            url="https://example.com/",
            status_code=200,
            server_header="Apache/2.4.58",
            body_snippet="Apache Server at example.com Port 443",
        ),
    ]
    result = _analyze_with_probe_attempts(
        monkeypatch, probe_attempts, malformed_request_probes=malformed,
    )

    assert result.server_type is None
    evidence_signals = [e["signal"] for e in result.metadata["server_identification"]["evidence"]]
    assert "malformed_response_server_header" not in evidence_signals
    assert "malformed_response_body" not in evidence_signals


def test_malformed_probe_error_does_not_crash(monkeypatch) -> None:
    probe_attempts = [
        ProbeAttempt(
            target=ProbeTarget(scheme="https", host="example.com", port=443, path="/"),
            tcp_open=True,
            status_code=200,
            reason_phrase="OK",
            server_header="nginx",
            **_ALL_SECURITY_HEADERS,
        ),
    ]
    malformed = [
        MalformedRequestProbe(
            url="https://example.com/",
            error_message="Connection reset",
        ),
    ]
    result = _analyze_with_probe_attempts(
        monkeypatch, probe_attempts, malformed_request_probes=malformed,
    )
    assert result.server_type == "nginx"


def test_try_malformed_request_probe_unicode_host_uses_idna(monkeypatch) -> None:
    from webconf_audit.external.recon import _try_malformed_request_probe

    class DummySock:
        def __init__(self) -> None:
            self.sent = b""

        def sendall(self, data: bytes) -> None:
            self.sent = data

        def recv(self, _size: int) -> bytes:
            return b""

        def close(self) -> None:
            return None

    dummy = DummySock()
    monkeypatch.setattr(
        "webconf_audit.external.recon.socket.create_connection",
        lambda *_args, **_kwargs: dummy,
    )

    host = "\u0442\u0435\u0441\u0442.\u0440\u0444"
    result = _try_malformed_request_probe(
        ProbeTarget(scheme="http", host=host, port=80, path="/"),
    )

    assert result.error_message is None
    assert host.encode("idna") in dummy.sent


def test_malformed_metadata_present(monkeypatch) -> None:
    probe_attempts = [
        ProbeAttempt(
            target=ProbeTarget(scheme="https", host="example.com", port=443, path="/"),
            tcp_open=True,
            status_code=200,
            reason_phrase="OK",
            server_header="nginx",
            **_ALL_SECURITY_HEADERS,
        ),
    ]
    malformed = [
        MalformedRequestProbe(
            url="https://example.com/",
            status_code=400,
            reason_phrase="Bad Request",
            server_header="nginx/1.24.0",
            body_snippet="<center>nginx</center>",
        ),
    ]
    result = _analyze_with_probe_attempts(
        monkeypatch, probe_attempts, malformed_request_probes=malformed,
    )

    assert "malformed_request_probes" in result.metadata
    mp_meta = result.metadata["malformed_request_probes"]
    assert len(mp_meta) == 1
    assert mp_meta[0]["status_code"] == 400
    assert mp_meta[0]["reason_phrase"] == "Bad Request"
    assert mp_meta[0]["server_header"] == "nginx/1.24.0"


# ---------------------------------------------------------------------------
# 1.3.3 — Extended header fingerprinting
# ---------------------------------------------------------------------------


def test_x_aspnetmvc_version_contributes_iis_evidence(monkeypatch) -> None:
    probe_attempts = [
        ProbeAttempt(
            target=ProbeTarget(scheme="https", host="example.com", port=443, path="/"),
            tcp_open=True,
            status_code=200,
            reason_phrase="OK",
            x_aspnetmvc_version_header="5.2",
            **_ALL_SECURITY_HEADERS,
        ),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)

    assert result.server_type == "iis"
    ident = result.metadata["server_identification"]
    evidence_signals = [e["signal"] for e in ident["evidence"]]
    assert "x_aspnetmvc_version_header" in evidence_signals
    # Single moderate vote → low confidence.
    assert ident["confidence"] == "low"


def test_x_aspnetmvc_version_reinforces_aspnet_version(monkeypatch) -> None:
    """Both X-AspNet-Version and X-AspNetMvc-Version → medium confidence."""
    probe_attempts = [
        ProbeAttempt(
            target=ProbeTarget(scheme="https", host="example.com", port=443, path="/"),
            tcp_open=True,
            status_code=200,
            reason_phrase="OK",
            x_powered_by_header="ASP.NET",
            x_aspnet_version_header="4.0.30319",
            x_aspnetmvc_version_header="5.2",
            **_ALL_SECURITY_HEADERS,
        ),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)

    assert result.server_type == "iis"
    ident = result.metadata["server_identification"]
    assert ident["confidence"] == "medium"
    evidence_signals = [e["signal"] for e in ident["evidence"]]
    assert "x_aspnetmvc_version_header" in evidence_signals
    assert "x_aspnet_version_header" in evidence_signals
    assert "x_powered_by_header" in evidence_signals


def test_set_cookie_aspnet_session_contributes_iis_evidence(monkeypatch) -> None:
    probe_attempts = [
        ProbeAttempt(
            target=ProbeTarget(scheme="https", host="example.com", port=443, path="/"),
            tcp_open=True,
            status_code=200,
            reason_phrase="OK",
            set_cookie_headers=("ASP.NET_SessionId=abc123; path=/; HttpOnly",),
            **_ALL_SECURITY_HEADERS,
        ),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)

    assert result.server_type == "iis"
    ident = result.metadata["server_identification"]
    evidence_signals = [e["signal"] for e in ident["evidence"]]
    assert "set_cookie_session" in evidence_signals


def test_set_cookie_aspxauth_contributes_iis_evidence(monkeypatch) -> None:
    probe_attempts = [
        ProbeAttempt(
            target=ProbeTarget(scheme="https", host="example.com", port=443, path="/"),
            tcp_open=True,
            status_code=200,
            reason_phrase="OK",
            set_cookie_headers=(".ASPXAUTH=DEADBEEF; path=/; secure; HttpOnly",),
            **_ALL_SECURITY_HEADERS,
        ),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)

    assert result.server_type == "iis"
    evidence_signals = [e["signal"] for e in result.metadata["server_identification"]["evidence"]]
    assert "set_cookie_session" in evidence_signals


def test_set_cookie_non_aspnet_does_not_create_evidence(monkeypatch) -> None:
    probe_attempts = [
        ProbeAttempt(
            target=ProbeTarget(scheme="https", host="example.com", port=443, path="/"),
            tcp_open=True,
            status_code=200,
            reason_phrase="OK",
            set_cookie_headers=("PHPSESSID=abc123; path=/",),
            **_ALL_SECURITY_HEADERS,
        ),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)

    # PHPSESSID is not an IIS indicator; no evidence should be created.
    assert result.server_type is None


def test_via_header_nginx_creates_weak_evidence(monkeypatch) -> None:
    probe_attempts = [
        ProbeAttempt(
            target=ProbeTarget(scheme="https", host="example.com", port=443, path="/"),
            tcp_open=True,
            status_code=200,
            reason_phrase="OK",
            via_header="1.1 nginx",
            **_ALL_SECURITY_HEADERS,
        ),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)

    ident = result.metadata["server_identification"]
    evidence_signals = [e["signal"] for e in ident["evidence"]]
    assert "via_header" in evidence_signals
    via_evidence = [e for e in ident["evidence"] if e["signal"] == "via_header"][0]
    assert via_evidence["indicates"] == "nginx"
    assert via_evidence["strength"] == "weak"
    # Via alone is weak → no vote → server_type is None.
    assert result.server_type is None


def test_via_header_apache_creates_weak_evidence(monkeypatch) -> None:
    probe_attempts = [
        ProbeAttempt(
            target=ProbeTarget(scheme="https", host="example.com", port=443, path="/"),
            tcp_open=True,
            status_code=200,
            reason_phrase="OK",
            via_header="1.1 Apache/2.4.58",
            **_ALL_SECURITY_HEADERS,
        ),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)

    ident = result.metadata["server_identification"]
    via_evidence = [e for e in ident["evidence"] if e["signal"] == "via_header"]
    assert len(via_evidence) == 1
    assert via_evidence[0]["indicates"] == "apache"


def test_via_header_unrecognized_no_evidence(monkeypatch) -> None:
    probe_attempts = [
        ProbeAttempt(
            target=ProbeTarget(scheme="https", host="example.com", port=443, path="/"),
            tcp_open=True,
            status_code=200,
            reason_phrase="OK",
            via_header="1.1 varnish",
            **_ALL_SECURITY_HEADERS,
        ),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)

    ident = result.metadata["server_identification"]
    via_evidence = [e for e in ident["evidence"] if e["signal"] == "via_header"]
    assert len(via_evidence) == 0


def test_new_headers_in_metadata(monkeypatch) -> None:
    probe_attempts = [
        ProbeAttempt(
            target=ProbeTarget(scheme="https", host="example.com", port=443, path="/"),
            tcp_open=True,
            status_code=200,
            reason_phrase="OK",
            server_header="nginx",
            x_aspnetmvc_version_header="5.2",
            via_header="1.1 proxy",
            etag_header='"abc123"',
            cache_control_header="no-store",
            x_dns_prefetch_control_header="off",
            **_ALL_SECURITY_HEADERS,
        ),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)

    meta = result.metadata["probe_attempts"][0]
    assert meta["x_aspnetmvc_version_header"] == "5.2"
    assert meta["via_header"] == "1.1 proxy"
    assert meta["etag_header"] == '"abc123"'
    assert meta["cache_control_header"] == "no-store"
    assert meta["x_dns_prefetch_control_header"] == "off"
    assert meta["cross_origin_embedder_policy_header"] == "require-corp"
    assert meta["cross_origin_opener_policy_header"] == "same-origin"
    assert meta["cross_origin_resource_policy_header"] == "same-origin"


def test_new_headers_in_diagnostics(monkeypatch) -> None:
    probe_attempts = [
        ProbeAttempt(
            target=ProbeTarget(scheme="https", host="example.com", port=443, path="/"),
            tcp_open=True,
            status_code=200,
            reason_phrase="OK",
            server_header="nginx",
            x_aspnetmvc_version_header="5.2",
            via_header="1.1 proxy",
            etag_header='"abc123"',
            cache_control_header="no-store",
            x_dns_prefetch_control_header="off",
            **_ALL_SECURITY_HEADERS,
        ),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)

    assert any("x_aspnetmvc_version: 5.2" in d for d in result.diagnostics)
    assert any("via: 1.1 proxy" in d for d in result.diagnostics)
    assert any('etag: "abc123"' in d for d in result.diagnostics)
    assert any("cache_control: no-store" in d for d in result.diagnostics)
    assert any("x_dns_prefetch_control: off" in d for d in result.diagnostics)
    assert any("cross_origin_embedder_policy: require-corp" in d for d in result.diagnostics)
    assert any("cross_origin_opener_policy: same-origin" in d for d in result.diagnostics)
    assert any("cross_origin_resource_policy: same-origin" in d for d in result.diagnostics)


def test_phase1_external_enrichment_metadata_is_present_together(monkeypatch) -> None:
    tls = TLSInfo(
        protocol_version="TLSv1.3",
        cipher_name="TLS_AES_256_GCM_SHA384",
        cipher_bits=256,
        cipher_protocol="TLSv1.3",
        cert_san=("example.com", "www.example.com"),
        supported_protocols=("TLSv1.2", "TLSv1.3"),
        cert_chain_complete=True,
    )
    probe_attempts = [
        _https_probe_with_headers(
            server_header="nginx/1.24.0",
            tls_info=tls,
            x_powered_by_header="PHP/8.2",
            x_aspnetmvc_version_header="5.2",
            via_header="1.1 proxy",
            etag_header='"abc123"',
            cache_control_header="no-store",
            x_dns_prefetch_control_header="off",
            body_snippet="Welcome to nginx!",
        ),
        _http_redirect_probe(location_header="https://example.com/app"),
    ]
    additional_attempts = [
        _https_probe_with_headers(
            target=ProbeTarget(scheme="https", host="example.com", port=443, path="/app"),
            server_header="nginx/1.24.0",
        ),
    ]
    sensitive = [
        _sensitive_path_probe("/.env", body_snippet="APP_ENV=production"),
    ]
    error_pages = [
        ErrorPageProbe(
            url="https://example.com/_wca_nonexistent_404_probe",
            status_code=404,
            server_header="nginx/1.24.0",
            body_snippet="<center>nginx</center>",
        ),
    ]
    malformed = [
        MalformedRequestProbe(
            url="https://example.com/",
            status_code=400,
            server_header="nginx/1.24.0",
            body_snippet="<center>nginx</center>",
        ),
    ]

    result = _analyze_with_probe_attempts(
        monkeypatch,
        probe_attempts,
        sensitive_path_probes=sensitive,
        error_page_probes=error_pages,
        malformed_request_probes=malformed,
        additional_probe_attempts=additional_attempts,
    )

    assert result.metadata["probe_attempts"][0]["tls_info"]["supported_protocols"] == [
        "TLSv1.2",
        "TLSv1.3",
    ]
    assert result.metadata["probe_attempts"][0]["cross_origin_embedder_policy_header"] == "require-corp"
    assert result.metadata["probe_attempts"][0]["cache_control_header"] == "no-store"
    assert result.metadata["server_identification"]["server_type"] == "nginx"
    assert result.metadata["error_page_probes"][0]["status_code"] == 404
    assert result.metadata["malformed_request_probes"][0]["status_code"] == 400
    assert result.metadata["sensitive_path_probes"][0]["path"] == "/.env"
    assert result.metadata["redirect_chains"][0]["final_url"] == "https://example.com/app"


def test_multiple_aspnet_signals_accumulate(monkeypatch) -> None:
    """X-AspNet-Version + X-AspNetMvc-Version + Set-Cookie ASP.NET → IIS medium."""
    probe_attempts = [
        ProbeAttempt(
            target=ProbeTarget(scheme="https", host="example.com", port=443, path="/"),
            tcp_open=True,
            status_code=200,
            reason_phrase="OK",
            x_aspnet_version_header="4.0.30319",
            x_aspnetmvc_version_header="5.2",
            set_cookie_headers=("ASP.NET_SessionId=abc; path=/",),
            **_ALL_SECURITY_HEADERS,
        ),
    ]
    result = _analyze_with_probe_attempts(monkeypatch, probe_attempts)

    assert result.server_type == "iis"
    ident = result.metadata["server_identification"]
    assert ident["confidence"] == "medium"


# ---------------------------------------------------------------------------
# 1.3.4 — Cross-signal integration and priority chain tests
# ---------------------------------------------------------------------------


def test_all_signals_agree_nginx(monkeypatch) -> None:
    """Server header + error page + malformed response all say nginx → high."""
    probe_attempts = [
        ProbeAttempt(
            target=ProbeTarget(scheme="https", host="example.com", port=443, path="/"),
            tcp_open=True,
            status_code=200,
            reason_phrase="OK",
            server_header="nginx/1.24.0",
            **_ALL_SECURITY_HEADERS,
        ),
    ]
    error_pages = [
        ErrorPageProbe(
            url="https://example.com/_wca_nonexistent_404_probe",
            status_code=404,
            body_snippet="<center>nginx</center>",
        ),
    ]
    malformed = [
        MalformedRequestProbe(
            url="https://example.com/",
            status_code=400,
            server_header="nginx/1.24.0",
            body_snippet="<center>nginx</center>",
        ),
    ]
    result = _analyze_with_probe_attempts(
        monkeypatch,
        probe_attempts,
        error_page_probes=error_pages,
        malformed_request_probes=malformed,
    )

    assert result.server_type == "nginx"
    ident = result.metadata["server_identification"]
    assert ident["confidence"] == "high"
    assert ident["ambiguous"] is False
    signals = {e["signal"] for e in ident["evidence"]}
    assert "server_header" in signals
    assert "error_page_body" in signals
    assert "malformed_response_server_header" in signals
    assert "malformed_response_body" in signals


def test_all_signals_agree_iis(monkeypatch) -> None:
    """IIS: Server header + X-AspNet + X-AspNetMvc + Set-Cookie + error page."""
    probe_attempts = [
        ProbeAttempt(
            target=ProbeTarget(scheme="https", host="example.com", port=443, path="/"),
            tcp_open=True,
            status_code=200,
            reason_phrase="OK",
            server_header="Microsoft-IIS/10.0",
            x_powered_by_header="ASP.NET",
            x_aspnet_version_header="4.0.30319",
            x_aspnetmvc_version_header="5.2",
            set_cookie_headers=("ASP.NET_SessionId=abc; path=/",),
            **_ALL_SECURITY_HEADERS,
        ),
    ]
    error_pages = [
        ErrorPageProbe(
            url="https://example.com/_wca_nonexistent_404_probe",
            status_code=404,
            body_snippet="<h2>IIS Detailed Error - 404.0</h2>",
        ),
    ]
    result = _analyze_with_probe_attempts(
        monkeypatch, probe_attempts, error_page_probes=error_pages,
    )

    assert result.server_type == "iis"
    ident = result.metadata["server_identification"]
    assert ident["confidence"] == "high"
    signals = {e["signal"] for e in ident["evidence"]}
    assert signals >= {
        "server_header",
        "x_powered_by_header",
        "x_aspnet_version_header",
        "x_aspnetmvc_version_header",
        "set_cookie_session",
        "error_page_body",
    }


def test_priority_direct_beats_error_page(monkeypatch) -> None:
    """Direct server header (nginx) should win over error page body (apache)."""
    probe_attempts = [
        ProbeAttempt(
            target=ProbeTarget(scheme="https", host="example.com", port=443, path="/"),
            tcp_open=True,
            status_code=200,
            reason_phrase="OK",
            server_header="nginx/1.24.0",
            **_ALL_SECURITY_HEADERS,
        ),
    ]
    error_pages = [
        ErrorPageProbe(
            url="https://example.com/_wca_nonexistent_404_probe",
            status_code=404,
            body_snippet="Apache Server at example.com Port 443",
        ),
    ]
    result = _analyze_with_probe_attempts(
        monkeypatch, probe_attempts, error_page_probes=error_pages,
    )

    assert result.server_type == "nginx"
    assert result.metadata["server_identification"]["confidence"] == "high"


def test_priority_direct_beats_malformed_body(monkeypatch) -> None:
    """Direct server header (apache) should win over malformed body (iis)."""
    probe_attempts = [
        ProbeAttempt(
            target=ProbeTarget(scheme="https", host="example.com", port=443, path="/"),
            tcp_open=True,
            status_code=200,
            reason_phrase="OK",
            server_header="Apache/2.4.58",
            **_ALL_SECURITY_HEADERS,
        ),
    ]
    malformed = [
        MalformedRequestProbe(
            url="https://example.com/",
            status_code=400,
            body_snippet="Bad Request - Invalid URL",
        ),
    ]
    result = _analyze_with_probe_attempts(
        monkeypatch, probe_attempts, malformed_request_probes=malformed,
    )

    assert result.server_type == "apache"
    assert result.metadata["server_identification"]["confidence"] == "high"


def test_priority_error_page_beats_app_stack(monkeypatch) -> None:
    """Error page body (nginx) should win over app_stack only (iis via X-AspNet)."""
    probe_attempts = [
        ProbeAttempt(
            target=ProbeTarget(scheme="https", host="example.com", port=443, path="/"),
            tcp_open=True,
            status_code=200,
            reason_phrase="OK",
            x_aspnet_version_header="4.0.30319",
            **_ALL_SECURITY_HEADERS,
        ),
    ]
    error_pages = [
        ErrorPageProbe(
            url="https://example.com/_wca_nonexistent_404_probe",
            status_code=404,
            body_snippet="<center>nginx</center>",
        ),
    ]
    result = _analyze_with_probe_attempts(
        monkeypatch, probe_attempts, error_page_probes=error_pages,
    )

    assert result.server_type == "nginx"


def test_new_signals_improve_confidence_with_weak_server_header(monkeypatch) -> None:
    """An uninformative Server header should be overridden by agreeing new signals."""
    probe_attempts = [
        ProbeAttempt(
            target=ProbeTarget(scheme="https", host="example.com", port=443, path="/"),
            tcp_open=True,
            status_code=200,
            reason_phrase="OK",
            server_header="custom-edge",
            **_ALL_SECURITY_HEADERS,
        ),
    ]
    error_pages = [
        ErrorPageProbe(
            url="https://example.com/_wca_nonexistent_404_probe",
            status_code=404,
            body_snippet="<center>nginx</center>",
        ),
    ]
    malformed = [
        MalformedRequestProbe(
            url="https://example.com/",
            status_code=400,
            body_snippet="<center>nginx</center>",
        ),
    ]
    result = _analyze_with_probe_attempts(
        monkeypatch,
        probe_attempts,
        error_page_probes=error_pages,
        malformed_request_probes=malformed,
    )

    assert result.server_type == "nginx"
    ident = result.metadata["server_identification"]
    assert ident["confidence"] == "medium"
    evidence_signals = {e["signal"] for e in ident["evidence"]}
    assert "server_header" not in evidence_signals
    assert "error_page_body" in evidence_signals
    assert "malformed_response_body" in evidence_signals


def test_malformed_server_header_merges_into_direct(monkeypatch) -> None:
    """Malformed response Server header should merge into direct votes."""
    probe_attempts = [
        ProbeAttempt(
            target=ProbeTarget(scheme="https", host="example.com", port=443, path="/"),
            tcp_open=True,
            status_code=200,
            reason_phrase="OK",
            **_ALL_SECURITY_HEADERS,
        ),
    ]
    malformed = [
        MalformedRequestProbe(
            url="https://example.com/",
            status_code=400,
            server_header="lighttpd/1.4.71",
        ),
    ]
    result = _analyze_with_probe_attempts(
        monkeypatch, probe_attempts, malformed_request_probes=malformed,
    )

    assert result.server_type == "lighttpd"
    assert result.metadata["server_identification"]["confidence"] == "high"


def test_no_signals_at_all(monkeypatch) -> None:
    """No headers, no error page, no malformed response → unknown."""
    probe_attempts = [
        ProbeAttempt(
            target=ProbeTarget(scheme="https", host="example.com", port=443, path="/"),
            tcp_open=True,
            status_code=200,
            reason_phrase="OK",
            **_ALL_SECURITY_HEADERS,
        ),
    ]
    result = _analyze_with_probe_attempts(
        monkeypatch,
        probe_attempts,
        error_page_probes=[],
        malformed_request_probes=[],
    )

    assert result.server_type is None
    ident = result.metadata["server_identification"]
    assert ident["confidence"] == "none"


def test_only_weak_via_insufficient_for_classification(monkeypatch) -> None:
    """Via header alone (weak) should create evidence but not classify."""
    probe_attempts = [
        ProbeAttempt(
            target=ProbeTarget(scheme="https", host="example.com", port=443, path="/"),
            tcp_open=True,
            status_code=200,
            reason_phrase="OK",
            via_header="1.1 nginx",
            **_ALL_SECURITY_HEADERS,
        ),
    ]
    result = _analyze_with_probe_attempts(
        monkeypatch,
        probe_attempts,
        error_page_probes=[],
        malformed_request_probes=[],
    )

    assert result.server_type is None
    ident = result.metadata["server_identification"]
    assert ident["confidence"] == "none"
    assert len(ident["evidence"]) == 1
    assert ident["evidence"][0]["signal"] == "via_header"


def test_error_page_and_malformed_body_agree_accumulate(monkeypatch) -> None:
    """Error page + malformed body both say apache → shares bucket, medium confidence."""
    probe_attempts = [
        ProbeAttempt(
            target=ProbeTarget(scheme="https", host="example.com", port=443, path="/"),
            tcp_open=True,
            status_code=200,
            reason_phrase="OK",
            **_ALL_SECURITY_HEADERS,
        ),
    ]
    error_pages = [
        ErrorPageProbe(
            url="https://example.com/_wca_nonexistent_404_probe",
            status_code=404,
            body_snippet="Apache Server at example.com Port 443",
        ),
    ]
    malformed = [
        MalformedRequestProbe(
            url="https://example.com/",
            status_code=400,
            body_snippet="Your browser sent a request that this server could not understand.",
        ),
    ]
    result = _analyze_with_probe_attempts(
        monkeypatch,
        probe_attempts,
        error_page_probes=error_pages,
        malformed_request_probes=malformed,
    )

    assert result.server_type == "apache"
    ident = result.metadata["server_identification"]
    assert ident["confidence"] == "medium"


def test_error_page_and_malformed_body_conflict(monkeypatch) -> None:
    """Error page says nginx, malformed body says apache → ambiguous in shared bucket."""
    probe_attempts = [
        ProbeAttempt(
            target=ProbeTarget(scheme="https", host="example.com", port=443, path="/"),
            tcp_open=True,
            status_code=200,
            reason_phrase="OK",
            **_ALL_SECURITY_HEADERS,
        ),
    ]
    error_pages = [
        ErrorPageProbe(
            url="https://example.com/_wca_nonexistent_404_probe",
            status_code=404,
            body_snippet="<center>nginx</center>",
        ),
    ]
    malformed = [
        MalformedRequestProbe(
            url="https://example.com/",
            status_code=400,
            body_snippet="Apache Server at example.com Port 443",
        ),
    ]
    result = _analyze_with_probe_attempts(
        monkeypatch,
        probe_attempts,
        error_page_probes=error_pages,
        malformed_request_probes=malformed,
    )

    ident = result.metadata["server_identification"]
    assert ident["ambiguous"] is True
    assert set(ident["candidate_server_types"]) == {"apache", "nginx"}

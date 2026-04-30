"""Tests for webconf_audit.external.recon.tls_probe and its integration into recon."""

from __future__ import annotations

import ssl
import warnings
from unittest.mock import MagicMock

import pytest

from webconf_audit.external.recon import (
    ProbeAttempt,
    ProbeTarget,
    TLSInfo,
    analyze_external_target,
)
from webconf_audit.external.recon.tls_probe import (
    ChainDepthResult,
    ChainVerificationResult,
    TLSVersionProbeResult,
    _build_tls_context,
    _probe_single_version,
    probe_chain_depth,
    probe_tls_versions,
    supported_protocol_labels,
    verify_certificate_chain,
)


# ---------------------------------------------------------------------------
# Unit tests for tls_probe module
# ---------------------------------------------------------------------------


class TestBuildTlsContext:
    def test_returns_ssl_context(self) -> None:
        ctx = _build_tls_context(ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_2)
        assert isinstance(ctx, ssl.SSLContext)

    def test_disables_hostname_check(self) -> None:
        ctx = _build_tls_context(ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_2)
        assert ctx.check_hostname is False

    def test_disables_cert_verification(self) -> None:
        ctx = _build_tls_context(ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_2)
        assert ctx.verify_mode == ssl.CERT_NONE

    def test_pins_min_version(self) -> None:
        ctx = _build_tls_context(ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_3)
        assert ctx.minimum_version == ssl.TLSVersion.TLSv1_2

    def test_pins_max_version(self) -> None:
        ctx = _build_tls_context(ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_3)
        assert ctx.maximum_version == ssl.TLSVersion.TLSv1_3

    def test_suppresses_deprecated_tls_version_warnings(self) -> None:
        with warnings.catch_warnings(record=True) as captured:
            warnings.simplefilter("always")
            _build_tls_context(ssl.TLSVersion.TLSv1, ssl.TLSVersion.TLSv1)
            _build_tls_context(ssl.TLSVersion.TLSv1_1, ssl.TLSVersion.TLSv1_1)

        deprecations = [
            warning
            for warning in captured
            if issubclass(warning.category, DeprecationWarning)
        ]
        assert deprecations == []


class TestProbeSingleVersion:
    def test_supported_version(self, monkeypatch) -> None:
        """Handshake succeeds → supported=True."""
        mock_raw = MagicMock()
        mock_tls = MagicMock()
        mock_tls.configure_mock(**{
            "__enter__.return_value": mock_tls,
            "__exit__.return_value": False,
        })

        mock_ctx = MagicMock()
        mock_ctx.configure_mock(**{"wrap_socket.return_value": mock_tls})

        monkeypatch.setattr(
            "webconf_audit.external.recon.tls_probe._build_tls_context",
            lambda _min_v, _max_v: mock_ctx,
        )
        monkeypatch.setattr(
            "webconf_audit.external.recon.tls_probe.socket.create_connection",
            lambda addr, timeout: mock_raw,
        )
        mock_raw.configure_mock(**{
            "__enter__.return_value": mock_raw,
            "__exit__.return_value": False,
        })

        result = _probe_single_version(
            "example.com", 443, "TLSv1.2",
            ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_2, 2.0,
        )
        assert result.label == "TLSv1.2"
        assert result.supported is True
        assert result.error_message is None

    def test_unsupported_version_ssl_error(self, monkeypatch) -> None:
        """SSLError during handshake → supported=False."""
        monkeypatch.setattr(
            "webconf_audit.external.recon.tls_probe._build_tls_context",
            lambda _min_v, _max_v: MagicMock(),
        )

        def fake_connect(addr, timeout):
            raise ssl.SSLError("unsupported protocol")

        monkeypatch.setattr(
            "webconf_audit.external.recon.tls_probe.socket.create_connection",
            fake_connect,
        )
        result = _probe_single_version(
            "example.com", 443, "TLSv1",
            ssl.TLSVersion.TLSv1, ssl.TLSVersion.TLSv1, 2.0,
        )
        assert result.label == "TLSv1"
        assert result.supported is False
        assert result.error_message is not None

    def test_unsupported_version_os_error(self, monkeypatch) -> None:
        """OSError (e.g. connection refused) → supported=False."""
        monkeypatch.setattr(
            "webconf_audit.external.recon.tls_probe._build_tls_context",
            lambda _min_v, _max_v: MagicMock(),
        )

        def fake_connect(addr, timeout):
            raise OSError("Connection refused")

        monkeypatch.setattr(
            "webconf_audit.external.recon.tls_probe.socket.create_connection",
            fake_connect,
        )
        result = _probe_single_version(
            "example.com", 443, "TLSv1.3",
            ssl.TLSVersion.TLSv1_3, ssl.TLSVersion.TLSv1_3, 2.0,
        )
        assert result.supported is False
        assert "Connection refused" in result.error_message


class TestProbeTlsVersions:
    def test_returns_four_results(self, monkeypatch) -> None:
        """Should probe all four TLS versions."""
        monkeypatch.setattr(
            "webconf_audit.external.recon.tls_probe._probe_single_version",
            lambda host, port, label, _min_v, _max_v, timeout: TLSVersionProbeResult(
                label=label, supported=True,
            ),
        )
        results = probe_tls_versions("example.com", 443)
        assert len(results) == 4

    def test_version_order(self, monkeypatch) -> None:
        """Results should be in ascending version order."""
        monkeypatch.setattr(
            "webconf_audit.external.recon.tls_probe._probe_single_version",
            lambda host, port, label, _min_v, _max_v, timeout: TLSVersionProbeResult(
                label=label, supported=True,
            ),
        )
        results = probe_tls_versions("example.com", 443)
        labels = [r.label for r in results]
        assert labels == ["TLSv1", "TLSv1.1", "TLSv1.2", "TLSv1.3"]

    def test_mixed_support(self, monkeypatch) -> None:
        """Only TLSv1.2 and TLSv1.3 supported → two True, two False."""
        def fake_probe(host, port, label, _min_v, _max_v, timeout):
            supported = label in ("TLSv1.2", "TLSv1.3")
            return TLSVersionProbeResult(
                label=label,
                supported=supported,
                error_message=None if supported else "unsupported",
            )

        monkeypatch.setattr(
            "webconf_audit.external.recon.tls_probe._probe_single_version",
            fake_probe,
        )
        results = probe_tls_versions("example.com", 443)
        support_map = {r.label: r.supported for r in results}
        assert support_map == {
            "TLSv1": False,
            "TLSv1.1": False,
            "TLSv1.2": True,
            "TLSv1.3": True,
        }

    def test_passes_timeout(self, monkeypatch) -> None:
        """Custom timeout should propagate to _probe_single_version."""
        captured_timeouts = []

        def fake_probe(host, port, label, _min_v, _max_v, timeout):
            captured_timeouts.append(timeout)
            return TLSVersionProbeResult(label=label, supported=True)

        monkeypatch.setattr(
            "webconf_audit.external.recon.tls_probe._probe_single_version",
            fake_probe,
        )
        probe_tls_versions("example.com", 443, timeout=5.0)
        assert all(t == 5.0 for t in captured_timeouts)


class TestSupportedProtocolLabels:
    def test_filters_supported(self) -> None:
        results = [
            TLSVersionProbeResult(label="TLSv1", supported=False),
            TLSVersionProbeResult(label="TLSv1.1", supported=False),
            TLSVersionProbeResult(label="TLSv1.2", supported=True),
            TLSVersionProbeResult(label="TLSv1.3", supported=True),
        ]
        assert supported_protocol_labels(results) == ("TLSv1.2", "TLSv1.3")

    def test_empty_when_none_supported(self) -> None:
        results = [
            TLSVersionProbeResult(label="TLSv1", supported=False),
            TLSVersionProbeResult(label="TLSv1.1", supported=False),
        ]
        assert supported_protocol_labels(results) == ()

    def test_all_supported(self) -> None:
        results = [
            TLSVersionProbeResult(label="TLSv1.2", supported=True),
            TLSVersionProbeResult(label="TLSv1.3", supported=True),
        ]
        assert supported_protocol_labels(results) == ("TLSv1.2", "TLSv1.3")

    def test_empty_input(self) -> None:
        assert supported_protocol_labels([]) == ()


# ---------------------------------------------------------------------------
# Integration: tls_probe results flow into recon pipeline
# ---------------------------------------------------------------------------


def _make_https_attempt(
    supported_protocols: tuple[str, ...] = (),
    **tls_kwargs,
) -> ProbeAttempt:
    tls = TLSInfo(
        protocol_version="TLSv1.3",
        supported_protocols=supported_protocols,
        **tls_kwargs,
    )
    return ProbeAttempt(
        target=ProbeTarget(scheme="https", host="example.com", port=443, path="/"),
        tcp_open=True,
        effective_method="GET",
        status_code=200,
        reason_phrase="OK",
        server_header="nginx/1.25",
        tls_info=tls,
    )


def _setup_enrichment_mocks(
    monkeypatch,
    attempt,
    tls_version_results=None,
    chain_result=None,
    depth_result=None,
):
    """Wire up monkeypatches for tests that exercise _enrich_tls_with_version_probe."""
    monkeypatch.setattr(
        "webconf_audit.external.recon._build_probe_targets",
        lambda t: [attempt.target],
    )
    monkeypatch.setattr(
        "webconf_audit.external.recon._is_tcp_port_open",
        lambda h, p: True,
    )
    monkeypatch.setattr(
        "webconf_audit.external.recon._try_http_method",
        lambda pt, method: attempt,
    )
    monkeypatch.setattr(
        "webconf_audit.external.recon._try_options_request",
        lambda pt: None,
    )
    monkeypatch.setattr(
        "webconf_audit.external.recon._probe_sensitive_paths",
        lambda _successful_attempts, identification=None: [],
    )

    if tls_version_results is None:
        tls_version_results = [
            TLSVersionProbeResult(label="TLSv1.2", supported=True),
            TLSVersionProbeResult(label="TLSv1.3", supported=True),
        ]
    monkeypatch.setattr(
        "webconf_audit.external.recon.tls_probe.probe_tls_versions",
        lambda host, port, **kw: tls_version_results,
    )

    if chain_result is None:
        chain_result = ChainVerificationResult(verified=True)
    monkeypatch.setattr(
        "webconf_audit.external.recon.tls_probe.verify_certificate_chain",
        lambda host, port, **kw: chain_result,
    )

    if depth_result is None:
        depth_result = ChainDepthResult(depth=2)
    monkeypatch.setattr(
        "webconf_audit.external.recon.tls_probe.probe_chain_depth",
        lambda host, port, **kw: depth_result,
    )


class TestTlsProbeIntegration:
    """Verify that _enrich_tls_with_version_probe injects supported_protocols and chain info."""

    def test_supported_protocols_in_metadata(self, monkeypatch) -> None:
        """When TLS probing succeeds, metadata includes supported_protocols."""
        attempt = _make_https_attempt()
        _setup_enrichment_mocks(monkeypatch, attempt)

        result = analyze_external_target("example.com")
        probes = result.metadata["probe_attempts"]
        tls_meta = probes[0]["tls_info"]
        assert tls_meta["supported_protocols"] == ["TLSv1.2", "TLSv1.3"]

    def test_supported_protocols_in_diagnostics(self, monkeypatch) -> None:
        """Diagnostics should include tls_supported line."""
        attempt = _make_https_attempt(supported_protocols=("TLSv1.2", "TLSv1.3"))

        monkeypatch.setattr(
            "webconf_audit.external.recon._build_probe_targets",
            lambda t: [attempt.target],
        )
        monkeypatch.setattr(
            "webconf_audit.external.recon._probe_target",
            lambda pt: attempt,
        )
        monkeypatch.setattr(
            "webconf_audit.external.recon._probe_sensitive_paths",
            lambda _successful_attempts, identification=None: [],
        )

        result = analyze_external_target("example.com")
        tls_diag = [d for d in result.diagnostics if d.startswith("tls_supported:")]
        assert len(tls_diag) == 1
        assert "TLSv1.2" in tls_diag[0]
        assert "TLSv1.3" in tls_diag[0]

    def test_http_attempt_skips_tls_probe(self, monkeypatch) -> None:
        """HTTP-only attempts should not trigger TLS version probing."""
        attempt = ProbeAttempt(
            target=ProbeTarget(scheme="http", host="example.com", port=80, path="/"),
            tcp_open=True,
            effective_method="GET",
            status_code=200,
            reason_phrase="OK",
            server_header="nginx/1.25",
            tls_info=None,
        )

        probe_called = []

        monkeypatch.setattr(
            "webconf_audit.external.recon._build_probe_targets",
            lambda t: [attempt.target],
        )
        monkeypatch.setattr(
            "webconf_audit.external.recon._probe_target",
            lambda pt: attempt,
        )
        monkeypatch.setattr(
            "webconf_audit.external.recon._probe_sensitive_paths",
            lambda _successful_attempts, identification=None: [],
        )

        original_probe = probe_tls_versions

        def tracking_probe(host, port, **kw):
            probe_called.append(True)
            return original_probe(host, port, **kw)

        monkeypatch.setattr(
            "webconf_audit.external.recon.tls_probe.probe_tls_versions",
            tracking_probe,
        )

        analyze_external_target("example.com")
        assert len(probe_called) == 0

    def test_tls_probe_all_versions_supported(self, monkeypatch) -> None:
        """When all 4 versions are supported, all appear in metadata."""
        attempt = _make_https_attempt()
        _setup_enrichment_mocks(
            monkeypatch, attempt,
            tls_version_results=[
                TLSVersionProbeResult(label=lbl, supported=True)
                for lbl in ("TLSv1", "TLSv1.1", "TLSv1.2", "TLSv1.3")
            ],
        )

        result = analyze_external_target("example.com")
        tls_meta = result.metadata["probe_attempts"][0]["tls_info"]
        assert tls_meta["supported_protocols"] == [
            "TLSv1", "TLSv1.1", "TLSv1.2", "TLSv1.3",
        ]

    def test_tls_probe_none_supported(self, monkeypatch) -> None:
        """When no versions succeed (edge case), supported_protocols is empty."""
        attempt = _make_https_attempt()
        _setup_enrichment_mocks(
            monkeypatch, attempt,
            tls_version_results=[
                TLSVersionProbeResult(label=lbl, supported=False, error_message="fail")
                for lbl in ("TLSv1", "TLSv1.1", "TLSv1.2", "TLSv1.3")
            ],
        )

        result = analyze_external_target("example.com")
        tls_meta = result.metadata["probe_attempts"][0]["tls_info"]
        assert tls_meta["supported_protocols"] == []


# ---------------------------------------------------------------------------
# Integration: cert_chain_depth flows into recon metadata and diagnostics
# ---------------------------------------------------------------------------


class TestChainDepthIntegration:
    """Verify cert_chain_depth is populated from probe_chain_depth in the pipeline."""

    def test_cert_chain_depth_in_metadata(self, monkeypatch) -> None:
        """cert_chain_depth appears in tls_info metadata when measured."""
        attempt = _make_https_attempt()
        _setup_enrichment_mocks(
            monkeypatch, attempt, depth_result=ChainDepthResult(depth=3),
        )

        result = analyze_external_target("example.com")
        tls_meta = result.metadata["probe_attempts"][0]["tls_info"]
        assert tls_meta["cert_chain_depth"] == 3

    def test_cert_chain_depth_none_in_metadata(self, monkeypatch) -> None:
        """depth=None is passed through to metadata as None."""
        attempt = _make_https_attempt()
        _setup_enrichment_mocks(
            monkeypatch, attempt,
            depth_result=ChainDepthResult(depth=None, error_message="timeout"),
        )

        result = analyze_external_target("example.com")
        tls_meta = result.metadata["probe_attempts"][0]["tls_info"]
        assert tls_meta["cert_chain_depth"] is None

    def test_cert_chain_depth_in_diagnostics(self, monkeypatch) -> None:
        """Diagnostics should include cert_chain_depth line when depth is known."""
        attempt = _make_https_attempt(cert_chain_depth=2)

        monkeypatch.setattr(
            "webconf_audit.external.recon._build_probe_targets",
            lambda t: [attempt.target],
        )
        monkeypatch.setattr(
            "webconf_audit.external.recon._probe_target",
            lambda pt: attempt,
        )
        monkeypatch.setattr(
            "webconf_audit.external.recon._probe_sensitive_paths",
            lambda _successful_attempts, identification=None: [],
        )

        result = analyze_external_target("example.com")
        depth_diag = [d for d in result.diagnostics if d.startswith("cert_chain_depth:")]
        assert len(depth_diag) == 1
        assert "2" in depth_diag[0]

    def test_cert_chain_depth_absent_from_diagnostics_when_none(self, monkeypatch) -> None:
        """No cert_chain_depth line in diagnostics when depth is None."""
        attempt = _make_https_attempt(cert_chain_depth=None)

        monkeypatch.setattr(
            "webconf_audit.external.recon._build_probe_targets",
            lambda t: [attempt.target],
        )
        monkeypatch.setattr(
            "webconf_audit.external.recon._probe_target",
            lambda pt: attempt,
        )
        monkeypatch.setattr(
            "webconf_audit.external.recon._probe_sensitive_paths",
            lambda _successful_attempts, identification=None: [],
        )

        result = analyze_external_target("example.com")
        depth_diag = [d for d in result.diagnostics if d.startswith("cert_chain_depth:")]
        assert depth_diag == []

    def test_tlsinfo_dataclass_accepts_cert_chain_depth(self) -> None:
        """TLSInfo can be constructed with cert_chain_depth."""
        tls = TLSInfo(cert_chain_depth=4)
        assert tls.cert_chain_depth == 4

    def test_tlsinfo_cert_chain_depth_defaults_to_none(self) -> None:
        """Existing TLSInfo constructors without cert_chain_depth still work."""
        tls = TLSInfo(protocol_version="TLSv1.3")
        assert tls.cert_chain_depth is None


# ---------------------------------------------------------------------------
# Unit tests for verify_certificate_chain
# ---------------------------------------------------------------------------


class TestVerifyCertificateChain:
    def test_valid_chain(self, monkeypatch) -> None:
        """Successful verified handshake → verified=True."""
        mock_raw = MagicMock()
        mock_raw.configure_mock(**{
            "__enter__.return_value": mock_raw,
            "__exit__.return_value": False,
        })

        mock_tls = MagicMock()
        mock_tls.configure_mock(**{
            "__enter__.return_value": mock_tls,
            "__exit__.return_value": False,
        })

        mock_ctx = MagicMock()
        mock_ctx.configure_mock(**{"wrap_socket.return_value": mock_tls})

        monkeypatch.setattr(
            "webconf_audit.external.recon.tls_probe.ssl.create_default_context",
            lambda: mock_ctx,
        )
        monkeypatch.setattr(
            "webconf_audit.external.recon.tls_probe.socket.create_connection",
            lambda addr, timeout: mock_raw,
        )

        result = verify_certificate_chain("example.com", 443)
        assert result.verified is True
        assert result.error_message is None

    def test_verification_error(self, monkeypatch) -> None:
        """SSLCertVerificationError → verified=False with error."""
        monkeypatch.setattr(
            "webconf_audit.external.recon.tls_probe.ssl.create_default_context",
            lambda: MagicMock(),
        )

        def fail_connect(addr, timeout):
            raise ssl.SSLCertVerificationError("certificate verify failed")

        monkeypatch.setattr(
            "webconf_audit.external.recon.tls_probe.socket.create_connection",
            fail_connect,
        )

        result = verify_certificate_chain("example.com", 443)
        assert result.verified is False
        assert "certificate verify failed" in result.error_message

    def test_expired_cert_is_indeterminate(self, monkeypatch) -> None:
        """Expired certificate → verified=None (not a chain issue)."""
        monkeypatch.setattr(
            "webconf_audit.external.recon.tls_probe.ssl.create_default_context",
            lambda: MagicMock(),
        )

        def fail_connect(addr, timeout):
            exc = ssl.SSLCertVerificationError("certificate has expired")
            exc.verify_code = 10  # X509_V_ERR_CERT_HAS_EXPIRED
            raise exc

        monkeypatch.setattr(
            "webconf_audit.external.recon.tls_probe.socket.create_connection",
            fail_connect,
        )

        result = verify_certificate_chain("example.com", 443)
        assert result.verified is None
        assert result.error_message is None

    def test_not_yet_valid_cert_is_indeterminate(self, monkeypatch) -> None:
        """Not-yet-valid certificate → verified=None (not a chain issue)."""
        monkeypatch.setattr(
            "webconf_audit.external.recon.tls_probe.ssl.create_default_context",
            lambda: MagicMock(),
        )

        def fail_connect(addr, timeout):
            exc = ssl.SSLCertVerificationError("certificate is not yet valid")
            exc.verify_code = 9  # X509_V_ERR_CERT_NOT_YET_VALID
            raise exc

        monkeypatch.setattr(
            "webconf_audit.external.recon.tls_probe.socket.create_connection",
            fail_connect,
        )

        result = verify_certificate_chain("example.com", 443)
        assert result.verified is None
        assert result.error_message is None

    def test_self_signed_cert_is_chain_failure(self, monkeypatch) -> None:
        """Self-signed certificate → verified=False (chain issue)."""
        monkeypatch.setattr(
            "webconf_audit.external.recon.tls_probe.ssl.create_default_context",
            lambda: MagicMock(),
        )

        def fail_connect(addr, timeout):
            exc = ssl.SSLCertVerificationError("self-signed certificate")
            exc.verify_code = 18  # X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT
            raise exc

        monkeypatch.setattr(
            "webconf_audit.external.recon.tls_probe.socket.create_connection",
            fail_connect,
        )

        result = verify_certificate_chain("example.com", 443)
        assert result.verified is False
        assert "self-signed certificate" in result.error_message

    def test_unable_to_get_issuer_is_chain_failure(self, monkeypatch) -> None:
        """Missing intermediate → verified=False (chain issue)."""
        monkeypatch.setattr(
            "webconf_audit.external.recon.tls_probe.ssl.create_default_context",
            lambda: MagicMock(),
        )

        def fail_connect(addr, timeout):
            exc = ssl.SSLCertVerificationError(
                "unable to get local issuer certificate"
            )
            exc.verify_code = 20  # X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY
            raise exc

        monkeypatch.setattr(
            "webconf_audit.external.recon.tls_probe.socket.create_connection",
            fail_connect,
        )

        result = verify_certificate_chain("example.com", 443)
        assert result.verified is False
        assert "unable to get local issuer" in result.error_message

    def test_os_error_is_indeterminate(self, monkeypatch) -> None:
        """Network-level OSError → verified=None (indeterminate)."""
        monkeypatch.setattr(
            "webconf_audit.external.recon.tls_probe.ssl.create_default_context",
            lambda: MagicMock(),
        )

        def fail_connect(addr, timeout):
            raise OSError("Connection refused")

        monkeypatch.setattr(
            "webconf_audit.external.recon.tls_probe.socket.create_connection",
            fail_connect,
        )

        result = verify_certificate_chain("example.com", 443)
        assert result.verified is None
        assert result.error_message is None

    def test_ssl_error_non_verification_is_indeterminate(self, monkeypatch) -> None:
        """Generic SSLError (not verification) → verified=None (indeterminate)."""
        monkeypatch.setattr(
            "webconf_audit.external.recon.tls_probe.ssl.create_default_context",
            lambda: MagicMock(),
        )

        def fail_connect(addr, timeout):
            raise ssl.SSLError("handshake failure")

        monkeypatch.setattr(
            "webconf_audit.external.recon.tls_probe.socket.create_connection",
            fail_connect,
        )

        result = verify_certificate_chain("example.com", 443)
        assert result.verified is None
        assert result.error_message is None


# ---------------------------------------------------------------------------
# Integration: chain verification flows into recon pipeline
# ---------------------------------------------------------------------------


class TestChainVerificationIntegration:
    def test_cert_chain_complete_true_in_metadata(self, monkeypatch) -> None:
        attempt = _make_https_attempt()
        _setup_enrichment_mocks(
            monkeypatch, attempt,
            chain_result=ChainVerificationResult(verified=True),
        )

        result = analyze_external_target("example.com")
        tls_meta = result.metadata["probe_attempts"][0]["tls_info"]
        assert tls_meta["cert_chain_complete"] is True
        assert tls_meta["cert_chain_error"] is None

    def test_cert_chain_complete_false_in_metadata(self, monkeypatch) -> None:
        attempt = _make_https_attempt()
        _setup_enrichment_mocks(
            monkeypatch, attempt,
            chain_result=ChainVerificationResult(
                verified=False,
                error_message="certificate verify failed: self-signed certificate",
            ),
        )

        result = analyze_external_target("example.com")
        tls_meta = result.metadata["probe_attempts"][0]["tls_info"]
        assert tls_meta["cert_chain_complete"] is False
        assert "self-signed certificate" in tls_meta["cert_chain_error"]

    def test_cert_chain_complete_in_diagnostics(self, monkeypatch) -> None:
        attempt = _make_https_attempt(
            cert_chain_complete=True,
        )

        monkeypatch.setattr(
            "webconf_audit.external.recon._build_probe_targets",
            lambda t: [attempt.target],
        )
        monkeypatch.setattr(
            "webconf_audit.external.recon._probe_target",
            lambda pt: attempt,
        )
        monkeypatch.setattr(
            "webconf_audit.external.recon._probe_sensitive_paths",
            lambda _successful_attempts, identification=None: [],
        )

        result = analyze_external_target("example.com")
        chain_diag = [d for d in result.diagnostics if d.startswith("cert_chain_complete:")]
        assert len(chain_diag) == 1
        assert "True" in chain_diag[0]

    def test_cert_chain_error_in_diagnostics(self, monkeypatch) -> None:
        attempt = _make_https_attempt(
            cert_chain_complete=False,
            cert_chain_error="certificate verify failed",
        )

        monkeypatch.setattr(
            "webconf_audit.external.recon._build_probe_targets",
            lambda t: [attempt.target],
        )
        monkeypatch.setattr(
            "webconf_audit.external.recon._probe_target",
            lambda pt: attempt,
        )
        monkeypatch.setattr(
            "webconf_audit.external.recon._probe_sensitive_paths",
            lambda _successful_attempts, identification=None: [],
        )

        result = analyze_external_target("example.com")
        err_diag = [d for d in result.diagnostics if d.startswith("cert_chain_error:")]
        assert len(err_diag) == 1
        assert "certificate verify failed" in err_diag[0]

    def test_http_attempt_no_chain_fields(self, monkeypatch) -> None:
        """HTTP attempts should have no cert_chain_complete in metadata."""
        attempt = ProbeAttempt(
            target=ProbeTarget(scheme="http", host="example.com", port=80, path="/"),
            tcp_open=True,
            effective_method="GET",
            status_code=200,
            reason_phrase="OK",
            server_header="nginx/1.25",
            tls_info=None,
        )

        monkeypatch.setattr(
            "webconf_audit.external.recon._build_probe_targets",
            lambda t: [attempt.target],
        )
        monkeypatch.setattr(
            "webconf_audit.external.recon._probe_target",
            lambda pt: attempt,
        )
        monkeypatch.setattr(
            "webconf_audit.external.recon._probe_sensitive_paths",
            lambda _successful_attempts, identification=None: [],
        )

        result = analyze_external_target("example.com")
        tls_meta = result.metadata["probe_attempts"][0]["tls_info"]
        assert tls_meta is None


# ---------------------------------------------------------------------------
# Unit tests for probe_chain_depth
# ---------------------------------------------------------------------------


class TestChainDepthResult:
    """ChainDepthResult dataclass contract."""

    def test_frozen(self) -> None:
        r = ChainDepthResult(depth=2)
        with pytest.raises(AttributeError):
            r.depth = 99  # type: ignore[misc]

    def test_slots(self) -> None:
        assert not hasattr(ChainDepthResult(depth=1), "__dict__")

    def test_defaults(self) -> None:
        r = ChainDepthResult(depth=3)
        assert r.depth == 3
        assert r.error_message is None

    def test_none_depth(self) -> None:
        r = ChainDepthResult(depth=None, error_message="timeout")
        assert r.depth is None
        assert r.error_message == "timeout"

    def test_zero_depth(self) -> None:
        r = ChainDepthResult(depth=0)
        assert r.depth == 0


class TestProbeChainDepth:
    """probe_chain_depth unit tests (all network I/O mocked)."""

    def _make_mock_conn(self, chain_length: int) -> MagicMock:
        """Return a mock OpenSSL Connection whose get_peer_cert_chain() returns N certs."""
        conn = MagicMock()
        conn.configure_mock(**{
            "get_peer_cert_chain.return_value": [MagicMock() for _ in range(chain_length)]
        })
        return conn

    def test_depth_two_certs(self, monkeypatch) -> None:
        """leaf + one intermediate → depth=2."""
        conn_mock = self._make_mock_conn(2)
        monkeypatch.setattr(
            "webconf_audit.external.recon.tls_probe._OSSL.Connection",
            lambda ctx, sock: conn_mock,
        )
        monkeypatch.setattr(
            "webconf_audit.external.recon.tls_probe.socket.create_connection",
            lambda *a, **kw: MagicMock(),
        )
        result = probe_chain_depth("example.com", 443)
        assert result.depth == 2
        assert result.error_message is None

    def test_depth_three_certs(self, monkeypatch) -> None:
        """leaf + two intermediates → depth=3."""
        conn_mock = self._make_mock_conn(3)
        monkeypatch.setattr(
            "webconf_audit.external.recon.tls_probe._OSSL.Connection",
            lambda ctx, sock: conn_mock,
        )
        monkeypatch.setattr(
            "webconf_audit.external.recon.tls_probe.socket.create_connection",
            lambda *a, **kw: MagicMock(),
        )
        result = probe_chain_depth("example.com", 443)
        assert result.depth == 3

    def test_depth_one_leaf_only(self, monkeypatch) -> None:
        """Server sends only the leaf certificate → depth=1."""
        conn_mock = self._make_mock_conn(1)
        monkeypatch.setattr(
            "webconf_audit.external.recon.tls_probe._OSSL.Connection",
            lambda ctx, sock: conn_mock,
        )
        monkeypatch.setattr(
            "webconf_audit.external.recon.tls_probe.socket.create_connection",
            lambda *a, **kw: MagicMock(),
        )
        result = probe_chain_depth("example.com", 443)
        assert result.depth == 1

    def test_empty_chain_returns_zero(self, monkeypatch) -> None:
        """get_peer_cert_chain() returning [] → depth=0 (boundary case)."""
        conn_mock = MagicMock()
        conn_mock.configure_mock(**{"get_peer_cert_chain.return_value": []})
        monkeypatch.setattr(
            "webconf_audit.external.recon.tls_probe._OSSL.Connection",
            lambda ctx, sock: conn_mock,
        )
        monkeypatch.setattr(
            "webconf_audit.external.recon.tls_probe.socket.create_connection",
            lambda *a, **kw: MagicMock(),
        )
        result = probe_chain_depth("example.com", 443)
        assert result.depth == 0

    def test_none_chain_returns_none(self, monkeypatch) -> None:
        """get_peer_cert_chain() returning None → depth=None (indeterminate)."""
        conn_mock = MagicMock()
        conn_mock.configure_mock(**{"get_peer_cert_chain.return_value": None})
        monkeypatch.setattr(
            "webconf_audit.external.recon.tls_probe._OSSL.Connection",
            lambda ctx, sock: conn_mock,
        )
        monkeypatch.setattr(
            "webconf_audit.external.recon.tls_probe.socket.create_connection",
            lambda *a, **kw: MagicMock(),
        )
        result = probe_chain_depth("example.com", 443)
        assert result.depth is None
        assert result.error_message is not None

    def test_os_error_returns_none(self, monkeypatch) -> None:
        """Network error → depth=None, error_message set."""
        monkeypatch.setattr(
            "webconf_audit.external.recon.tls_probe.socket.create_connection",
            lambda *a, **kw: (_ for _ in ()).throw(OSError("connection refused")),
        )
        result = probe_chain_depth("example.com", 443)
        assert result.depth is None
        assert result.error_message is not None
        assert "connection refused" in result.error_message

    def test_openssl_error_returns_none(self, monkeypatch) -> None:
        """OpenSSL.SSL.Error during handshake → depth=None."""
        from OpenSSL import SSL as OSSL

        conn_mock = MagicMock()
        conn_mock.configure_mock(**{
            "do_handshake.side_effect": OSSL.Error([("handshake", "failed")])
        })
        monkeypatch.setattr(
            "webconf_audit.external.recon.tls_probe._OSSL.Connection",
            lambda ctx, sock: conn_mock,
        )
        monkeypatch.setattr(
            "webconf_audit.external.recon.tls_probe.socket.create_connection",
            lambda *a, **kw: MagicMock(),
        )
        result = probe_chain_depth("example.com", 443)
        assert result.depth is None
        assert result.error_message is not None

    def test_sni_set(self, monkeypatch) -> None:
        """SNI host name must be passed to the connection."""
        conn_mock = self._make_mock_conn(2)
        monkeypatch.setattr(
            "webconf_audit.external.recon.tls_probe._OSSL.Connection",
            lambda ctx, sock: conn_mock,
        )
        monkeypatch.setattr(
            "webconf_audit.external.recon.tls_probe.socket.create_connection",
            lambda *a, **kw: MagicMock(),
        )
        probe_chain_depth("myhost.example.com", 443)
        conn_mock.set_tlsext_host_name.assert_called_once_with(b"myhost.example.com")

    def test_connect_state_called(self, monkeypatch) -> None:
        """set_connect_state must be called (configures client mode)."""
        conn_mock = self._make_mock_conn(2)
        monkeypatch.setattr(
            "webconf_audit.external.recon.tls_probe._OSSL.Connection",
            lambda ctx, sock: conn_mock,
        )
        monkeypatch.setattr(
            "webconf_audit.external.recon.tls_probe.socket.create_connection",
            lambda *a, **kw: MagicMock(),
        )
        probe_chain_depth("example.com", 443)
        conn_mock.set_connect_state.assert_called_once()

    def test_timeout_passed_to_create_connection(self, monkeypatch) -> None:
        """Custom timeout must reach socket.create_connection."""
        captured: list[float] = []

        def fake_create_connection(addr, timeout=None):
            captured.append(timeout)
            return MagicMock()

        conn_mock = self._make_mock_conn(1)
        monkeypatch.setattr(
            "webconf_audit.external.recon.tls_probe._OSSL.Connection",
            lambda ctx, sock: conn_mock,
        )
        monkeypatch.setattr(
            "webconf_audit.external.recon.tls_probe.socket.create_connection",
            fake_create_connection,
        )
        probe_chain_depth("example.com", 443, timeout=7.5)
        assert captured == [7.5]

    def test_sni_idna_encoding(self, monkeypatch) -> None:
        """Non-ASCII hostnames must be IDNA-encoded for SNI."""
        conn_mock = self._make_mock_conn(2)
        monkeypatch.setattr(
            "webconf_audit.external.recon.tls_probe._OSSL.Connection",
            lambda ctx, sock: conn_mock,
        )
        monkeypatch.setattr(
            "webconf_audit.external.recon.tls_probe.socket.create_connection",
            lambda *a, **kw: MagicMock(),
        )
        probe_chain_depth("münchen.de", 443)
        conn_mock.set_tlsext_host_name.assert_called_once_with(b"xn--mnchen-3ya.de")

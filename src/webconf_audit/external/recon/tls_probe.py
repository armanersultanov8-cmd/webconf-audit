"""Active TLS version probing and certificate-chain depth measurement.

For each TLS/SSL protocol version the Python ``ssl`` module can express,
attempts a constrained handshake against the target to determine whether
the server supports that version.  The result is a tuple of human-readable
protocol labels (e.g. ``("TLSv1.2", "TLSv1.3")``) suitable for storing
in :pyattr:`TLSInfo.supported_protocols`.

:func:`probe_chain_depth` uses ``pyOpenSSL`` (``OpenSSL.SSL``) to retrieve
the full intermediate-certificate chain supplied by the server, which the
Python ``ssl`` stdlib does not expose.
"""

from __future__ import annotations

import logging
import socket
import ssl
import warnings
from dataclasses import dataclass

from OpenSSL import SSL as _OSSL

_logger = logging.getLogger(__name__)

# Own timeout constant — avoids coupling to recon.py and circular-import
# fragility.  Kept in sync with recon.DEFAULT_TIMEOUT_SECONDS by convention.
DEFAULT_PROBE_TIMEOUT_SECONDS: float = 2.0

# --- Protocol definitions ---------------------------------------------------

# Each entry maps a human-readable label to the ``ssl`` module attributes
# needed to constrain a context to *only* that version.
#
# Python >= 3.10 deprecated the per-version ``PROTOCOL_TLSv1`` etc. constants
# in favour of ``TLSVersion`` min/max pinning on a ``TLS_CLIENT`` context.
# We use the modern approach exclusively.

_TLS_VERSIONS: tuple[tuple[str, ssl.TLSVersion, ssl.TLSVersion], ...] = (
    ("TLSv1", ssl.TLSVersion.TLSv1, ssl.TLSVersion.TLSv1),
    ("TLSv1.1", ssl.TLSVersion.TLSv1_1, ssl.TLSVersion.TLSv1_1),
    ("TLSv1.2", ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_2),
    ("TLSv1.3", ssl.TLSVersion.TLSv1_3, ssl.TLSVersion.TLSv1_3),
)


@dataclass(frozen=True, slots=True)
class TLSVersionProbeResult:
    """Outcome of probing a single TLS version against one host:port."""

    label: str
    supported: bool
    error_message: str | None = None


# --- Probing ----------------------------------------------------------------


def _build_tls_context(
    min_ver: ssl.TLSVersion,
    max_ver: ssl.TLSVersion,
) -> ssl.SSLContext:
    """Create an ``SSLContext`` pinned to a single TLS version.

    Certificate verification is disabled because we are interested only in
    whether the handshake succeeds at the protocol level, not whether the
    certificate is trusted.
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    # Python 3.14 warns when pinning deprecated legacy protocol versions
    # (TLSv1/TLSv1.1). We still intentionally probe them to detect insecure
    # server support, so suppress only this narrow warning at assignment time.
    with warnings.catch_warnings():
        warnings.filterwarnings(
            "ignore",
            category=DeprecationWarning,
            message=r"ssl\.TLSVersion\.TLSv1(?:_1)? is deprecated",
        )
        ctx.minimum_version = min_ver
        ctx.maximum_version = max_ver
    return ctx


def _probe_single_version(
    host: str,
    port: int,
    label: str,
    min_ver: ssl.TLSVersion,
    max_ver: ssl.TLSVersion,
    timeout: float,
) -> TLSVersionProbeResult:
    """Try a TLS handshake constrained to one protocol version."""
    try:
        ctx = _build_tls_context(min_ver, max_ver)
        with socket.create_connection((host, port), timeout=timeout) as raw_sock:
            with ctx.wrap_socket(raw_sock, server_hostname=host) as _tls_sock:
                return TLSVersionProbeResult(label=label, supported=True)
    except (OSError, ssl.SSLError) as exc:
        return TLSVersionProbeResult(
            label=label, supported=False, error_message=str(exc),
        )


def probe_tls_versions(
    host: str,
    port: int,
    timeout: float = DEFAULT_PROBE_TIMEOUT_SECONDS,
) -> list[TLSVersionProbeResult]:
    """Probe *host*:*port* for each known TLS version.

    Returns a list of :class:`TLSVersionProbeResult` in ascending version
    order (TLSv1 … TLSv1.3).  Each entry states whether that version is
    supported.
    """
    results: list[TLSVersionProbeResult] = []
    for label, min_ver, max_ver in _TLS_VERSIONS:
        results.append(
            _probe_single_version(host, port, label, min_ver, max_ver, timeout)
        )
    return results


def supported_protocol_labels(
    results: list[TLSVersionProbeResult],
) -> tuple[str, ...]:
    """Extract the labels of supported versions from probe results."""
    return tuple(r.label for r in results if r.supported)


# --- Certificate chain verification ----------------------------------------


@dataclass(frozen=True, slots=True)
class ChainVerificationResult:
    """Outcome of verifying the certificate chain against the system CA store.

    ``verified`` is *True* when the chain is complete and trusted, *False*
    when the chain is definitively broken (e.g. self-signed, missing
    intermediate), and *None* when the check was indeterminate (network
    error, non-verification TLS failure).
    """

    verified: bool | None
    error_message: str | None = None


# OpenSSL verify error codes that represent leaf-certificate validity
# problems rather than trust-chain / intermediate-certificate issues.
# When the *only* failure is one of these, the chain itself is fine.
_LEAF_VALIDITY_VERIFY_CODES: frozenset[int] = frozenset({
    10,  # X509_V_ERR_CERT_HAS_EXPIRED
    9,   # X509_V_ERR_CERT_NOT_YET_VALID
    # Hostname mismatch should not happen (check_hostname=False) but
    # guard against it anyway.
    62,  # X509_V_ERR_HOSTNAME_MISMATCH
})


def verify_certificate_chain(
    host: str,
    port: int,
    timeout: float = DEFAULT_PROBE_TIMEOUT_SECONDS,
) -> ChainVerificationResult:
    """Verify the certificate trust chain against the system CA store.

    Uses :func:`ssl.create_default_context` to load the system CA bundle,
    but **disables hostname checking** so that a hostname / SAN mismatch
    does not cause a false ``cert_chain_incomplete`` finding.

    Leaf-certificate validity problems (expired, not-yet-valid) are
    treated as **indeterminate** for chain-completeness purposes — the
    chain itself may be perfectly fine even though the leaf cert has an
    independent validity issue.  Only trust-chain failures (self-signed,
    missing intermediates, untrusted root) yield ``verified=False``.

    Generic network or TLS errors also yield ``verified=None``.
    """
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False  # hostname mismatch is NOT a chain issue
        with socket.create_connection((host, port), timeout=timeout) as raw_sock:
            with ctx.wrap_socket(raw_sock, server_hostname=host) as _tls_sock:
                return ChainVerificationResult(verified=True)
    except ssl.SSLCertVerificationError as exc:
        # Distinguish chain failures from leaf-validity failures.
        verify_code = getattr(exc, "verify_code", None)
        if verify_code is not None and verify_code in _LEAF_VALIDITY_VERIFY_CODES:
            # Leaf issue (expired, not-yet-valid) — not a chain problem.
            return ChainVerificationResult(verified=None)
        return ChainVerificationResult(verified=False, error_message=str(exc))
    except (OSError, ssl.SSLError):
        # Network or non-verification TLS errors — we cannot determine
        # chain status; return None to signal indeterminate.
        return ChainVerificationResult(verified=None)


# --- Certificate chain depth ------------------------------------------------


@dataclass(frozen=True, slots=True)
class ChainDepthResult:
    """Outcome of measuring the certificate chain depth via pyOpenSSL.

    ``depth`` is the number of certificates the server sent during the
    handshake (leaf + all intermediates it supplied).  A value of ``1``
    means only the leaf was presented (no intermediates); a value of
    ``None`` means the measurement could not be taken (network error,
    TLS error, unexpected exception).
    """

    depth: int | None
    error_message: str | None = None


def probe_chain_depth(
    host: str,
    port: int,
    timeout: float = DEFAULT_PROBE_TIMEOUT_SECONDS,
) -> ChainDepthResult:
    """Return the number of certificates the server supplied in the handshake.

    Uses ``pyOpenSSL`` (``OpenSSL.SSL``) which exposes
    :meth:`Connection.get_peer_cert_chain` — the Python ``ssl`` stdlib
    does not provide this information.

    Certificate verification is disabled so that expired / self-signed
    certificates do not prevent the chain from being retrieved.
    """
    raw_sock: socket.socket | None = None
    conn: _OSSL.Connection | None = None
    try:
        ctx = _OSSL.Context(_OSSL.TLS_METHOD)
        ctx.set_verify(_OSSL.VERIFY_NONE, lambda *_: True)

        raw_sock = socket.create_connection((host, port), timeout=timeout)
        conn = _OSSL.Connection(ctx, raw_sock)
        conn.set_tlsext_host_name(host.encode("idna"))
        conn.set_connect_state()
        conn.do_handshake()

        chain = conn.get_peer_cert_chain()
        if chain is None:
            return ChainDepthResult(depth=None, error_message="get_peer_cert_chain() returned None")
        return ChainDepthResult(depth=len(chain))
    except (OSError, _OSSL.Error, Exception) as exc:  # noqa: BLE001
        return ChainDepthResult(depth=None, error_message=str(exc))
    finally:
        if conn is not None:
            try:
                conn.close()
            except Exception:  # noqa: BLE001
                _logger.debug("Failed to close pyOpenSSL connection.", exc_info=True)
        if raw_sock is not None:
            try:
                raw_sock.close()
            except Exception:  # noqa: BLE001
                _logger.debug("Failed to close TLS probe raw socket.", exc_info=True)


__all__ = [
    "ChainDepthResult",
    "ChainVerificationResult",
    "TLSVersionProbeResult",
    "probe_chain_depth",
    "probe_tls_versions",
    "supported_protocol_labels",
    "verify_certificate_chain",
]

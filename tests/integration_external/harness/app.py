from __future__ import annotations

import ssl
import threading
from queue import Empty, Queue
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HTTP_PORT = 8080
HTTPS_PORT = 8443
HTTPS_EXTERNAL_BASE = "https://127.0.0.1:18443"

_SENSITIVE_BODIES: dict[str, tuple[str, str]] = {
    "/.git/HEAD": ("text/plain", "ref: refs/heads/main\n"),
    "/.env": ("text/plain", "APP_ENV=integration\nSECRET_KEY=test-secret\n"),
    "/.htaccess": ("text/plain", "RewriteEngine On\nDeny from all\n"),
    "/.htpasswd": ("text/plain", "admin:$apr1$test$abcdefghijk\n"),
    "/wp-admin/": ("text/html", "<html><body>WordPress admin</body></html>"),
    "/phpinfo.php": ("text/html", "<html><body>phpinfo()</body></html>"),
    "/elmah.axd": ("text/html", "<html><body>ELMAH logs</body></html>"),
    "/trace.axd": ("text/html", "<html><body>Trace.axd output</body></html>"),
    "/web.config": ("text/xml", "<configuration><system.webServer /></configuration>"),
    "/robots.txt": ("text/plain", "User-agent: *\nDisallow: /private/\n"),
    "/sitemap.xml": ("application/xml", "<urlset><url><loc>https://example.local/</loc></url></urlset>"),
    "/.svn/entries": ("text/plain", "dir\n12\n"),
}

_ROOT_BODY = """\
<html>
  <body>
    <h1>External Integration Harness</h1>
    <p>IIS-like response for external analyzer integration tests.</p>
  </body>
</html>
"""

_FINAL_BODY = """\
<html>
  <body>
    <h1>Redirect landing page</h1>
  </body>
</html>
"""


class HarnessHandler(BaseHTTPRequestHandler):
    server_version = "Microsoft-IIS/10.0"
    sys_version = ""
    protocol_version = "HTTP/1.1"

    def log_message(self, _format: str, *_args) -> None:
        return None

    def do_GET(self) -> None:
        self._handle_request(send_body=True)

    def do_HEAD(self) -> None:
        self._handle_request(send_body=False)

    def do_OPTIONS(self) -> None:
        allow = "GET, HEAD, OPTIONS"
        public = None

        if self.path == "/head-fallback":
            allow = "GET, HEAD, OPTIONS, TRACE, PROPFIND"
            public = allow
        elif self.path == "/allow-trace":
            allow = "GET, HEAD, OPTIONS, TRACE, PUT, PROPFIND"
            public = allow

        self._send_response(
            status=200,
            reason="OK",
            body="",
            send_body=False,
            extra_headers={
                "Allow": allow,
                **({"Public": public} if public is not None else {}),
            },
        )

    def _handle_request(self, *, send_body: bool) -> None:
        if "%%MALFORMED%%PATH" in self.path:
            self._send_iis_error(
                status=400,
                reason="Bad Request",
                body="<html><body><h1>Bad Request - Invalid URL</h1><p>Microsoft-IIS/10.0</p></body></html>",
                send_body=send_body,
            )
            return

        if self.path == "/_wca_nonexistent_404_probe":
            self._send_iis_error(
                status=404,
                reason="Not Found",
                body="<html><body><h2>IIS Detailed Error - 404.0</h2><p>Microsoft-IIS/10.0</p></body></html>",
                send_body=send_body,
            )
            return

        if self.path == "/head-fallback" and self.command == "HEAD":
            self._send_response(
                status=405,
                reason="Method Not Allowed",
                body="",
                send_body=False,
                extra_headers={"Allow": "GET, HEAD, OPTIONS, PUT"},
            )
            return

        if self.path == "/redirect-start":
            self._send_response(
                status=307,
                reason="Temporary Redirect",
                body="",
                send_body=False,
                extra_headers={"Location": f"{HTTPS_EXTERNAL_BASE}/redirect-middle"},
            )
            return

        if self.path == "/redirect-middle":
            self._send_response(
                status=302,
                reason="Found",
                body="",
                send_body=False,
                extra_headers={"Location": f"{HTTPS_EXTERNAL_BASE}/final"},
            )
            return

        if self.path == "/final":
            self._send_response(
                status=200,
                reason="OK",
                body=_FINAL_BODY,
                send_body=send_body,
                extra_headers=self._common_headers(is_https=self._is_https),
            )
            return

        if self.path == "/allow-trace":
            self._send_response(
                status=200,
                reason="OK",
                body="<html><body>Allow TRACE target</body></html>",
                send_body=send_body,
                extra_headers={
                    **self._common_headers(is_https=self._is_https),
                    "Allow": "GET, HEAD, OPTIONS, TRACE, PUT",
                    "Access-Control-Allow-Origin": "*",
                },
            )
            return

        if self.path == "/cors-open":
            self._send_response(
                status=200,
                reason="OK",
                body="<html><body>CORS open target</body></html>",
                send_body=send_body,
                extra_headers={
                    **self._common_headers(is_https=self._is_https),
                    "Access-Control-Allow-Origin": "*",
                },
            )
            return

        if self.path in _SENSITIVE_BODIES:
            content_type, body = _SENSITIVE_BODIES[self.path]
            self._send_response(
                status=200,
                reason="OK",
                body=body,
                send_body=send_body,
                extra_headers={
                    **self._common_headers(is_https=self._is_https),
                    "Content-Type": content_type,
                },
            )
            return

        self._send_response(
            status=200,
            reason="OK",
            body=_ROOT_BODY,
            send_body=send_body,
            extra_headers=self._common_headers(is_https=self._is_https),
        )

    @property
    def _is_https(self) -> bool:
        return bool(getattr(self.server, "is_https", False))

    def _common_headers(self, *, is_https: bool) -> dict[str, str]:
        headers = {
            "Content-Type": "text/html; charset=utf-8",
            "X-Powered-By": "ASP.NET",
            "X-AspNet-Version": "4.0.30319",
            "X-AspNetMvc-Version": "5.2",
        }
        if is_https:
            headers.update(
                {
                    "Strict-Transport-Security": "max-age=300",
                    "X-Frame-Options": "ALLOWALL",
                    "X-Content-Type-Options": "invalid",
                    "Content-Security-Policy": "default-src 'self' 'unsafe-inline' 'unsafe-eval'",
                    "Referrer-Policy": "unsafe-url",
                    "Cache-Control": "private",
                    "Access-Control-Allow-Origin": "*",
                    "Access-Control-Allow-Credentials": "true",
                    "Set-Cookie": "PHPSESSID=abc123, sessionid=xyz; SameSite=None",
                }
            )
        else:
            headers["Cache-Control"] = "no-store"
        return headers

    def _send_iis_error(
        self,
        *,
        status: int,
        reason: str,
        body: str,
        send_body: bool,
    ) -> None:
        self._send_response(
            status=status,
            reason=reason,
            body=body,
            send_body=send_body,
            extra_headers={
                **self._common_headers(is_https=self._is_https),
                "Content-Type": "text/html; charset=utf-8",
            },
        )

    def _send_response(
        self,
        *,
        status: int,
        reason: str,
        body: str,
        send_body: bool,
        extra_headers: dict[str, str] | None = None,
    ) -> None:
        encoded = body.encode("utf-8")
        self.send_response(status, reason)
        headers = extra_headers or {}
        for name, value in headers.items():
            if name == "Set-Cookie" and "," in value:
                for cookie in value.split(","):
                    self.send_header("Set-Cookie", cookie.strip())
                continue
            self.send_header(name, value)
        self.send_header("Content-Length", str(len(encoded)))
        self.send_header("Connection", "close")
        self.end_headers()
        if send_body:
            self.wfile.write(encoded)


def _serve_http() -> None:
    server = ThreadingHTTPServer(("0.0.0.0", HTTP_PORT), HarnessHandler)
    server.is_https = False
    server.serve_forever()


def _serve_https() -> None:
    server = ThreadingHTTPServer(("0.0.0.0", HTTPS_PORT), HarnessHandler)
    server.is_https = True
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.maximum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain("/app/certs/cert.pem", "/app/certs/key.pem")
    server.socket = context.wrap_socket(server.socket, server_side=True)
    server.serve_forever()


def main() -> None:
    errors: Queue[tuple[str, BaseException]] = Queue()

    def run_server(name: str, target) -> None:
        try:
            target()
        except BaseException as exc:
            errors.put((name, exc))
            raise

    http_thread = threading.Thread(
        target=run_server,
        args=("http", _serve_http),
        daemon=True,
    )
    https_thread = threading.Thread(
        target=run_server,
        args=("https", _serve_https),
        daemon=True,
    )
    http_thread.start()
    https_thread.start()

    while True:
        try:
            name, exc = errors.get(timeout=1.0)
        except Empty:
            # Queue timeout is the steady-state heartbeat of this loop,
            # not an error; chaining it onto the RuntimeError via implicit
            # exception context would dump an irrelevant ``During handling
            # of the above exception, another exception occurred`` block
            # into the traceback when a harness thread actually dies.
            if not http_thread.is_alive():
                raise RuntimeError("HTTP harness server stopped unexpectedly.") from None
            if not https_thread.is_alive():
                raise RuntimeError("HTTPS harness server stopped unexpectedly.") from None
            continue
        raise RuntimeError(f"{name.upper()} harness server failed.") from exc


if __name__ == "__main__":
    main()

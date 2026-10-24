"""Loopback-only local web dashboard shell for Group-IB monitoring."""

from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
from typing import Any

from config import AppConfig

HOST = "127.0.0.1"
PORT = 8765
WEB_ROOT = Path(__file__).resolve().parent / "web"
INDEX_FILE = WEB_ROOT / "index.html"

SECURITY_HEADERS = {
    "Cache-Control": "no-store",
    "Content-Security-Policy": (
        "default-src 'self'; "
        "connect-src 'self'; "
        "img-src 'self' data:; "
        "style-src 'self' 'unsafe-inline'; "
        "script-src 'self' 'unsafe-inline'; "
        "object-src 'none'; base-uri 'none'; frame-ancestors 'none'"
    ),
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "X-Frame-Options": "DENY",
}


def build_health_payload(config: AppConfig | None = None) -> dict[str, Any]:
    """Return non-secret local readiness metadata; this does not call Group-IB."""
    current = config or AppConfig.from_environment()
    return {
        "status": "ok",
        "credentials_configured": current.has_credentials(),
        "provider_api_connected": False,
        "provider_validation": "Use tools/groupib_contract_probe.py for live validation.",
        "next_gate": "W3 - connect the dashboard read model to the verified provider client.",
    }


class DashboardHandler(BaseHTTPRequestHandler):
    """Serve only the dashboard entry point and a non-secret health endpoint."""

    server_version = "GroupIBDashboard"
    sys_version = ""

    def _send(self, status: int, body: bytes, content_type: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        for name, value in SECURITY_HEADERS.items():
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802 - stdlib handler method name
        if self.path in ("/", "/index.html"):
            try:
                body = INDEX_FILE.read_bytes()
            except OSError:
                self._send(500, b"Dashboard UI is unavailable.", "text/plain; charset=utf-8")
                return
            self._send(200, body, "text/html; charset=utf-8")
            return

        if self.path == "/api/health":
            body = json.dumps(build_health_payload(), separators=(",", ":")).encode("utf-8")
            self._send(200, body, "application/json; charset=utf-8")
            return

        self._send(404, b"Not found.", "text/plain; charset=utf-8")

    def do_POST(self) -> None:  # noqa: N802 - stdlib handler method name
        self._send(405, b"Method not allowed.", "text/plain; charset=utf-8")

    def log_message(self, format_string: str, *args: object) -> None:
        # Keep request logging minimal and never log headers, query values, or bodies.
        super().log_message(format_string, *args)


def main() -> int:
    if not INDEX_FILE.is_file():
        raise SystemExit(f"Dashboard entry point not found: {INDEX_FILE}")

    server = ThreadingHTTPServer((HOST, PORT), DashboardHandler)
    print(f"Group-IB dashboard shell: http://{HOST}:{PORT}")
    print("Bound to loopback only. No Group-IB records are loaded by this shell yet.")
    print("Press Ctrl+C to stop.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nDashboard stopped.")
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

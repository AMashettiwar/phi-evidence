"""Tests for browser crawler robots.txt accounting, authorized owner mode
(ignore_robots), SPA DOM link discovery, and third-party POST beacon / MD5 +
SHA-256 hashed PHI interception."""

from __future__ import annotations

import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import threading
import yaml

from phi_scan.browser import capture
from phi_scan.detect import detect


def test_robots_disallow_reports_zero_pages_and_ignore_robots_overrides(tmp_path: Path, monkeypatch) -> None:
    """When robots.txt has Disallow: /, capture reports 0 pages read and an
    explicit stopped reason; setting ignore_robots: true scans the target."""
    monkeypatch.setenv("PHI_EVIDENCE_KEYS", str(tmp_path / "keys"))

    html_page = (
        b"<!doctype html><html><body>"
        b"<p>Patient: Rafael Ibarra, MRN-448812, started chemotherapy for breast cancer</p>"
        b"</body></html>"
    )
    robots_txt = b"User-agent: *\nDisallow: /\n"

    class DisallowingSite(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            if self.path == "/robots.txt":
                self.send_response(200)
                self.send_header("Content-Type", "text/plain")
                self.send_header("Content-Length", str(len(robots_txt)))
                self.end_headers()
                self.wfile.write(robots_txt)
                return
            if self.path == "/":
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.send_header("Content-Length", str(len(html_page)))
                self.end_headers()
                self.wfile.write(html_page)
                return
            self.send_response(404)
            self.end_headers()

        def log_message(self, *args) -> None:
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), DisallowingSite)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    target = f"http://127.0.0.1:{server.server_address[1]}"

    try:
        # 1. Default mode: obeys robots.txt and reports 0 pages read + stopped reason
        scope_default = tmp_path / "scope_default.yaml"
        scope_default.write_text(yaml.safe_dump({"target": target, "rate_limit": {"page_cap": 3}}))
        rec1 = capture(scope_default, tmp_path / "out_default")["capture"]
        assert rec1["pages"] == 0
        assert rec1["pages_blocked_by_robots"] >= 1
        assert rec1["stopped"] and "robots.txt" in rec1["stopped"]

        # 2. Authorized owner mode: ignore_robots: true scans the page and finds the leak
        scope_auth = tmp_path / "scope_auth.yaml"
        scope_auth.write_text(yaml.safe_dump({
            "target": target,
            "ignore_robots": True,
            "rate_limit": {"page_cap": 3},
        }))
        out_auth = tmp_path / "out_auth"
        rec2 = capture(scope_auth, out_auth)["capture"]
        assert rec2["pages"] >= 1
        assert rec2["stopped"] is None
        findings = detect(out_auth / "index.jsonl", out_auth / "vault", context="public-web")
        assert findings, "Expected leak to be caught when ignore_robots is enabled"
    finally:
        server.shutdown()


def test_third_party_post_beacon_and_md5_hashed_phi_caught(tmp_path: Path, monkeypatch) -> None:
    """An out-of-scope POST beacon carrying MD5-hashed patient email or JSON PHI
    is aborted before leaving the browser and flagged as a critical third_party finding."""
    monkeypatch.setenv("PHI_EVIDENCE_KEYS", str(tmp_path / "keys"))

    email = "marisol.lindqvist@clinic-portal.org"
    md5_email = hashlib.md5(email.encode("utf-8")).hexdigest()  # noqa: S324

    page_html = f"""<!doctype html><html><body>
    <p>Contact: {email}</p>
    <script>
      fetch("http://127.0.0.1:9/pixel/collect", {{
        method: "POST",
        headers: {{"Content-Type": "application/json"}},
        body: JSON.stringify({{em_md5: "{md5_email}", event: "PatientView"}})
      }}).catch(() => {{}});
    </script>
    </body></html>""".encode("utf-8")

    class BeaconSite(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            if self.path == "/":
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.send_header("Content-Length", str(len(page_html)))
                self.end_headers()
                self.wfile.write(page_html)
                return
            self.send_response(404)
            self.end_headers()

        def log_message(self, *args) -> None:
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), BeaconSite)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    target = f"http://127.0.0.1:{server.server_address[1]}"

    try:
        scope = tmp_path / "scope.yaml"
        scope.write_text(yaml.safe_dump({"target": target, "rate_limit": {"page_cap": 2}}))
        out = tmp_path / "out"
        rec = capture(scope, out)["capture"]
        assert rec["requests_refused_out_of_scope"] >= 1
        findings = detect(out / "index.jsonl", out / "vault", context="public-web")
        assert any(
            f["carrier"] == "third_party" and f["extraction"] == "hashed_identifier" and f["level"] == "critical"
            for f in findings
        ), f"Expected MD5-hashed email in POST beacon to be caught, got {findings}"
    finally:
        server.shutdown()

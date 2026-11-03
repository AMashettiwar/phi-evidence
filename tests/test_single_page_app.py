"""A single-page app answers every address with the same page (first real
app scanned, 2026-11-03). The crawl must not keep "/.env" when it is only that
page, and must not ask for the same script once per page."""

import threading
from collections import Counter
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import yaml

from phi_scan.browser import capture

SHELL = (b'<!doctype html><html><head><script src="/assets/app.js"></script></head>'
         b'<body><a href="/a">A</a> <a href="/b">B</a></body></html>')


def test_catch_all_pages_and_repeat_assets(tmp_path, monkeypatch):
    monkeypatch.setenv("PHI_EVIDENCE_KEYS", str(tmp_path / "keys"))
    hits: Counter = Counter()

    class Shell(BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802
            hits[self.path] += 1
            script = self.path == "/assets/app.js"
            body = b"document.title = 'App';" if script else SHELL
            self.send_response(200)
            self.send_header("Content-Type", "text/javascript" if script else "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Shell)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    target = f"http://127.0.0.1:{server.server_address[1]}"
    scope = tmp_path / "scope.yaml"
    # "/", the six well-known paths, then the two linked pages.
    scope.write_text(yaml.safe_dump({"target": target, "rate_limit": {"page_cap": 9}}))
    try:
        record = capture(scope, tmp_path / "out")["capture"]
    finally:
        server.shutdown()
    kept = (tmp_path / "out" / "index.jsonl").read_text(encoding="utf-8")
    assert hits["/a"] and hits["/b"] and hits["/.env"], hits
    assert ".env" not in kept and ".git" not in kept and '"a.html"' not in kept
    assert '"index.html"' in kept
    # One request from the crawl; the logged-out recheck asks once more.
    assert hits["/assets/app.js"] <= 2, hits
    assert record["stopped"] is None

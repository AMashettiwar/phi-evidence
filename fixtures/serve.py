#!/usr/bin/env python3
"""Serve the fake world locally, plus a tracker sink that records what it gets.

Two ports:
  8801  the site and its API, read-only
  8802  the outside company that the pages quietly send data to

Every request is appended to fixtures/out/access.jsonl.
Every tracker hit is appended to fixtures/out/tracker_hits.jsonl, so we can
prove what actually left the site rather than guessing from the page source.

This server only answers GET and HEAD. There is no code path that changes the
world, which is what makes "read-only" testable instead of aspirational.

Run:  python fixtures/serve.py
"""

from __future__ import annotations

import base64
import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

ROOT = Path(__file__).resolve().parents[1]
WORLD = ROOT / "fixtures" / "world"
OUT = ROOT / "fixtures" / "out"
SITE_PORT = 8801
TRACKER_PORT = 8802

GIF = base64.b64decode("R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7")

CONTENT_TYPES = {
    ".html": "text/html; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".js": "application/javascript; charset=utf-8",
    ".json": "application/json; charset=utf-8",
    ".map": "application/json; charset=utf-8",
    ".csv": "text/csv; charset=utf-8",
    ".log": "text/plain; charset=utf-8",
    ".sql": "text/plain; charset=utf-8",
    ".xml": "application/xml; charset=utf-8",
    ".env": "text/plain; charset=utf-8",
    ".pdf": "application/pdf",
}

_write_lock = threading.Lock()


def append(path: Path, record: dict) -> None:
    with _write_lock:
        with path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, sort_keys=True) + "\n")


def resolve(path: str) -> Path | None:
    """Map a URL path onto a file in the world, refusing anything outside it."""
    if path in ("/", ""):
        return WORLD / "site" / "index.html"
    if path.startswith("/api/"):
        tail = path[len("/api/"):].strip("/")
        name = {
            "v1/patients/1042": "patient_1042.json",
            "v1/labs/1042": "labs_1042.json",
            "health": "health.json",
        }.get(tail)
        return WORLD / "api" / name if name else None
    if path.startswith("/files/"):
        return WORLD / "files" / path[len("/files/"):]
    if path.startswith("/logs/"):
        return WORLD / "logs" / path[len("/logs/"):]
    if path.startswith("/portal"):
        return WORLD / "site" / "portal.html"

    candidate = (WORLD / "site" / path.lstrip("/")).resolve()
    if not str(candidate).startswith(str((WORLD / "site").resolve())):
        return None
    if candidate.is_dir():
        candidate = candidate / "index.html"
    elif not candidate.exists() and not candidate.suffix:
        # Do not rewrite dotfiles like .env: they have no suffix but are real files.
        candidate = candidate.with_suffix(".html")
    return candidate


class SiteHandler(BaseHTTPRequestHandler):
    server_version = "NorthbridgeFixture/1.0"

    def log_message(self, *args) -> None:  # silence the default stderr spam
        return

    def do_HEAD(self) -> None:
        self.handle_request(body=False)

    def do_GET(self) -> None:
        self.handle_request(body=True)

    def do_POST(self) -> None:
        self.send_error(405, "This fixture is read-only")

    def handle_request(self, body: bool) -> None:
        parsed = urlparse(self.path)
        append(OUT / "access.jsonl", {
            "ts": round(time.time(), 3),
            "method": self.command,
            "path": parsed.path,
            "query": parsed.query,
            "referer": self.headers.get("Referer"),
            "user_agent": self.headers.get("User-Agent"),
        })

        target = resolve(parsed.path)
        if target is None or not target.exists() or not target.is_file():
            self.send_error(404, "Not found")
            return

        payload = target.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", CONTENT_TYPES.get(target.suffix, "application/octet-stream"))
        self.send_header("Content-Length", str(len(payload)))
        if parsed.path.startswith("/portal"):
            self.send_header("Set-Cookie", "sid=demo; Path=/")
        self.end_headers()
        if body:
            self.wfile.write(payload)


class TrackerHandler(BaseHTTPRequestHandler):
    server_version = "OutsideCompany/0.1"

    def log_message(self, *args) -> None:
        return

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        append(OUT / "tracker_hits.jsonl", {
            "ts": round(time.time(), 3),
            "path": parsed.path,
            "query": parsed.query,
            "params": {k: v[0] for k, v in parse_qs(parsed.query).items()},
            "referer": self.headers.get("Referer"),
        })
        self.send_response(200)
        self.send_header("Content-Type", "image/gif")
        self.send_header("Content-Length", str(len(GIF)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(GIF)


def main() -> int:
    OUT.mkdir(parents=True, exist_ok=True)
    for name in ("access.jsonl", "tracker_hits.jsonl"):
        (OUT / name).write_text("", encoding="utf-8")

    servers = [
        ThreadingHTTPServer(("127.0.0.1", SITE_PORT), SiteHandler),
        ThreadingHTTPServer(("127.0.0.1", TRACKER_PORT), TrackerHandler),
    ]
    for server in servers:
        threading.Thread(target=server.serve_forever, daemon=True).start()

    print(f"site    http://127.0.0.1:{SITE_PORT}/")
    print(f"tracker http://127.0.0.1:{TRACKER_PORT}/")
    print("ctrl-c to stop")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("stopping")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Run the fixture server and check it behaves, without needing a browser.

Starts the site and the tracker sink in this process, makes real HTTP requests,
then inspects the logs the server wrote. This proves three things before a
browser is involved:

  1. every planted file is actually reachable over HTTP
  2. the tracker sink records what it receives
  3. writes are refused, so "read-only" is enforced by the server, not by hope

Run:  python tools/smoke_http.py
"""

from __future__ import annotations

import json
import sys
import threading
import time
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "fixtures"))

import serve  # noqa: E402

BASE = f"http://127.0.0.1:{serve.SITE_PORT}"
TRACKER = f"http://127.0.0.1:{serve.TRACKER_PORT}"

PATHS = [
    "/", "/services.html", "/tracker.html", "/detail.html", "/analytics.html",
    "/scripts/app.js", "/scripts/app.js.map", "/sitemap.xml", "/.env",
    "/backup/db_dump.sql", "/exports/patients_2026-09.csv",
    "/api/v1/patients/1042", "/api/v1/labs/1042", "/api/health",
    "/files/roster.csv", "/files/lab-report.pdf", "/logs/app.log",
]
PIXEL = "/collect?pid=MRN-881096&dx=G35&campaign=spring"

failures: list[str] = []


def get(url: str) -> tuple[int, bytes, str]:
    with urllib.request.urlopen(url, timeout=10) as response:
        return response.status, response.read(), response.headers.get("Content-Type", "")


def post_should_fail() -> str:
    request = urllib.request.Request(BASE + "/api/v1/patients/1042", data=b"x",
                                     method="POST")
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            failures.append(f"POST returned {response.status}, should have been refused")
            return f"{response.status} (SHOULD HAVE BEEN REFUSED)"
    except urllib.error.HTTPError as exc:
        if exc.code != 405:
            failures.append(f"POST returned {exc.code}, expected 405")
        return str(exc.code)
    except Exception as exc:  # noqa: BLE001
        failures.append(f"POST raised {type(exc).__name__}: {exc}")
        return f"error {type(exc).__name__}"


def main() -> int:
    serve.OUT.mkdir(parents=True, exist_ok=True)
    for name in ("access.jsonl", "tracker_hits.jsonl"):
        (serve.OUT / name).write_text("", encoding="utf-8")

    site = ThreadingHTTPServer(("127.0.0.1", serve.SITE_PORT), serve.SiteHandler)
    tracker = ThreadingHTTPServer(("127.0.0.1", serve.TRACKER_PORT), serve.TrackerHandler)
    threads = [threading.Thread(target=s.serve_forever, daemon=True) for s in (site, tracker)]
    for thread in threads:
        thread.start()
    time.sleep(0.3)

    try:
        print("=== fetch every planted file ===")
        for path in PATHS:
            try:
                status, body, kind = get(BASE + path)
                print(f"  {path:36} {status} {len(body):>7}  {kind.split(';')[0]}")
                if status != 200 or not body:
                    failures.append(f"{path}: status {status}, {len(body)} bytes")
            except Exception as exc:  # noqa: BLE001
                print(f"  {path:36} ERROR {exc}")
                failures.append(f"{path}: {type(exc).__name__}")

        print("=== tracker sink ===")
        status, body, kind = get(TRACKER + PIXEL)
        print(f"  {PIXEL:36} {status} {len(body):>7}  {kind.split(';')[0]}")
        if status != 200:
            failures.append("tracker pixel did not return 200")

        print("=== write attempt ===")
        print(f"  POST /api/v1/patients/1042 -> {post_should_fail()}")

        print("=== 404 behaviour ===")
        try:
            get(BASE + "/does-not-exist")
            failures.append("missing page returned 200")
        except urllib.error.HTTPError as exc:
            print(f"  /does-not-exist {exc.code}")
            if exc.code != 404:
                failures.append(f"missing page returned {exc.code}")
    finally:
        for server in (site, tracker):
            server.shutdown()

    print("-" * 70)
    hits = [json.loads(line) for line in
            (serve.OUT / "tracker_hits.jsonl").read_text(encoding="utf-8").splitlines() if line]
    access = [json.loads(line) for line in
              (serve.OUT / "access.jsonl").read_text(encoding="utf-8").splitlines() if line]

    print(f"access log lines  : {len(access)}")
    print(f"tracker hits      : {len(hits)}")
    if not hits:
        failures.append("tracker recorded nothing")
    else:
        params = hits[0].get("params", {})
        print(f"tracker received  : {params}")
        if params.get("pid") != "MRN-881096":
            failures.append(f"tracker did not record the record number, got {params.get('pid')!r}")
        if params.get("dx") != "G35":
            failures.append(f"tracker did not record the diagnosis code, got {params.get('dx')!r}")

    if failures:
        print(f"FAIL  {len(failures)} problem(s)")
        for item in failures:
            print(f"  - {item}")
        return 1

    print("PASS  server serves the world, records the tracker, and refuses writes")
    return 0


if __name__ == "__main__":
    sys.exit(main())

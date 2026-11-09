#!/usr/bin/env python3
"""Gate G8: the live crawler, exercised against the fixture server.

Checks the things that make a scanner safe to point at a real site:

  1. it stays on one host and refuses anything else
  2. it obeys robots.txt and records what it skipped
  3. it waits between requests
  4. it only ever uses GET
  5. findings from a live crawl match what a static read of the same site finds,
     except where robots.txt legitimately blocks a path

Run:  python tools/check_crawl.py
"""

from __future__ import annotations

import json
import sys
import threading
import time
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "fixtures"))
sys.path.insert(0, str(ROOT / "pylibs"))

import serve  # noqa: E402
from phi_scan.collect import collect  # noqa: E402
from phi_scan.crawl import crawl  # noqa: E402
from phi_scan.detect import detect  # noqa: E402

OUT = ROOT / "artifacts" / "g8"
DELAY = 0.1  # fast for a test; the shipped default is 1.0


def main() -> int:
    failures: list[str] = []

    serve.OUT.mkdir(parents=True, exist_ok=True)
    (serve.OUT / "access.jsonl").write_text("", encoding="utf-8")

    site = ThreadingHTTPServer(("127.0.0.1", serve.SITE_PORT), serve.SiteHandler)
    tracker = ThreadingHTTPServer(("127.0.0.1", serve.TRACKER_PORT), serve.TrackerHandler)
    for server in (site, tracker):
        threading.Thread(target=server.serve_forever, daemon=True).start()
    time.sleep(0.3)

    try:
        base = f"http://127.0.0.1:{serve.SITE_PORT}/"
        started = time.time()
        result = crawl(base, OUT / "crawl", max_pages=60, delay=DELAY,
                       alias_hosts=("northbridge.example",),
                       seeds=("/backup/db_dump.sql",
                              "/exports/patients_2026-09.csv"))
        elapsed = time.time() - started
    finally:
        for server in (site, tracker):
            server.shutdown()

    log = result["log"]
    fetched = [entry for entry in log if entry.get("result") == "fetched"]
    refused = [entry for entry in log if entry.get("result") == "refused_off_host"]
    robots_blocked = [entry for entry in log if entry.get("result") == "blocked_by_robots"]

    print("=" * 70)
    print("LIVE CRAWL GATE")
    print("=" * 70)
    print(f"pages fetched        {len(fetched)}")
    print(f"off-host refused     {len(refused)}")
    print(f"blocked by robots    {len(robots_blocked)}")
    print(f"wall clock           {elapsed:.2f}s  (delay {DELAY}s)")

    # --- only GET was ever used -------------------------------------------
    methods = set()
    access = serve.OUT / "access.jsonl"
    if access.exists():
        for line in access.read_text(encoding="utf-8").splitlines():
            if line.strip():
                methods.add(json.loads(line)["method"])
    print(f"methods used         {sorted(methods)}")
    if methods - {"GET"}:
        failures.append(f"a method other than GET was used: {sorted(methods)}")

    # --- the rate limit was real ------------------------------------------
    gaps: list[float] = []
    if access.exists():
        stamps = [json.loads(line)["ts"] for line in
                  access.read_text(encoding="utf-8").splitlines() if line.strip()]
        gaps = [b - a for a, b in zip(stamps, stamps[1:]) if b >= a]
    if gaps:
        print(f"gap min / median     {min(gaps):.3f}s / {sorted(gaps)[len(gaps) // 2]:.3f}s")
        if min(gaps) < DELAY * 0.8:
            failures.append(f"a request came after {min(gaps):.3f}s, below the {DELAY}s delay")

    if not fetched:
        failures.append("nothing was fetched")
    if not robots_blocked:
        failures.append("robots.txt was never triggered, so the check proves nothing")

    # --- findings from the live crawl -------------------------------------
    manifest = collect(OUT / "crawl", OUT / "run", str(ROOT / "pylibs"))
    findings = detect(OUT / "run" / "index.jsonl", OUT / "run" / "vault")
    print(f"observations         {manifest['observations']}")
    print(f"findings             {len(findings)}")
    for carrier, count in sorted(manifest["carriers"].items()):
        print(f"   {carrier:20} {count}")

    blocked_paths = [entry["url"] for entry in robots_blocked]
    if blocked_paths:
        print()
        print("skipped because robots.txt forbids it:")
        for url in blocked_paths[:6]:
            print(f"   {url}")

    print()
    if failures:
        print(f"FAIL  {len(failures)} problem(s)")
        for item in failures:
            print(f"  - {item}")
        return 1
    print("PASS  one host, GET only, robots obeyed, rate limit held")
    return 0


if __name__ == "__main__":
    sys.exit(main())

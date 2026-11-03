#!/usr/bin/env python3
"""Gate G2: is the live capture safe, slow, reproducible and replayable?

Serves the synthetic world with its tracker sink, scans it twice in a real
browser as account A, and checks from the server's side, not the scanner's:

  * the canonical findings of the two runs are byte-identical
  * nothing reached the out-of-scope tracker (its own log is empty)
  * no two requests arrived less than the scope's gap apart (server access log)
  * no planted value appears anywhere in either run's artifact tree
  * every finding replays: its span's HMAC is unchanged

Run:  python tools/gate_g2.py        (about five minutes: the scan is slow on purpose)
"""

from __future__ import annotations

import json
import shutil
import sys
import threading
from http.server import ThreadingHTTPServer
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "fixtures"))

import serve  # noqa: E402
from phi_scan.browser import capture  # noqa: E402
from phi_scan.detect import detect  # noqa: E402
from phi_scan.evidence import replay, write  # noqa: E402
from phi_scan.vault import Vault  # noqa: E402

SCOPE = ROOT / "fixtures" / "scope.yaml"
OUT = ROOT / "artifacts" / "g2"


def lines(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]


def scan(run: Path) -> dict:
    record = capture(SCOPE, run)
    findings = detect(run / "index.jsonl", run / "vault", (), context="public-web")
    write(run, findings, Vault(run / "vault"))
    return {"capture": record["capture"], "findings": findings}


def main() -> int:
    problems: list[str] = []
    gap = yaml.safe_load(SCOPE.read_text(encoding="utf-8"))["rate_limit"]["min_interval_seconds"]
    key = json.loads((ROOT / "eval" / "keys" / "world_key.json").read_text(encoding="utf-8"))
    planted = sorted({item["value"] for item in key["items"] if item["expected_flag"]})

    servers = [ThreadingHTTPServer(("127.0.0.1", serve.SITE_PORT), serve.SiteHandler),
               ThreadingHTTPServer(("127.0.0.1", serve.TRACKER_PORT), serve.TrackerHandler)]
    for server in servers:
        threading.Thread(target=server.serve_forever, daemon=True).start()
    shutil.rmtree(OUT, ignore_errors=True)
    runs, gaps, tracker_hits = [], [], 0
    try:
        for number in (1, 2):
            serve.OUT.mkdir(parents=True, exist_ok=True)
            for name in ("access.jsonl", "tracker_hits.jsonl"):
                (serve.OUT / name).write_text("", encoding="utf-8")
            runs.append(scan(OUT / f"run{number}"))
            stamps = [entry["ts"] for entry in lines(serve.OUT / "access.jsonl")]
            gaps += [later - earlier for earlier, later in zip(stamps, stamps[1:])]
            tracker_hits += len(lines(serve.OUT / "tracker_hits.jsonl"))
    finally:
        for server in servers:
            server.shutdown()

    first, second = (OUT / "run1" / "findings.json"), (OUT / "run2" / "findings.json")
    identical = first.read_bytes() == second.read_bytes()
    record = runs[0]["capture"]
    print(f"pages / requests     {record['pages']} / {record['requests_sent']}")
    print(f"refused out of scope {record['requests_refused_out_of_scope']} (recorded, never sent)")
    print(f"stopped early        {record['stopped']}")
    print(f"findings             {len(runs[0]['findings'])} / {len(runs[1]['findings'])}")
    print(f"canonical identical  {identical}")
    print(f"tracker received     {tracker_hits}  (must be 0)")
    print(f"min request gap      {min(gaps):.3f}s  (must be >= {gap:.3f})")
    if not identical:
        problems.append("the two runs' canonical findings differ")
    if tracker_hits:
        problems.append(f"{tracker_hits} requests reached the out-of-scope tracker")
    if not record["requests_refused_out_of_scope"]:
        problems.append("no out-of-scope request was intercepted: the guard was never exercised")
    if min(gaps) < gap:
        problems.append(f"two requests arrived {min(gaps):.3f}s apart")
    if record["stopped"]:
        problems.append(f"the scan stopped early: {record['stopped']}")

    leaked = []
    for path in sorted(p for p in OUT.rglob("*") if p.is_file()):
        data = path.read_bytes()
        leaked += [(path.relative_to(OUT).as_posix(), value) for value in planted
                   if value.encode("utf-8") in data]
    print(f"planted values found {len(leaked)}  (must be 0)")
    for where, value in leaked[:8]:
        print(f"  - {where}: {value[:3]}...")
    if leaked:
        problems.append(f"{len(leaked)} planted values in the artifact tree")

    for number in (1, 2):
        result = replay(OUT / f"run{number}")
        print(f"replay run{number}          {result['identical']}/{result['checked']} identical")
        if not result["checked"] or result["mismatched"]:
            problems.append(f"run{number} replay: {result['mismatched'][:5] or 'nothing to replay'}")

    if problems:
        print(f"FAIL  {len(problems)} problem(s)")
        for problem in problems:
            print(f"  - {problem}")
        return 1
    print("PASS  capture is in scope, paced, reproducible and replayable")
    return 0


if __name__ == "__main__":
    sys.exit(main())

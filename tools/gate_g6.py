#!/usr/bin/env python3
"""Gate G6: the bot, end to end, through the command a user runs.

Serves the synthetic world, then runs exactly

    python -m phi_scan.cli scan --scope fixtures/scope.yaml --out artifacts/g6/run

and checks the outputs mechanically:
  * report.html, findings.sarif, findings.json, run.json hold no planted value
  * findings.json validates against phi_scan/finding.schema.json
  * every finding replays (python -m phi_scan.cli replay artifacts/g6/run)
  * live recall against the world key, and the levels of the cases only a live
    scan can settle (the page public by mistake, the IDOR record, own record)

Fresh-clone reproduction of the gate G5 numbers is M9 (tools/fresh_clone.py).

Run:  python tools/gate_g6.py
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
import threading
from http.server import ThreadingHTTPServer
from pathlib import Path

import jsonschema

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "fixtures"))
sys.path.insert(0, str(ROOT))

import serve  # noqa: E402
from phi_scan.vault import Vault  # noqa: E402

OUT = ROOT / "artifacts" / "g6" / "run"


def main() -> int:
    problems: list[str] = []
    shutil.rmtree(OUT.parent, ignore_errors=True)
    serve.OUT.mkdir(parents=True, exist_ok=True)
    for name in ("access.jsonl", "tracker_hits.jsonl"):
        (serve.OUT / name).write_text("", encoding="utf-8")
    servers = [ThreadingHTTPServer(("127.0.0.1", serve.SITE_PORT), serve.SiteHandler),
               ThreadingHTTPServer(("127.0.0.1", serve.TRACKER_PORT), serve.TrackerHandler)]
    for server in servers:
        threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        scan = subprocess.run([sys.executable, "-m", "phi_scan.cli", "scan", "--scope",
                               str(ROOT / "fixtures" / "scope.yaml"), "--out", str(OUT)],
                              cwd=ROOT, capture_output=True, text=True, encoding="utf-8", errors="replace")
    finally:
        for server in servers:
            server.shutdown()
    print(scan.stdout.strip().splitlines()[-1] if scan.stdout.strip() else scan.stderr[-500:])
    if scan.returncode != 0:
        print(f"FAIL  the scan command exited {scan.returncode}")
        return 1

    key = json.loads((ROOT / "eval" / "keys" / "world_key.json").read_text(encoding="utf-8"))["items"]
    planted = [item for item in key if item["expected_flag"]]
    for name in ("report.html", "findings.sarif", "findings.json", "run.json", "capture.json",
                 "evidence.jsonl", "index.jsonl"):
        text = (OUT / name).read_text(encoding="utf-8")
        shown = sorted({item["id"] for item in planted if item["value"] in text})
        print(f"{name:16} unmasked planted values: {len(shown)}")
        if shown:
            problems.append(f"{name} shows planted values {shown[:5]}")

    findings = json.loads((OUT / "findings.json").read_text(encoding="utf-8"))
    try:
        jsonschema.validate(findings, json.loads((ROOT / "phi_scan" / "finding.schema.json").read_text()))
        print(f"schema           valid ({len(findings)} findings)")
    except jsonschema.ValidationError as error:
        problems.append(f"findings.json does not validate: {error.message}")

    replay = subprocess.run([sys.executable, "-m", "phi_scan.cli", "replay", str(OUT)], cwd=ROOT,
                            capture_output=True, text=True, encoding="utf-8", errors="replace")
    result = json.loads(replay.stdout)
    print(f"replay           {result['identical']}/{result['checked']} identical")
    if replay.returncode != 0:
        problems.append(f"replay failed: {result['mismatched'][:5]}")

    vault = Vault(OUT / "vault")
    tokens = {}
    for line in (OUT / "evidence.jsonl").read_text(encoding="utf-8").splitlines():
        entry = json.loads(line)
        for token in entry["value_tokens"]:
            tokens.setdefault(token, []).append(entry["finding_id"])
    by_id = {f["finding_id"]: f for f in findings}
    caught = [item for item in planted if vault.token(item["value"]) in tokens]
    print(f"live recall      {len(caught)}/{len(planted)} (unlinked files are a stated crawl limit)")
    level_of = lambda value: {by_id[i]["level"] for i in tokens.get(vault.token(value), [])}  # noqa: E731
    checks = {"L074": "critical", "L071": "high"}
    for item in planted:
        if item["id"] in checks:
            got = level_of(item["value"])
            ok = checks[item["id"]] in got
            print(f"measured level   {item['id']} {item['note'][:48]}... -> {sorted(got)}")
            if not ok:
                problems.append(f"{item['id']} should be {checks[item['id']]}, got {sorted(got)}")
    own = [i for i in key if i.get("record") == "own_record" and i["file"].startswith("api/")]
    for item in own:
        if vault.token(item["value"]) in tokens:
            problems.append("the scanning account's own record was reported")
    run = json.loads((OUT / "run.json").read_text(encoding="utf-8"))
    print(f"cleared          {len(run['cleared'])} records with a stated reason; model {run['model']}")

    if problems:
        print(f"FAIL  {len(problems)} problem(s)")
        for problem in problems:
            print(f"  - {problem}")
        return 1
    print("PASS  one command scans the live target and every output is safe and replayable")
    return 0


if __name__ == "__main__":
    sys.exit(main())

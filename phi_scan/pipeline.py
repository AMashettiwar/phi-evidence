"""One command, end to end (brief sections 3 and 6, PLAN P6).

    scope file -> browser capture -> detection -> model review -> evidence -> reports

Outputs in the scan directory:
    findings.json     canonical findings (byte-identical across runs; schema in
                      finding.schema.json)
    evidence.jsonl    chain of custody: object, span HMAC, versions, replay command
    findings.sarif    the same findings for code-scanning tools (SARIF 2.1.0)
    report.html       one page for a reviewer: masks only, never a value
    run.json          this run: versions, model and cost, cleared records, capture
    vault/            encrypted evidence; the key is kept outside the scan directory
"""

from __future__ import annotations

import html
import json
import re
from datetime import datetime, timezone
from pathlib import Path

import yaml

from . import evidence
from .ai import GroqProvider, injection_findings, review_all
from .browser import capture, load_scope
from .collect import collect
from .detect import detect
from .vault import Vault

ROOT = Path(__file__).resolve().parents[1]
LEVELS = ("critical", "high", "medium", "review")
SARIF_LEVEL = {"critical": "error", "high": "error", "medium": "warning", "review": "note"}
WORDING = "Possible PHI exposure, needs compliance review."
# A path segment that itself carries a record number or a name is masked in the
# report: "Rafael-Ibarra_MRN-881010.html" names a patient before anyone opens it.
IDENTIFYING_SEGMENT = re.compile(r"\d{5,}|[A-Z][a-z]+[-_][A-Z][a-z]+")


def scan_live(scope_path: Path, out: Path, provider=None) -> dict:
    record = capture(scope_path, out)["capture"]
    scope = load_scope(scope_path)
    own = frozenset(a["patient_id"] for a in scope["accounts"] if a["name"] == scope["scan_as"])
    cleared: list[dict] = []
    findings = detect(out / "index.jsonl", out / "vault", (), context="public-web",
                      measured=record["audience"], own_ids=own, cleared=cleared)
    summary = {key: record[key] for key in ("target", "scan_as", "pages", "requests_sent",
                                            "requests_refused_out_of_scope", "stopped")}
    return finish(out, findings, cleared, provider, {"mode": "live", "capture": summary})


def scan_files(source: Path, out: Path, provider=None, context: str = "covered-entity",
               auth_prefixes: tuple[str, ...] = ()) -> dict:
    collect(source, out)
    cleared: list[dict] = []
    findings = detect(out / "index.jsonl", out / "vault", auth_prefixes, context=context,
                      cleared=cleared)
    return finish(out, findings, cleared, provider, {"mode": "files", "source": str(source)})


def finish(out: Path, findings: list[dict], cleared: list[dict], provider, run: dict) -> dict:
    vault = Vault(out / "vault")
    injections: list[dict] = []
    if provider is not None:
        findings, requests = review_all(findings, vault, provider)
        injections = injection_findings(requests)
    tool = evidence.write(out, findings, vault)
    (out / "findings.sarif").write_text(sarif(findings), encoding="utf-8", newline="\n")
    run = {**run, "created": datetime.now(timezone.utc).isoformat(timespec="seconds"),
           "versions": tool["versions"], "findings": len(findings),
           "levels": {level: sum(f["level"] == level for f in findings) for level in LEVELS},
           "cleared": cleared, "injection_attempts": len(injections),
           "model": provider.name if provider else "none",
           "cost": provider.cost() if isinstance(provider, GroqProvider) else None}
    (out / "run.json").write_text(json.dumps(run, indent=2, sort_keys=True) + "\n",
                                  encoding="utf-8", newline="\n")
    (out / "report.html").write_text(report(findings, run), encoding="utf-8", newline="\n")
    return run


def mask_path(path: str) -> str:
    return "/".join("[masked]" + Path(part).suffix if IDENTIFYING_SEGMENT.search(part) else part
                    for part in path.split("/"))


def rules_index() -> dict[str, dict]:
    rules = yaml.safe_load((ROOT / "policy" / "rules.yaml").read_text(encoding="utf-8"))["rules"]
    return {rule["id"]: rule for rule in rules}


def sarif(findings: list[dict]) -> str:
    rules = rules_index()
    used = sorted({r for f in findings for r in f["rules"]})
    document = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": "phi-scan", "rules": [
            {"id": rule_id, "shortDescription": {"text": rules[rule_id]["citation"]}}
            for rule_id in used]}},
            "results": [{
                "ruleId": (f["rules"] or ["permitted_disclosure"])[0],
                "level": SARIF_LEVEL[f["level"]],
                "message": {"text": f"{WORDING} {', '.join(f['identifiers'])} in {f['carrier']}: "
                                    f"{f['value_mask']}"},
                "locations": [{"physicalLocation": {
                    "artifactLocation": {"uri": mask_path(f["path"])},
                    "region": {"byteOffset": f["offset"], "byteLength": f["length"]}}}],
                "properties": {"finding_id": f["finding_id"], "severity": f["level"],
                               "evidence_grade": f["evidence_grade"]},
            } for f in findings]}]}
    return json.dumps(document, indent=2, sort_keys=True) + "\n"


def report(findings: list[dict], run: dict) -> str:
    """One self-contained page. Every dynamic string is escaped, and the only
    representation of a value is its mask."""
    rules = rules_index()
    esc = html.escape
    rows = []
    for f in sorted(findings, key=lambda f: (LEVELS.index(f["level"]), f["finding_id"])):
        ai = f.get("ai") or {}
        cites = "<br>".join(f"{esc(rules[r]['citation'])}"
                            + (" <em>(contested)</em>" if rules[r].get("contested") else "")
                            for r in f["rules"] if r in rules)
        rows.append(
            f"<tr class='{f['level']}'><td>{esc(f['finding_id'])}</td><td>{esc(f['level'])}</td>"
            f"<td>{esc(f['carrier'])}</td><td><code>{esc(mask_path(f['path']))}</code></td>"
            f"<td>{esc(', '.join(f['identifiers']))}</td><td><code>{esc(f['value_mask'])}</code></td>"
            f"<td>{cites}</td><td>{esc(f['evidence_grade'])}</td><td>{esc(f.get('person', ''))}</td>"
            f"<td>{esc(ai.get('explanation', ''))}</td></tr>")
    cleared = "".join(
        f"<li><code>{esc(mask_path(c['path']))}</code> ({esc(c['carrier'])}): "
        f"{esc(c['predicate'])} - {esc(c['evidence'])}</li>" for c in run["cleared"])
    levels = " ".join(f"<span class='pill {k}'>{k} {v}</span>" for k, v in run["levels"].items())
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<title>phi-scan report</title><style>
:root {{ color-scheme: light dark; --line: #8884; }}
body {{ font: 15px/1.5 system-ui, sans-serif; margin: 2rem auto; max-width: 1200px; padding: 0 1rem; }}
table {{ border-collapse: collapse; width: 100%; font-size: 13px; }}
th, td {{ border-bottom: 1px solid var(--line); padding: .4rem .5rem; text-align: left; vertical-align: top; }}
.pill {{ border: 1px solid var(--line); border-radius: 1rem; padding: .1rem .6rem; margin-right: .3rem; }}
tr.critical td:nth-child(2), .pill.critical {{ color: #c0392b; font-weight: 600; }}
tr.high td:nth-child(2), .pill.high {{ color: #d35400; font-weight: 600; }}
</style></head><body>
<h1>Possible PHI exposure, needs compliance review</h1>
<p>{esc(run['mode'])} scan, {esc(run['created'])}. {len(findings)} findings. {levels}</p>
<p>This report never shows a patient value: each finding carries a mask, and the evidence
behind it is encrypted in the scan's vault. It makes no breach determination and gives no
legal advice. Treat it as a sensitive document.</p>
<table><thead><tr><th>Finding</th><th>Level</th><th>Where</th><th>Path</th><th>Identifiers</th>
<th>Masked value</th><th>Rule</th><th>Evidence</th><th>Person</th><th>Review note</th></tr></thead>
<tbody>{''.join(rows)}</tbody></table>
<h2>Not reported, and why</h2><ul>{cleared or '<li>None.</li>'}</ul>
<p>Model: {esc(run['model'])}. Injection attempts recorded: {run['injection_attempts']}.</p>
</body></html>
"""

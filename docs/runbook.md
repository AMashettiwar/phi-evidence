# Runbook

Steps for the operator. Read `docs/threat-model.md` first, and complete `docs/discovery-protocol.md` before any scan of a real target.

**Interface.** `python -m phi_scan.cli scan --scope SCOPE --out OUT` runs a live scan end to end
(`phi_scan/pipeline.py`); `scan --source DIR` scans files you already have; `replay OUT` re-checks
every finding's evidence. `--llm auto|groq|stub|none` chooses the review model (auto = Groq when
`GROQ_API_KEY` is set). `tools/gate_g6.py` runs exactly this command against the synthetic site.

**Without a terminal.** `install.bat` then `start.bat` (or `python -m phi_scan.launcher`) open a
form on `http://127.0.0.1:8765/` that writes the scope, runs the same scan and replay, and shows
the result. Results go to `~/PHI-Scans/<site>-<time>/`; cookies are never written there.
`START-HERE.md` is the guide for people who do not run code.

## 1. Prerequisites

- Python 3.11
- `pip install -r requirements.lock`
- `python -m playwright install chromium`
- Disk encryption on the machine that runs the scan (a temp mirror of served bytes exists while it runs).

## 2. Write a scope file

Start from `fixtures/scope.yaml`. A real engagement replaces it with the signed scope. Keep it outside the repository: it holds session cookies.

Only `target` is required; every other field has a safe default.

| Field | Meaning |
|---|---|
| `target` | Base URL where crawling starts. |
| `in_scope.hosts` | Exact `host:port` values the scan may request. Anything else is refused. Default: the target's host. |
| `out_of_scope.hosts` | Hosts that must never be requested (for example a tracker). What pages send there is observed, not requested. |
| `out_of_scope.paths` | Paths never fetched on in-scope hosts. Put any state-changing GET here. Logout and sign-out paths are refused without being listed. |
| `accounts` | Optional test accounts: `name`, `cookie` (one `name=value` or a whole Cookie line copied from the browser, `a=1; b=2`), optional `patient_id`. The scanner presents the cookies and never submits a login form. Without accounts only public pages are scanned. |
| `scan_as` | Which account the crawl uses (default: the first). The other account is used for the differential access test. |
| `api` | Optional. `schema` (path of the OpenAPI/Swagger description), `self` (the "my record" path, e.g. `/api/patients/me`), `by_id` (e.g. `/api/patients/{id}`). Without it the scan reads every description found at the usual paths (`/openapi.json`, `/swagger.json`, `/v3/api-docs`, ...). `capture.json` → `access_test` says what ran, or why not. |
| `rate_limit` | `concurrency` (1), `min_interval_seconds` (never below 1), `jitter_seconds`, `page_cap` (200). |
| `stop_conditions` | Documented stops: 429, three server errors in a row, page cap, redirect out of scope. |

## 3. Provision two test accounts

Create accounts A and B on the target, each with its own synthetic patient record. Put each session cookie in `accounts`; `patient_id` is needed only when the "my record" response does not carry an `id` field. The scan asks whether A can read B's record, and treats A's own record as not a finding. Use test data only; do not use real patients.

## 4. Groq key (optional AI review)

Put `GROQ_API_KEY=...` in a `.env` file at the repository root. `.env` is git-ignored. The environment variable also works. Without a key the deterministic stub reviewer is used. Only redacted spans are sent; there is no BAA. See threat model 3.7 before using this against a real target.

## 5. Run a scan

```
python -m phi_scan.cli scan --scope SCOPE --out OUT
```

The scan fetches robots.txt and sitemap.xml, visits linked pages in a headless browser as the scanning account, reads storage and cookies, fetches each captured URL again logged out to measure the audience, runs the differential test, then detects and writes outputs. It stops on any stop condition and records why in `capture.json`.

It sees only linked, sitemapped and a short fixed list of well-known paths. Unlinked files are not found.

## 6. Read the outputs

| File | What it is |
|---|---|
| `findings.json` | Canonical findings: location, carrier, identifier types, masked value, level, rule ids. Same input gives the same bytes. |
| `evidence.jsonl` | Chain of custody, one line per finding: vault object, offset, length, HMAC of the bytes, value tokens, tool versions, replay command. Changes between runs (per-scan key). |
| `capture.json` | What the scan did: pages, requests sent, requests refused as out of scope, why it stopped, measured audience per URL, publicly cacheable and noindex paths, vault addresses of the HAR and screenshots. |
| `report.html` | One human view: masks only, rule citations, why records were cleared. Sensitive. |
| `findings.sarif` | The same findings as SARIF 2.1.0, for code-scanning tools. |
| `vault/` | Encrypted raw bytes and `access.log`. The key is in `~/.phi-evidence/keys`, not here. |

Levels run Critical, High, Medium, Review. Every one means "Possible PHI exposure, needs compliance review." Review means a small group or an uncertain case. No output claims a page is clean or that a breach occurred.

## 7. Replay evidence

```
python -m phi_scan.cli replay OUT
python -m phi_scan.cli replay OUT --finding FINDING_ID
```

Re-reads each finding's span from the vault and recomputes its HMAC. Output: checked, identical, mismatched. A mismatch means the stored bytes changed. Replay needs the key and an unexpired vault, and each read is logged.

## 8. Destroy a vault

Destroy after the retention period set in the discovery protocol, or on counsel's instruction. In Python:

```
from pathlib import Path
from phi_scan.vault import Vault
Vault(Path("OUT/vault")).destroy()
```

This deletes the objects and the key file and appends a "destroy" line to `access.log`. Evidence can no longer be replayed. The key file is deleted, not overwritten. The vault also refuses reads after 30 days.

## 9. Verify the tool

```
python tools/run_gates.py
```

Runs every gate in order and exits non-zero if any fails (22 steps at the time of writing). Gate meanings are in `TESTING.md` and `docs/handover.md`.

## 10. When a Critical finding appears

1. Stop. Do not copy the report outside the access list set in the discovery protocol.
2. Notify the privacy officer within one business day, as the protocol states. For an authentication or transport finding, also the security officer.
3. Note the discovery date and time. The 60-day clock in 45 CFR 164.404 may start at discovery. The tool does not decide whether a breach occurred; counsel does.
4. Do not retest or probe further without approval. Do not open the vault except by a logged read for a stated purpose.
5. Follow `docs/discovery-protocol.md` for sequestering, retention, and counsel access to raw bytes.

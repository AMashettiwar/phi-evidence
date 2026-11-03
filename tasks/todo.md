# phi-evidence — build to the full PROMPT-v2 brief

Seeded from phi-scan `main` (cb95fd8, tag `exam-ready-2026-10-30`), history kept, no remote.
The brief: `docs/brief/PROMPT-v2.md`. Gate ledger it was decomposed into: `docs/brief/PLAN.md`.
Rulebook (owner decisions, e.g. street address alone = Medium): `docs/brief/rulebook.md`.

## Stop condition

Done when **every gate below passes by command from a fresh clone and a fresh venv**, and one
command runs the bot end to end against the live synthetic target:

```
phi-scan scan --scope fixtures/scope.yaml --out out/run   # browser + API + files -> vault -> detect -> LLM -> JSON + HTML
phi-scan replay out/run                                   # every finding re-derived from stored bytes
python tools/run_gates.py                                 # G0..G6, exit 0
```

Items that need people are built and packaged, then reported as **pending human**, not as done:
G0 rulebook sign-off, G5 blind two-reviewer adjudication.

## Decisions and deviations (stated, not silent)

- LLM provider: **Groq** (OpenAI-compatible HTTP, stdlib client). Key read from `GROQ_API_KEY` or
  the git-ignored `.env`. The model only ever sees redacted spans of synthetic data.
- Groq has no dated model snapshots: record model id + `system_fingerprint` per call; stability is
  measured (k=3, Fleiss kappa), not assumed.
- Synthea (Java) is not used: Faker for format variants, real FHIR R4 / HL7v2 / DICOM / X12 shapes.
- SNOMED, LOINC tables are licensed: terminology lookup uses public sets only.
- Regimes: the brief's closed list of 11 rule ids. Other regimes stay a registry slot.
- Corpus: 6 strata x 160 positives = 960 positives + ~700 hard negatives (>=40%). Meets both
  PROMPT-v2 (>=150/stratum) and the >=40% negative rule.
- "Fresh container": Docker daemon was unreachable on this machine; if still so, fresh clone +
  fresh venv is the reproducibility proof and the Dockerfile ships marked unvalidated.
- Benchmark circularity: the same author builds detector and benchmark. Mitigation: key hash frozen
  before the first scored run, a held-out split never used while tuning, every miss itemised.
  Independent validation still needs the human reviewers.

## Milestones

### M1 — reproducible baseline  (done, ace3184)
- [x] `.venv` from Python 3.11; direct deps pinned in `pyproject.toml`, everything in `requirements.lock`
- [x] missing model is an error, not a silent regex fallback (simpler than reporting a mode)
- [x] root cause was not the model: `WORD` admitted `_`, so "Bhatt DEMO_PATIENT_MRN" beat
      "Freya Bhatt" once en_core_web_sm 3.7.1 split the name. Fixed; `tests/test_names.py`
- [x] `tools/run_gates.py` is the one gate list (added the missing `build_injection.py`); CI calls it
- **verified:** fresh clone + fresh venv from the lock: 16/16 gates

### M2 — P0 policy spec (G0)
- [x] `policy/phi-exposure-spec.md` covering brief 2.1-2.9
- [x] `rules.yaml`: 12 ids = the brief's 11 citations ((b)(2)(i)/(ii) split), quotes linted
- [x] `identifiers.yaml` 18/18 with check + mask + always_flag (ssn, mrn, plan_id)
- [x] `policy/negatives.yaml`: 8 predicates, each with evidence, function, fixture (built in M3/M5)
- [x] invariant 3 (no rule id outside registry) now enforced in `check_detect.py`, with a control
- [ ] **owner decision open:** severity as the rulebook's ordinal "worst of" rule (implemented)
      vs the brief's numeric weights. Spec 2.6 records it.
- [ ] **pending human:** rulebook sign-off -> `policy/SIGNOFF.md`
- **verify (G0):** `python tools/gate_g0.py` -> 11/11 rule ids resolve, 0 quote mismatches, 18/18 identifiers, 8/8 predicates with fixtures

### M3 — P1 frozen fixtures and key (G1)  (done, frozen at 70ba8b3)
- [x] world: accounts A/B by session cookie (`fixtures/scope.yaml`), 401 when logged out,
      `/portal/print/` public by mistake, IDOR at `/api/v2/patients/{id}`, `_headers`/`_redirects`
- [x] world carriers added: aria_hidden, json_ld, indexeddb, cookie, response_header,
      hidden_sheet, tracked_changes, file_metadata (docx core), speaker_notes, exif
- [x] 4 missing negative fixtures; `negatives.yaml` points at real world files
- [x] corpus: 6 x 160 positives, 8 x 90 negatives (42.9%), 20% heldout, seeded, byte-identical
- [x] freeze is deliberate: `tools/freeze.py` -> committed `eval/frozen.json`; generators never write it
- **verified (G1):** carriers 23/23, world planted 73, one location 1767/1767, negatives 8/8 keyed clean
- decision: reserved SSN = area 000/666, group 00, serial 0000, or 987-65-4320..4329. Area 9xx is
  the ITIN space and stays an identifier.
- known: pptx is minimal (no slide master), JPEG not decoded by a real decoder (no PIL)

### M4 design decisions (recorded before building)
- vault (`phi_scan/vault.py`, done + tests): per-scan 32-byte key in `~/.phi-evidence/keys`
  (override `PHI_EVIDENCE_KEYS`), HMAC-SHA256 addresses, AES-256-GCM, access.log, 30-day TTL,
  `destroy()` shreds the key. `vault.token(value)` replaces plain SHA-256 value hashes.
- per-scan keys make the index differ between runs by design: `check_collect` must pass one key
  to both runs. G2's byte-identical requirement applies to the **canonical JSON**, which therefore
  carries no salted tokens, no vault addresses and no timestamps; those go in a run manifest.
- browser capture: Playwright with account A's cookie; out-of-scope requests intercepted, recorded
  as evidence and aborted (never sent); every request delayed to keep >=1 s gaps; screenshots taken
  with all text blurred (redacted at capture).

### M4 — P2 collection and evidence chain (G2)
- [ ] Playwright collector: HAR + bodies + route interception, isolated profile
- [ ] API collector from the schema; file collector for the four document types
- [ ] scope guard (0 out-of-scope requests), rate limit (concurrency 1, >=1 s + jitter, page cap)
- [ ] HMAC tokenisation at ingest (per-scan salt); encrypted, access-logged vault with TTL
- [ ] evidence bundle: hashes, timestamps, versions, replay command
- [ ] logged-out re-fetch, indexability probe (canaries only), identity oracle A/B
- **verify (G2):** two runs byte-identical canonical JSON; out-of-scope = 0; min gap >= 1.000 s from HAR; raw planted values in artifacts = 0; 20/20 replays identical

### M5 — P3 detection (G3)
- [ ] validators: SSN, Luhn, NPI (80840), DEA, ICD-10 / LOINC / RxNorm syntax, DOB plausibility
- [ ] MRN / member-ID format induction; FHIR, HL7v2, DICOM, X12, CSV/XLSX extractors
- [ ] scispaCy clinical NER + public terminology; cross-carrier entity resolution
- [ ] trackers: list + payload decode + hashed-identifier match; QI scorer; record linker
- **verify (G3):** planted recall 100%; carrier invariance 18/18; hard negatives clean; always-flag misses 0

### M6 — P4 adjudication with Groq (G4)
- [ ] deterministic policy engine owns findings + severity; LLM proposer only (schema, evidence ids)
- [ ] redaction before any request; injection attempts logged as findings; suppression caps
- [ ] Groq provider: temp 0, seed, k=3, Fleiss kappa, tokens x price, p95 latency
- **verify (G4):** 0 escapes / 25 injection pages; kappa >= 0.80; 0 always-flag suppressions / 1,000 attempts; cost reported

### M7 — P5 evaluation (G5)
- [ ] protocol + key hash frozen; power analysis printed before the run
- [ ] runner across Presidio / rules / rules+LLM; Wilson CIs; McNemar; miss + false-alarm ledger with reason codes
- [ ] blind-review packet for two reviewers (pending human)
- **verify (G5):** acceptance table from the brief section 8; any undecidable threshold fails loudly

### M8 — P6 report, CLI, handover (G6)
- [ ] canonical JSON + JSON Schema (+ SARIF projection); one HTML view; `phi-scan scan|replay` CLI
- [ ] threat model, runbook, discovery protocol, handover pack
- **verify (G6):** 0 unmasked values in rendered HTML; schema validates; fresh clone reproduces G5 numbers

### M9 — end to end from scratch
- [ ] fresh clone, fresh venv, `run_gates.py` + the e2e command above, numbers match the committed ledger

## Review
(filled in at the end)

# phi-scan — Build Plan & Gate Ledger

Status: awaiting sign-off on §7 open questions. No code written yet, by design.

## 1. Operating constraint (verified 2026-10-28)

| Capability | Result | Consequence |
|---|---|---|
| Python 3.11.9 | present | matches the spec |
| pip + venv | works (TEMP) | deps installable |
| PyPI network | HTTP 200 | models/browsers downloadable |
| Node 24, git 2.53 | present | Playwright + versioning fine |
| Docker | installed, **daemon unreachable** (named-pipe deny) | validate natively; ship a Dockerfile unvalidated |
| Workspace visible to my file tools | yes | deliverables land in `default-workspace/phi-scan/` |
| Workspace visible to running processes | **no** — read and write both denied | code must run from a TEMP mirror |

**Workflow.** Author and execute in `%TEMP%\phi-scan-lab\`, publish to `default-workspace/phi-scan/` at every gate with a `MANIFEST.sha256`. The workspace copy is the deliverable; the TEMP copy is the thing that gets tested. Every gate check runs against the TEMP copy, and the manifest is re-verified on publish.

This is a real limitation: I cannot execute the exact bytes in the workspace. Mitigation is the manifest plus a rule that nothing is published until its gate passes. Flag it at handover — the team, running unconfined, can execute in place.

## 2. Repo layout

```
phi-scan/
  policy/        spec.md, rules.yaml (closed rule registry), identifiers.yaml (18 rows)
  phi_scan/
    collect/     browser.py, api.py, files.py, scope_guard.py, rate_limit.py
    detect/      validators.py, extractors.py, entity_resolution.py, qi_score.py, trackers.py
    adjudicate/  policy_engine.py, llm_adapter.py, injection_guard.py
    evidence/    bundle.py, hashing.py, tokenize.py
    report/      html.py, json_out.py, finding.schema.json
    cli.py
  corpus/        generators, templates, synthea_adapter.py
  fixtures/      site/, api/, docs/
  eval/          protocol.md, runner.py, stats.py, keys/
  tests/         unit/ integration/ metamorphic/ adversarial/
```

## 3. Phases, tasks, and verification

Each task has a completion check that produces output, not an opinion. Nothing proceeds until its phase gate is green.

### P0 — Policy spec (no code)
1. Transcribe PHI definition from 45 CFR 160.103, with paragraph anchors.
2. Build `identifiers.yaml`: 18 rows × {pattern, validator, mask, suppressible, severity_class}.
3. Build `rules.yaml`: closed registry, 11 IDs (160.103; 164.514(b)(1); 164.514(b)(2)(i)/(ii); 164.502(a); 164.502(a)(5)(iii); 164.312(e)(1); 164.312(a),(b); 164.308(a)(1)(ii)(D); 164.528; 42 CFR Part 2; GINA), each with quote + source URL + `contested: true|false`.
4. Define structural record boundaries (§2.3 of the brief).
5. Define identifiability: direct layer + quasi-identifier scoring + small-cell threshold.
6. Define the 8 negative predicates, each with a machine-checkable predicate.
7. Define severity weights and the threshold map.
8. Write the 5 testable invariants.

**Gate G0.** Citation linter resolves 11/11 rule IDs against stored eCFR text (zero unresolved, zero quote mismatches). Identifier table covers 18/18 with a validator and mask. Every negative predicate has ≥1 named fixture. Script prints a table; a human (you) reads the invariants and signs off.

### P1 — Frozen fixtures and answer key (tests before the bot)
1. Generate the synthetic site: static pages + hidden DOM + URL params + storage + third-party beacons + error page.
2. Generate the synthetic API: FHIR-shaped responses + one IDOR path.
3. Generate documents: PDF lab report, XLSX with hidden sheet, image with EXIF, DOCX with tracked changes.
4. Generate the corpus: template-driven, 6 strata × ≥150 positives, ~700 hard negatives, ≥40% must-not-flag.
5. Write the answer key: item → carrier → byte offset → expected verdict.
6. Hash and freeze the key; record in `eval/keys/FROZEN.json`.
7. Write the coverage matrix checker.

**Gate G1.** Carrier matrix 18/18 (every carrier from §2.2 has ≥1 planted leak). Planted leaks ≥40. Negatives ≥40% of corpus. Key hash recorded. Every planted item has exactly one byte offset (no ambiguity). A sampler prints 20 random items with their planted value and location for eyeball check.

### P2 — Evidence chain and collection
1. Playwright collector: HAR + bodies + route interception.
2. API collector from schema.
3. File collector (PDF/XLSX/EXIF/DOCX).
4. Scope guard (allowlist, hard stop, zero out-of-scope requests).
5. Rate limiter (concurrency 1, ≥1s, jitter, page cap).
6. Tokenization at ingest (HMAC, per-scan salt) + encrypted vault + TTL.
7. Evidence bundle writer (hashes, timestamps, versions, replay command).
8. Logged-out re-fetch + indexability probe (canaries only).

**Gate G2.** Two consecutive runs produce byte-identical canonical JSON. Out-of-scope requests = 0. Measured inter-request ≥1.000s from HAR timestamps. Raw planted values in the default artifact tree = 0 (mechanical scan against the answer key). 20/20 sampled findings replay to identical bytes.

### P3 — Detection
1. Validators: SSN ranges, Luhn, NPI/80840, DEA, ICD-10/LOINC/RxNorm syntax, DOB plausibility.
2. Format induction for MRN/member ID.
3. Schema-aware extractors: FHIR, HL7v2, DICOM, X12, CSV/XLSX.
4. Clinical NER (scispaCy) + terminology lookup.
5. Cross-carrier entity resolution.
6. Tracker list + payload decode + hashed-identifier matching.
7. Quasi-identifier scorer.
8. Structural record linker.

**Gate G3.** Planted recall 100% (deterministic set, so this is fair). Carrier-invariance 18/18 (same finding detected in every carrier). Validator suite green including hard negatives: valid NPI not flagged, reference ranges not flagged, code-only pages not flagged, 555-01xx phones not flagged. Always-flag misses = 0.

### P4 — Adjudication
1. Deterministic policy engine owning the finding set.
2. LLM adapter: schema-constrained, evidence-ID-citing, no finding without byte offset.
3. Redaction path: LLM never receives raw values.
4. Injection guard: page text never in instruction channel; attempts logged.
5. Suppression caps.
6. Determinism: pinned snapshot, temp 0, seed, k=3, κ.
7. Cost instrumentation.

**Gate G4.** Injection suite: 0 escapes over 25 crafted pages. Fleiss κ ≥0.80 over k=3. Always-flag suppressions = 0 in 1,000 adversarial attempts. Cost per scan reported. Runs against a stub provider first, so this gate does not need a real key.

### P5 — Evaluation
1. Freeze protocol + key hash.
2. Power analysis printed before the run.
3. Runner across 3 arms (Presidio / rules / rules+LLM).
4. Wilson/bootstrap CIs, McNemar.
5. Miss and false-alarm ledger with reason codes.
6. Blind human adjudication sample.

**Gate G5.** The acceptance table. If a threshold is undecidable at the achieved n, the run fails loudly rather than reporting a pass.

### P6 — Report, CLI, handover
1. Canonical JSON + schema.
2. HTML report.
3. `phi-scan <target>` CLI.
4. Threat model, runbook, discovery protocol, handover pack.

**Gate G6.** Zero unmasked values in rendered HTML (mechanical). Schema validates. Fresh-clone run reproduces the gate G5 numbers.

## 4. What I will decide without asking

pytest; pydantic v2 for schemas; JSON Schema for the finding contract; argparse for the CLI (no typer dependency); attributes-based packages for values; no database (JSONL + files); ruff + mypy strict; Python 3.11 only; Playwright Chromium pinned via `PLAYWRIGHT_BROWSERS_PATH` in TEMP.

## 5. Sequencing rule

P0 → P1 are pure design and fixtures. They need **no API key, no platform access, no BAA**. That is where we start, and it is where the acceptance criteria get locked. The first run of the bot against anything happens only after G1.

## 6. Known risks

1. **Workspace/exec split** (§1). Mitigated by manifest, not eliminated.
2. **No BAA** → LLM sees redacted spans only. This is a design constraint, not a blocker, and it is the stronger architecture. Upgrade path documented.
3. **Docker unvalidated.** Native path is primary.
4. **Synthetic-only fixtures** until 1Cell.ai access. Real-format drift is the main quality risk; mitigated by generating from real schemas (FHIR R4, DICOM, X12) rather than invented ones.
5. **Scope creep in "all US compliance."** Bounded by the rule registry in P0; adding a regime is a registry row plus fixtures, not a rewrite.

## 7. Open questions (blocking P0 start)

1. Which LLM provider will the key be for? (Adapter is provider-agnostic; default = stub provider until a key arrives.)
2. Confirm the TEMP-lab + published-mirror workflow.
3. Confirm corpus at ~1,200 generated items across 6 strata, instead of 2,000 across 30+.
4. Confirm the regime list: HIPAA Privacy/Security/Breach Notification, 42 CFR Part 2, GINA, FTC HBNR, CA CMIA, WA My Health My Data, IL GIPA, TX HB300 + a registry slot for remaining states.
5. Any public 1Cell.ai material usable now (public site, sample report, API docs) for realistic fixtures?
6. Check in at every gate, or batch P0–P2 and report once?

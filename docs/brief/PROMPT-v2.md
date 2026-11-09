# PHI Exposure Evidence System — Build Brief (v2)

## 0. What you are building

A read-only system that produces **evidence of possible PHI exposure** on one authorized target, with a reproducible evidence chain and a pre-registered evaluation proving the numbers are real.

Required phrasing for every finding: **"Possible PHI exposure, needs compliance review."** Never "violation."

The deliverable is an evidence system, not a detector demo. A finding that cannot be reproduced from stored bytes is not a finding.

## 1. Non-goals

- No remediation, no breach determination, no legal advice.
- No write actions: no state-mutating clicks, no form submits, no auth changes, no uploads.
- No crawling outside authorized scope; no probing third-party tracker endpoints.
- No coverage score or single "health" number that can hide misses.

## 2. Phase 0 — the policy spec (write before any code)

Deliver `policy/phi-exposure-spec.md`.

**2.1 Definition.** Quote PHI from 45 CFR 160.103 with paragraph citation. State explicitly: identifiability is a *risk* standard, operationalized by 164.514(b)(1) expert determination. The 18 identifiers in 164.514(b)(2)(i) are a *removal* list for the safe harbor, and 164.514(b)(2)(ii)'s "actual knowledge" clause means the safe harbor is not purely mechanical — full automation cannot make the final call.

**2.2 Finding model.** A finding is a tuple: `subject` (data class) → `carrier` → `observer` → `persistence` → `evidence` → `rule_ids`. Enumerate carriers: visible text; hidden DOM (comments, `display:none`, `aria-hidden`, `data-*`, JSON-LD); URL path/query/fragment; page title; headers (Referer, Set-Cookie, Location); browser storage (localStorage, sessionStorage, IndexedDB, cookies); API responses; third-party requests; downloadable files (PDF text layer, PDF/DOCX/XLSX metadata, EXIF, hidden sheets, tracked changes, speaker notes); error and log surfaces.

**2.3 Record boundaries.** Link identity to health data only inside a structural record: table row, JSON object, URL, log line, HL7 segment group, FHIR resource, form field set, list item. "Same sentence" alone is not a record boundary.

**2.4 Identifiability.** Two layers:
- Direct: each of the 18 identifiers with format spec, validator, and masking rule.
- Quasi-identifier combination scoring: estimate k-anonymity against a stated reference population. Small-cell aggregates (n below a documented threshold) become `review` findings, not PHI findings.
- Non-suppressible always-flag classes: SSN, MRN, insurance/Medicare/Medicaid ID.
- Heightened sensitivity tags: HIV, mental health, substance use, reproductive, genetic, oncology.

**2.5 Negative predicates, each with an evidence requirement.** Provider/staff page (path + schema.org Physician markup + valid NPI via Luhn with 80840 prefix); public health article; group statistics above the cell threshold; reserved or synthetic values (SSA-invalid SSN ranges, RFC 2606 domains, RFC 5737/3849 addresses, 555-01xx phones, Faker/Synthea markers); company contact data; code reference pages (ICD/CPT/LOINC alone); the account holder's own data under a provisioned test account.

**2.6 Severity calculus.** Not buckets. `risk = f(identifiability, sensitivity, audience, persistence, propagation, ease)`, weights documented, thresholds mapped to Critical/High/Medium/Review. Audience is **measured** (§4.3), never assumed. Third-party transmission carries `legal_note: contested`.

**2.7 Legal mapping (closed list).** Rule IDs only from: 160.103; 164.514(b)(1); 164.514(b)(2)(i)/(ii); 164.502(a); 164.502(a)(5)(iii); 164.312(e)(1); 164.312(a),(b); 164.308(a)(1)(ii)(D); 164.528; 42 CFR Part 2; GINA. Tracker and third-party transmission findings must cite the vacatur in *AHA v. Becerra* (N.D. Tex., June 2024) and be framed as contested risk. Never synthesize a rule ID.

**2.8 Discovery protocol.** Scanning may start the 60-day breach-notification clock and creates a new copy of PHI. Specify: who is notified and when; what is sequestered; report classification; encryption; access logging; retention and destruction; counsel-access path for raw bytes.

**2.9 Testable invariants.** The spec asserts, and the test suite checks: no finding without a byte offset; no suppression of a checksum-valid always-flag class; no rule ID outside the list; no unmasked value in any default artifact; every finding replayable from its evidence bundle.

## 3. Evidence contract

Canonical JSON schema per finding. Required: evidence ID; request (method, URL with query hashed, header subset) and response hash; DOM snapshot hash; screenshot redacted **at capture**; timestamps; tool and model versions; replay command; instance list for dedup (one finding, N instances). Machine output: canonical JSON, optional SARIF/OCSF projection. Human output: one HTML view. No raw PHI in default artifacts.

## 4. Collection

**4.1 Authorization.** Written scope: domains, subdomains, API hosts, roles, data classes, explicit out-of-scope. Respect robots.txt and terms. Rate limit: concurrency 1, ≥1s between requests, jitter, hard page cap, documented stop conditions. Isolated browser profile. Provisioned test accounts only.

**4.2 Capture.** Playwright + CDP Network domain → HAR + bodies; route interception; httpx for API enumeration from the schema; sitemap/robots discovery; document extractors for files.

**4.3 Audience measurement.** Logged-out re-fetch of every authenticated hit; indexability probe using **canary strings only**; cache and CDN header inspection; Referer behavior check.

**4.4 Identity oracle.** Two provisioned accounts A and B; differential access test (can A see B's record?); a canary patient record with a controlled unique marker to prove data flow.

**4.5 Ingest safety.** HMAC-tokenize identifiers at ingest with a per-scan salt. Raw bytes go to an encrypted, access-logged vault with TTL. Default mode persists no raw values.

## 5. Detection

- Validators, not bare regex: SSN (area/group/serial rules), Luhn, NPI (Luhn + 80840), DEA, ICD-10/LOINC/RxNorm syntax, DOB plausibility.
- Format induction for MRN and member IDs from observed patterns plus cross-record consistency.
- Schema-aware extraction: FHIR R4 (Patient, Observation, DiagnosticReport, Condition, Specimen), HL7v2, DICOM, X12 837/835, CSV/XLSX.
- Clinical NER from a biomedical model (scispaCy) plus terminology lookup (SNOMED, ICD-10-CM, RxNorm, LOINC, HGVS, ClinVar), not a hand-typed word list.
- Entity resolution across carriers (name variants, DOB, MRN) so "J. Smith" on p.1 links to "John Smith" on p.3.
- Trackers: maintained list plus endpoint patterns plus **payload decoding** plus hashed-identifier matching (SHA-256 of normalized email/phone). The distinction that matters is "PHI transmitted," not "tracker present."

## 6. Adjudication

- A deterministic policy engine owns the finding set and severity.
- The LLM is a proposer and prose writer only: schema-constrained, every claim cites an evidence ID, cannot emit a finding without a byte offset, cannot suppress an always-flag class, cannot invent a rule ID.
- Untrusted text: page content never enters the instruction channel. Attempts to instruct the scanner are themselves logged as injection findings.
- BAA gate: default LLM sees redacted spans only. Raw spans require a signed BAA and a documented deployment posture.
- Determinism: pinned model snapshot, temperature 0, fixed seed, k=3 runs, Fleiss κ reported, disagreements itemized.

## 7. Benchmark (pre-registered)

- Freeze the protocol and the answer-key SHA-256 before run 1. No edits after.
- Taxonomy is a crossing of axes, not a list of anecdotes: {data class} × {carrier} × {observer} × {format} × {obfuscation}. At most 6 primary strata, each with ≥150 positives.
- Hard-negative pool with evidence predicates; ≥40% of the set must be must-not-flag.
- Planted ground truth only. Synthea for clinical coherence, Faker for format variants.
- Adversarial gates: prompt injection; zero-width, homoglyph, base64, HTML-entity and RTL evasion; tokens split across nodes; CSS-hidden content; JSON-LD; HL7/FHIR/DICOM/PDF/XLSX carriers; locale formats.
- Metamorphic tests: the same finding must be caught when moved across carriers.
- Synthetic site and API: ≥40 planted leaks spanning every carrier, plus clean pages that must stay clean.
- Blind human adjudication of the ambiguous stratum by two reviewers who have not seen the code; report κ.
- Arms: plain Presidio, rules-only, rules+LLM.
- Statistics: Wilson or bootstrap CIs per stratum; McNemar across arms; power analysis stated before the run; every miss and false alarm listed with a reason code.

## 8. Acceptance (decidable)

| Criterion | Threshold | How decided |
|---|---|---|
| Always-flag recall (SSN/MRN/insurance) | zero misses | fixed adversarial gate suite, non-statistical |
| Recall per primary stratum | point ≥0.95, Wilson 95% LB ≥0.90 | ≥150 positives per stratum |
| Precision | ≥0.85 overall | false-alarm taxonomy itemized |
| Planted leaks on synthetic site | 100% | deterministic planted set |
| False alarms on clean pages | ≤0.5% of clean page-carriers | clean corpus |
| rules vs rules+LLM | McNemar p<0.05, delta reported | same frozen set |
| LLM stability | Fleiss κ ≥0.80 over k=3 | adjudication decisions |
| Reproducibility | identical canonical JSON from a fresh container | independent re-run |
| Cost | reported per scan (tokens × price, p95 latency) | instrumentation |

Where a threshold cannot be decided at the stated n, say so and propose the n that would decide it.

## 9. Build order

0 policy spec → 1 evidence contract, synthetic site/API, frozen answer key → 2 collection → 3 detection → 4 adjudication → 5 evaluation harness → 6 report renderers. Tests before implementation at every step. Stub all four target adapters behind one collector interface and make the public-site + portal + API slice work end to end before broadening.

## 10. Hard constraints

- Findings phrased "possible PHI exposure, needs compliance review."
- Never store real PHI by default. Masking is not de-identification, so treat every report as a sensitive document.
- Read-only, in-scope, slow, no third-party endpoint probing.
- Every claim traceable, every number reproducible, every miss disclosed.

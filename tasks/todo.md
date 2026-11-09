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

### M4 — P2 collection and evidence chain (G2)  (done, 9b02e71; world re-frozen c29c35b)
- [x] Playwright capture (`phi_scan/browser.py`): one route fetches every request with redirects
      off, paced and scope-checked; out-of-scope requests recorded and aborted; HAR + blurred
      screenshots into the vault; bodies only in a temp mirror
- [x] file collector: aria_hidden, json_ld, indexeddb, cookie, response_header, hidden_sheet,
      tracked_changes, file_metadata (docProps), speaker_notes, exif
- [x] encrypted, access-logged, expiring vault; HMAC tokens; canonical findings.json + evidence.jsonl
- [x] logged-out re-fetch (audience), identity oracle (self / other), Cache-Control public, X-Robots-Tag
- **verified (G2):** canonical identical, tracker received 0, min server gap 1.014 s, 0 planted values
  in artifacts, 62/62 replay. Live recall 65/73: the 8 misses are files nothing links to (v1 API,
  DICOM, FHIR bundle, logs, encoded value) — a stated crawl limit; the file scan finds all 73.
- known: indexability is from robots.txt + X-Robots-Tag only; no search-engine probe (canaries only
  was the brief's constraint, and no engine is in scope)

### M5 progress notes
- corpus baseline (detector tuned on the 60-leak world): S1 52%, S2 67%, S3 86%, S4 46%, S5 83%,
  S6 36% recall; 85/720 negatives flagged. Error analysis on the dev split only.
- done: clinical NER (`phi_scan/clinical.py`, scispaCy en_ner_bc5cdr_md, word-like mention filter),
  negative predicates wired into detect (+ `cleared` reasons), own record via oracle or `own_ids`,
  measured audience, schema-aware HL7 (message = record, DG1 dx), X12 (REF*EA, HI dx, payer
  skipped, natural name order), CSV dx/record headers, labelled MRN forms, Medicare MBI,
  de-obfuscation (`phi_scan/normalize.py`), rendered page text for split nodes, record = whole
  docProps / EXIF block, SQL DDL skipped, lazy clinical-file check, vault log/cache
- world: 73/73 caught, 0 false alarms, 50/50 always-flag; only L074 level differs (static cannot
  measure audience; live does)
- lesson: never generate code containing escapes through a string; use the Edit/Write tools

### M5–M8 status (b4b91b0, protocol frozen a991baa / 6909c04)
- G3: world 73/73, 0 false alarms; carrier invariance 23/23, hard negatives 4/4; scale 1,140 files,
  23.6 MB while scanning (models load once, outside the budget); evasion 14/15 (known limit kept)
- G4: passes on the stub; Groq run needs the key. 25 injection pages, 0 escapes; 0 of 2,000
  adversarial reviews pushed an always-flag finding below High
- G5: protocol frozen before the first scored run; first run started without a key (LLM criterion
  undecidable by design)
- G6: live end-to-end via `phi-scan scan --scope`: 0 unmasked values in 7 outputs, schema valid,
  59/59 replay, measured levels right (IDOR High, mistaken-public page Critical, own record clear)
- browser refuses non-GET/HEAD (G2 proves no write reached the site)
- **owner decision open:** the model may move a non-always-flag finding to Review (confidence >= 0.8,
  25% cap) so rules+LLM can differ from rules; the rulebook says the AI never chooses a level
- **pending human:** blind review (`eval/review_packet.csv`, `python -m eval.adjudication`)

### G5 scored runs (protocol frozen before the first)
- run 1: S1 0.881 (held-out 0.562), S4 0.938, false alarms 15/720 -> fixes from dev errors only
- run 2: S4 1.000, false alarms 0/720, precision 1.000; S1 0.894 (held-out 0.500)
- split design flaw: items rotate through templates by index and every 5th is held out, so some
  templates exist only in held-out. Held-out therefore measures unseen templates. Not inspected;
  instead `tests/probes_prose.py` (40 independent items) found the general gaps -> run 3
- runs 4-6 (Groq): every recall stratum passes (S1 159/160, held-out 0.969 after rendering by
  record); precision 0.982; clean-page false alarms 18/720, all one held-out consented-testimonial
  layout never seen in development; rules vs rules+LLM b=1 c=1 (neutral)
- M9 fresh clone: 22/24 gates; rules/Presidio arms and rules ledger byte-identical. Kappa 0.643 in
  the clone vs 0.820 here: the LLM stability criterion is not reliably met
- owner chose "inspect and disclose" (2026-11-03): `eval/disclosures.md`. One template opened
  (N8.blockquote); consent needle now ignores spacing; held-out N8.blockquote 18 -> 0 flagged.
  N8's held-out number is a development number from here on; other held-out strata stay blind
- run 7 (after that fix): 13/14. False alarms 0/720, precision 1.000, recall unchanged. Only
  rules vs rules+LLM fails: b=3 c=0 (model moved 3 dev-split leaks to Review: S3-0017,
  S4-0012, S4-0132). With rules at ceiling the model can only lose -> owner decision 2

### Launch without a terminal (2026-11-03)
- [x] `install.bat` / `start.bat` -> `phi_scan/launcher.py`: a form on 127.0.0.1:8765 (token +
  Host check), scope written for the scan only, cookies never saved, results in ~/PHI-Scans
- [x] scope needs only `target`; accounts optional; a whole Cookie line accepted; logout and
  sign-out paths never fetched
- [x] access test finds record addresses itself: every OpenAPI/Swagger description at the usual
  paths, or the scope's `api` section; `capture.json` -> `access_test` says what ran or why not
- [x] `START-HERE.md` for people who do not run code
- **verify:** G2 and G6 pass (L071 High via auto-discovery); launcher run on the served site

### First real application (2026-11-03): localhost:4000, a Vue + Vuetify SPA, public pages
- 15 pages, 12 findings, **all false alarms**. Causes, each now a test in `tests/test_real_app.py`
  or `tests/test_single_page_app.py` paired with a planted leak that must still be found:
  - whole `<style>` blocks and print stylesheets read as text: font stacks became people, colour
    codes (#283593) record numbers -> only `content:` strings are read
  - whole SVG files read as text: `stroke=` read as the disease, `font-family` as a person ->
    only drawn text is read
  - "Digital Pathology" read as a person -> "-logy"/"-graphy" words are never surnames
  - a 7,800-character one-line chunk not treated as minified (threshold was 50,000) -> 2,000
  - a "000000" placeholder became a record number -> one repeated digit is never an id
  - the SPA answers "/.env" with its home page -> a body equal to the answer for a missing
    page is not kept; assets a page already loaded are not fetched again
  - the title "Augusta Digital Pathology" read as the person "Augusta Digital" -> product
    words (digital, portal, viewer, ...) join NAME_STOP; "Jane Doe Oncology Report" still a name
- found on the way: evidence offsets counted characters, not bytes, so after any non-ASCII
  text the span pointed early (replay still matched the wrong bytes) -> `_byte_span`
- found on the way: pacing was counted from the send, the server measures arrival; G2 saw
  0.94 s between two requests once the request order changed -> also counted from the answer
- **verify:** rescan of the same public pages: 0 findings (was 12), 44 requests (was 81),
  finished without hitting the request cap; G2, G3, G6, check_* and 101 tests pass
- G5 after the fixes: run 8 failed check_detect inside G5 only (passed alone 4 times; output
  was discarded, so G5 now prints it on failure); run 9 13/14, every recall and precision
  number unchanged, rules vs rules+LLM b=2 c=0
- deviation: procedures and tests are recognised by medical word formation and a short noun list,
  British spellings folded; licensed SNOMED/CPT unavailable, public ICD-10-PCS not downloaded

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

### Realistic hospital site (2026-11-04): false alarms before real sites find them
- `fixtures/build_realsite.py`: doctor directory and bios (title, slug, JSON-LD, NPI), provider
  API, sitemap of doctors, health article with author/reviewer, press release, trial listings,
  job post, support-group event, sample insurance card, FHIR docs, privacy notice, WordPress
  users endpoint, GTM/GA, plus 8 planted leaks in the same pages; `fixtures/thirdparty/` holds
  seven real MIT-licensed vendor files used unmodified
- first measurement: 26 false alarms, 1 miss. Root causes and fixes (each tested in
  `tests/test_real_app.py`):
  - title-case org names ("Mercy Valley") -> a run the page repeats before an org word is the org
  - staff and authors (Dr., credentials, "Name, president and CEO", bylines, meta author,
    JSON-LD author/organizer) -> N1/N2 evidence widened; every name needs it; patient cue blocks
  - "Last, First" on "Riverton, Ohio" and "Hospitals, Doctors" -> states and lists rejected;
    evidence now located for flipped names
  - code: model fragments as names -> names must be name-shaped; in scripts and source maps a
    name counts only beside a record id and bare numbers never do; minified = >200 chars/line
  - JSON: "name" of a Place/Event/Organization/MedicalCondition is not a person; predicates now
    judge the key-based names the decision used
  - field labels "Member ID", "Rx BIN"; placeholders JOHN Q SAMPLE, 123456789; NCT ids
  - dates/phones alone in title/meta/JSON-LD are the site's (hidden carriers keep the wider rule)
  - miss: sitemap links are URL-decoded and "&dx=" counts as a diagnosis label
- found on the way (pre-existing): "Rafael Ibarra Oncology Report" was tagged ORG and hid the name
- **verify:** realsite 8/8, 0 false alarms; check_detect, G0, G1, G2 (gap 1.031 s), G3, G6,
  evasion, context, emit, 108 tests; G5 13/14 with every recall and precision number unchanged

### First public real site: HAPI FHIR public test server (2026-11-05)
- SMART Health IT sandbox skipped: its robots.txt says `Disallow: *`. HAPI has no robots.txt and
  exists for public testing; 20 pages, about 1 request a second, AI off
- run 1 crashed: a full-page screenshot of the 1.9 MB front page timed out and ended the scan.
  Screenshots now fail soft and are listed in `capture.json` -> `screenshots_skipped`
- run 2: 16 findings, all false (the crawl reached only the server's own UI). Causes and fixes,
  each tested in `tests/test_real_app.py` and locked into `fixtures/build_realsite.py`:
  - a bare capitalised pair ("Server Actions", "Get Tags") is weak evidence: alone it no longer
    flags a title, comment or script, and no 6-8 digit count beside it becomes a record number.
    It is backed by the model, an honorific or label, "Last, First", a record value directly
    beside it, or record fields (dob, mrn, dx) in the same object
  - acronym pairs ("HAPI FHIR", "Swagger UI") and code capitals ("CatalogEntry") are not names,
    from any source including the model; McDonald, LaToya, DiCaprio still are
  - in a long unstructured block a weak name needs its health fact within 150 characters
  - all-caps "chemicals" (HFQL) and run-together type names (MolecularSequence) are not health
  - in scripts, a weak name beside a health word is noise; a person needs real evidence
- true positives on real software output: one HAPI Patient search page (20 test patients) as a
  public file: 20/20 found, Critical. Found on the way: the whole-bundle finding carried all 20
  record numbers and linked them as one person; first names alone also linked people. Lists
  with more than 3 ids no longer link, single-word names never do: 20 findings, 20 people
- speed: detection on HAPI's 20 pages was dominated by the language models. Table cells are read
  only within the first 20,000 characters, both models read in batches, and the whole-page value
  list is built only when used: 311 s CPU for 20 pages including a 1.9 MB page
- G5 caught the weak-name rule's cost before commit: web carriers 160 -> 144. Causes: a
  name the model found at the same span as a pair was wrongly weak (bug), and data-* values
  lost their label. Fixed: backing readings are tracked apart; an attribute's own name
  (data-patient) labels its value. Real-site follow-ups the same evaluation then exposed:
  a bare number counts only within 80 characters of the name (a capability statement's
  counts sat 50 KB from a contact name), and inside scripts the prose model's PERSON label
  alone backs nothing ("Unique Identifier" in embedded API docs)
- **verify (final):** HAPI pages 0 false alarms; HAPI patients 20/20 as 20 people; realsite
  9/9 and 0; 118 tests; 14 quick gates; G2 (gap 1.022 s), G6; G5 13/14 with recall and
  precision unchanged; rules vs rules+LLM b=5 c=0 this run

### Second public real site: OpenEMR demo (2026-11-06/07)
- target `https://demo.openemr.io/openemr` (host root has no robots.txt; the app redirects to
  its login page). Run 1 crashed: reading localStorage was refused ("Access is denied for this
  document") and the scan ended with nothing saved
- fixed: storage, IndexedDB, cookies, a page's links and any single request now fail soft and
  are listed in `capture.json` -> `collection_skipped` (test: a page load and a file whose
  connections are dropped)
- run 2 completed: 0 findings, but **nothing was scanned**. OpenEMR's own robots.txt at
  /openemr/robots.txt says `Disallow: /`; the bot obeyed it. Run 1's refusal was the browser
  still on its blank start page. `pages: 7` in capture.json counts addresses considered, not
  pages read (only robots.txt was kept, 4 requests sent)
- open: a scan stopped by robots.txt reports "0 findings", which reads as clean; it should say
  nothing was scanned and why. "pages" should count pages actually read
- one full-suite run failed the new test while the machine slept (18 h wall clock); details not
  kept; 3 runs since pass (119 tests)

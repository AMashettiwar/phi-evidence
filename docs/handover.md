# Handover

Written 2026-11-02. Source of truth for status is `tasks/todo.md`; this page summarises it. Several milestones were still in progress when it was written, so confirm gate results by running the commands.

## 1. What the system is

A read-only tool that looks at one authorised target and reports possible PHI exposure, each finding worded "Possible PHI exposure, needs compliance review." It captures what a browser sees and sends, stores raw bytes in an encrypted, access-logged, expiring vault, detects identifiers with validators and rules, lets a language model (Groq) review redacted spans under hard caps, and writes findings that can be replayed from stored bytes. It does not fix anything, decide that a breach occurred, or claim a page is clean.

## 2. Gate ledger

Run all: `python tools/run_gates.py` (the single ordered list; CI calls it). Brief gate numbers G0 to G6 come from `docs/brief/PLAN.md`.

| Gate | Command | Status per `tasks/todo.md` |
|---|---|---|
| G0 policy spec | `python tools/gate_g0.py` (also `python tools/lint_policy.py`) | Machine checks built. Rulebook sign-off pending a human. |
| G1 fixtures and key | `python tools/gate_g1.py` | Done, frozen. Carriers 23/23, 73 planted leaks, one location each. |
| G2 collection and evidence | `python tools/gate_g2.py` (with `tools/check_collect.py`) | Passes: two live runs give byte-identical canonical findings, the tracker received 0 requests, 0 writes reached the site (1 page POST blocked), min server-side gap 1.015 s, 0 planted values in either artifact tree, 61/61 findings replay in both runs. |
| G3 detection | `python tools/gate_g3.py` (with `tools/check_detect.py`) | Passes. World 73/73 caught, 0 false alarms, 50/50 always-flag; the same record found in 23/23 carriers; hard negatives 4/4 clean. Independent probes (`tests/test_probes.py`) 30/30 prose, 7/7 layouts, 0/10 negatives flagged. |
| G4 adjudication | `python tools/gate_g4.py` (with `tools/check_ai.py`) | Passes on Groq `openai/gpt-oss-120b`: 0 injection escapes over 25 pages (all 25 logged), 0 of 2,000 adversarial reviews pushed an always-flag finding below High, Fleiss kappa 0.820 over k=3 (40 findings; 18 distinct model fingerprints, so determinism is best effort), 145 calls for $0.025, p95 1.34 s. |
| G5 evaluation | `python tools/gate_g5.py` | Gate exists. Undecidable thresholds must fail loudly. Blind review pending humans. |
| G6 end to end | `python tools/gate_g6.py` runs `python -m phi_scan.cli scan --scope fixtures/scope.yaml` against the served site | Passes: 0 unmasked planted values in report.html, SARIF, findings, run, capture, evidence and index; schema valid; every finding replays; measured levels right (IDOR record High, page public by mistake Critical, own record not reported). |
| M9 fresh clone | `python tools/fresh_clone.py` | Clones HEAD, builds a venv from `requirements.lock` only, runs every gate, compares the acceptance table with the committed `eval/results.json`. |

Other gates in the list: `pytest -q tests`, `check_world`, `check_crawl`, `check_scale`, `check_evasion`, `check_context`, `check_emit`, `check_no_exam_content`, and the fixture builders. `TESTING.md` says what each proves. I have not run them for this document.

## 3. Decisions and deviations from the brief (from `tasks/todo.md`)

- LLM provider: Groq (OpenAI-compatible HTTP, stdlib client). Key from `GROQ_API_KEY` or the git-ignored `.env`. The model only ever sees redacted spans of synthetic data.
- Groq has no dated model snapshots: model id and `system_fingerprint` are recorded per call; stability is measured (k=3, Fleiss kappa), not assumed.
- Synthea (Java) is not used: Faker for format variants, real FHIR R4 / HL7v2 / DICOM / X12 shapes.
- SNOMED and LOINC tables are licensed: terminology lookup uses public sets only.
- Regimes: the brief's closed list of 11 rule ids (12 registry entries, as (b)(2)(i)/(ii) split). Other regimes stay a registry slot.
- Corpus: 6 strata x 160 positives = 960 positives plus about 700 hard negatives (at least 40%). Meets the brief's 150 per stratum and the 40% rule.
- "Fresh container": Docker daemon was unreachable on the build machine; fresh clone plus fresh venv is the reproducibility proof, and the Dockerfile ships marked unvalidated.
- Benchmark circularity: the same author built detector and benchmark. Mitigation: key hash frozen before the first scored run, a held-out split never used while tuning, every miss itemised. Independent validation still needs the human reviewers.
- Missing model is an error, not a silent regex fallback.
- Per-scan keys make the index differ between runs by design. Canonical JSON therefore carries no salted tokens, vault addresses or timestamps; those go in `evidence.jsonl`.
- Reserved SSN: area 000/666, group 00, serial 0000, or 987-65-4320..4329. Area 9xx is the ITIN space and stays an identifier.
- Spec 2.6: severity is the rulebook's ordinal "worst of" rule, not the brief's numeric weights.
- Spec 2.8: the 60-day clock is noted, never determined, by the tool.
- Live capture recall on the world was 65/73 in G2: the 8 misses are files nothing links to (v1 API, DICOM, FHIR bundle, logs, encoded value), a stated crawl limit; the file scan finds all 73.
- Indexability is from robots.txt and X-Robots-Tag only; no search-engine probe.
- A rulebook rule is stricter than the brief: a testimonial without a visible consent or fiction marker is a finding.

## 4. Open owner decisions

1. Severity: ordinal "worst of" rule (implemented, rulebook section 7) versus the brief's numeric `risk = f(...)` weights. Spec 2.6 records it.
2. AI moving findings to Review: the rulebook says the AI never chooses a level; the brief wants rules+LLM to differ measurably from rules alone. Current rule (`phi_scan/ai.py`): model confidence at least 0.8, not always-flag, at most 25% of findings, never deleted. Confirm or remove.

## 5. Pending humans

| Item | What to do |
|---|---|
| Rulebook sign-off (G0) | Work the checklist at the end of `docs/brief/rulebook.md`; record in `policy/SIGNOFF.md`. |
| Blind two-reviewer adjudication (G5) | Two reviewers who have not seen the code fill `reviewer_a` and `reviewer_b` ("exposure" or "not_exposure") in `eval/review_packet.csv`, then run `python -m eval.adjudication`. It reports Cohen's kappa and exits 2 until both columns are filled. |
| Fleiss kappa with the real model | Needs a Groq key. |
| Discovery protocol | Complete `docs/discovery-protocol.md` before a real target. |
| Counsel review | Legal registry and protocol. |

## 6. Known limits

- No OCR: text burned into images is not read.
- No archive, e-mail or office-container recursion beyond the carriers listed in `TESTING.md`.
- The crawl sees only linked, sitemapped and a fixed list of well-known paths. Unlinked files need the file scan.
- Benchmark is synthetic only, and detector and benchmark share an author. Held-out split reduces, not removes, optimism.
- Groq's seed is best effort; outputs can vary between runs.
- JPEG and PPTX fixtures are minimal (JPEG not decoded by a real decoder; PPTX has no slide master).
- No census table is bundled for the quasi-identifier scorer, so its k estimates lack a stated reference population (spec 2.4 says one will be bundled).
- Spelled-out letters and digit substitution defeat the text detectors (`TESTING.md`).
- Public benchmarks (n2c2, PhysioNet deid) have not been run.
- Browser path guard checks host and path, not HTTP method (threat model 3.5).
- Temp mirror is unencrypted while a scan runs; `destroy()` does not overwrite the key file.
- Presence in scope of a tracker is observed only through what pages send; the tool does not probe it.

## 7. Where everything lives

| Path | Contents |
|---|---|
| `docs/brief/PROMPT-v2.md`, `PLAN.md`, `rulebook.md` | The brief, the gate plan, owner decisions. |
| `policy/` | `phi-exposure-spec.md`, `rules.yaml`, `identifiers.yaml`, `negatives.yaml`, `severity.yaml`, `source/` (eCFR text). |
| `phi_scan/` | Code: `browser.py` (capture), `collect.py`, `vault.py`, `detect.py`, `ai.py` (Groq and stub), `evidence.py`, `report.py`, `cli.py`. |
| `fixtures/` | Synthetic world, corpus, injection pages, `scope.yaml`; builders in `fixtures/build_*.py`. |
| `eval/` | `protocol.md`, `frozen.json`, runner, stats, `review_packet.csv`, `adjudication.py`. |
| `tools/` | Gates and checks; `run_gates.py` is the list. |
| `tests/` | pytest suite. |
| `tasks/todo.md` | Milestones, decisions, status. |
| `TESTING.md`, `GATES.md`, `README.md` | Gate explanations; the pre-registered exam-readiness ledger; overview. |
| `docs/threat-model.md`, `runbook.md`, `discovery-protocol.md` | Operator documents. |
| `~/.phi-evidence/keys` | Per-scan keys (outside the repository). |

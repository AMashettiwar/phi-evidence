# PHI exposure specification

The document the code must obey. Brief: `docs/brief/PROMPT-v2.md` section 2. Owner decisions
in plain English: `docs/brief/rulebook.md`. Where they differ, this file says which one wins
and why. Machine-readable parts live beside it and are checked by `tools/gate_g0.py`:

| File | Holds |
|---|---|
| `rules.yaml` | the closed rule registry, each quote verified against `source/` by `tools/lint_policy.py` |
| `identifiers.yaml` | the 18 Safe Harbor identifiers: check, mask, always-flag |
| `severity.yaml` | levels and the carrier / audience ladder |
| `negatives.yaml` | the 8 do-not-flag predicates, each with evidence and fixtures |

Every finding is worded **"Possible PHI exposure, needs compliance review."** Never "violation".

## 2.1 Definition

PHI is individually identifiable health information as defined in 45 CFR 160.103
(rule `phi_definition`; quote in `rules.yaml`).

Identifiability is a **risk** standard. 45 CFR 164.514(b)(1) (`expert_determination`) lets an
expert decide that the risk of identification is very small. The 18 identifiers of
164.514(b)(2)(i) (`safe_harbor`) are a **removal list**, not a definition of everything that
identifies a person. 164.514(b)(2)(ii) (`actual_knowledge`) adds that the covered entity must not
know the remainder could identify someone. That clause makes Safe Harbor non-mechanical, so the
tool never certifies data as de-identified and never claims a page is clean.

## 2.2 Finding model

A finding is the tuple `subject -> carrier -> observer -> persistence -> evidence -> rule_ids`.

- **subject**: the data class (identifier keys from `identifiers.yaml`, plus health facts).
- **carrier**: where it sits. Visible text; hidden DOM (comments, `display:none`, `aria-hidden`,
  `data-*`, JSON-LD); URL path / query / fragment; page title; headers (Referer, Set-Cookie,
  Location); browser storage (localStorage, sessionStorage, IndexedDB, cookies); API responses;
  third-party requests; downloadable files (PDF text layer, PDF / DOCX / XLSX metadata, EXIF,
  hidden sheets, tracked changes, speaker notes); error and log surfaces.
- **observer**: who can see it, **measured** (logged-out re-fetch, section 4.3 of the brief), never
  assumed. Values: `public`, `authenticated_other` (another patient's data behind a login),
  `authenticated_self` (the test account's own record), `third_party`.
- **persistence**: transient view, stored on the client, indexed, cached, logged.
- **evidence**: an evidence id pointing at stored bytes with a byte offset (section 3 of the brief).
- **rule_ids**: only ids present in `rules.yaml`.

## 2.3 Record boundaries

Identity and health link only inside one structural record: a table row, a JSON object, a URL, a
log line, an HL7 segment group, a FHIR resource, a form field set, a list item. "Same sentence" is
not a record boundary. Two facts in different records are not linked.

## 2.4 Identifiability

- **Direct layer.** Each of the 18 identifiers has a check (`must_pass_check`), a mask, and an
  `always_flag` flag in `identifiers.yaml`. Validators, not bare patterns: SSN area / group /
  serial rules, Luhn, NPI with the 80840 prefix, DEA check digit, DOB plausibility.
- **Quasi-identifier layer.** ZIP3, birth year, sex, and rare diagnosis combine into an estimated
  equivalence-class size `k` against a stated reference population (US census counts bundled with
  the tool). `k < 11` makes a `review` finding, not a PHI finding.
- **Small cells.** An aggregate whose count is below 11 is a `review` finding. 11 follows the CMS
  cell-suppression convention; it is a parameter in `severity.yaml`, not a law.
- **Always-flag, never suppressible:** SSN, medical record number, health plan / Medicare /
  Medicaid id. The adjudicator may not clear these.
- **Owner decision (rulebook section 2):** a street address alone is a finding, level Medium.
- **Heightened sensitivity tags:** HIV, mental health, substance use, reproductive, genetic,
  oncology. A tag raises the level by one step, never above Critical.

## 2.5 Negative predicates

Eight situations are not findings, and each needs evidence rather than a hunch. They are listed
with their evidence requirement, implementing function, and fixtures in `negatives.yaml`. The
rulebook's eighth predicate (testimonial with a **visible** consent or fiction marker) is stricter
than the brief: a testimonial without a visible marker is a finding.

## 2.6 Severity calculus

The brief asks for `risk = f(identifiability, sensitivity, audience, persistence, propagation,
ease)` with documented weights. **The owner's rulebook (section 7) overrides the numeric form:**
the level is the worst of fixed ordinal rules, so the adjudicator can never choose it. The six
factors are still the inputs:

| Factor | Effect on level |
|---|---|
| identifiability | always-flag id, or identity + health in one record: eligible for Critical. Identifier alone: Medium. QI or small cell: Review |
| audience (measured) | public: Critical. authenticated_other: High. authenticated_self: not a finding |
| persistence | URL, title, hidden code, browser storage: at least High |
| propagation | sent to a third party: Critical, with `legal_note: contested` on public pages |
| sensitivity | a heightened tag raises one step |
| ease | an unlinked file is still reachable: same as its audience |

Level = the worst level any factor reaches. Thresholds and ladders are in `severity.yaml`.
**Open for owner confirmation:** numeric weights (the brief) versus this ordinal rule (the rulebook).

## 2.7 Legal mapping (closed list)

Rule ids come only from `rules.yaml`, which covers the brief's eleven citations: 160.103;
164.514(b)(1); 164.514(b)(2)(i) and (ii) (two ids); 164.502(a); 164.502(a)(5)(iii); 164.312(e)(1);
164.312(a),(b); 164.308(a)(1)(ii)(D); 164.528; 42 CFR Part 2; GINA. Tracker and third-party
transmission findings cite *American Hospital Association v. Becerra* (N.D. Tex., June 2024), which
vacated part of the HHS tracking-technology guidance, and are framed as **contested risk**. The tool
never synthesises a rule id. Other regimes (FTC HBNR, state laws) are a registry row plus fixtures
when added, not a code change.

## 2.8 Discovery protocol

Scanning a live system can be the moment an organisation *discovers* an exposure, which may start
the 60-day breach-notification clock (45 CFR 164.404), and the scan itself makes a new copy of PHI.
Before any scan of a real target the operator fills in, in `docs/discovery-protocol.md`:

1. **Who is told, and when**: the privacy officer within one business day of a Critical finding;
   the security officer for any authentication or transport finding.
2. **What is sequestered**: the vault for that scan. Reports carry masks and hashes only.
3. **Report classification**: every report is a sensitive document. Masking is not de-identification.
4. **Encryption**: vault bytes encrypted at rest with a per-scan key; the key is not stored with them.
5. **Access logging**: every vault read is appended to the scan's access log with who and why.
6. **Retention and destruction**: the vault has a TTL (default 30 days); destruction is logged.
7. **Counsel access**: raw bytes are released only to counsel, by a logged vault read.

## 2.9 Testable invariants

| # | Invariant | Checked by |
|---|---|---|
| 1 | no finding without a byte offset into stored evidence | `tools/check_emit.py` |
| 2 | no suppression of a checksum-valid always-flag class | `tools/check_ai.py` |
| 3 | no rule id outside `rules.yaml` | `tools/check_detect.py` |
| 4 | no unmasked value in any default artifact | `tools/check_collect.py` |
| 5 | every finding replays from its evidence bundle | `tools/check_emit.py` |

The gates named here are tightened in later milestones (G2 replay, G4 adversarial suppression).

# GATES — pre-registered exam readiness

Scope of this pass: the P0 items and the hygiene rules. Everything below is
checked by a command or has an ABANDON line with a reason. No exam was opened,
and no exam score is recorded anywhere in this repository.

- [x] G1 no answer-key input in the app
  CHECK: python tools/check_no_exam_content.py
  EXPECT: PASS
  EVIDENCE: app.py takes a document zip and a context only; the key uploader and
  the scoring path were removed, not hidden behind a flag.

- [x] G2 no exam content in the repository
  CHECK: python tools/check_no_exam_content.py --key <sealed key, CI secret>
  EXPECT: PASS
  EVIDENCE: fifteen exam-derived strings were removed from phi_scan/detect.py,
  phi_scan/structured.py, TESTING.md, GATES.md and the scoring tools; the scoring
  tools themselves were deleted from the repo.

- [x] G3 existing gates still pass
  CHECK: python tools/check_detect.py && python tools/check_collect.py && python tools/check_evasion.py
  EXPECT: PASS
  EVIDENCE: world 60/60 with 0 false alarms; collection PASS; evasion 14/15
  (was 13/15 before the P0 work).

- [x] G4 covered-entity vs public-web changes the test
  CHECK: python fixtures/build_context.py && python tools/check_context.py
  EXPECT: PASS
  EVIDENCE: "covered-entity findings 6 files ['access.log','roster.csv']; \
public-web findings 0 files []" — identifier-alone reported, identity+health suppressed.

- [x] G5 positional output round-trips through redaction
  CHECK: python tools/check_emit.py
  EXPECT: PASS
  EVIDENCE: 66 findings, 66 positional lines, 30 document verdicts, 32 redacted
  files, **0 findings after rescan**.

- [x] G6 frozen tag handed to the examiner
  EVIDENCE: tag `exam-ready-2026-10-30` on the commit that carries this ledger.
  The tree is not modified after the tag; the examiner checks out that tag only.

ABANDON: P1 containers (archives, MIME, PDF revisions, office hidden layers,
nested DICOM, RTF) — not started. Each needs its own extractor plus a
source-offset map; that is a multi-leaf build, not a patch.

ABANDON: P1 normalisation layer and date/age engine — not started. The current
detectors see one form of a value; spelled-out and substituted forms are still
missed, which is why the recall ceiling is bounded.

ABANDON: P2 name source, eponym disambiguation, residues and derived identifiers,
precision lexicons — not started. The rule-based name finder remains in place.

ABANDON: P3 pixels (OCR, barcodes, face detection) — not started. No OCR engine
is installed and the sandbox cannot run one reliably.

ABANDON: public corpora (n2c2 2014, PhysioNet deid) — credentialled access or a
data-use agreement is required; neither is available here.

The honest state: two P0 items are done and gated, the rest of the brief is
unstarted. The tool is better in general — a stated scope, real positions, a
provable redaction round-trip — but its recall has not been measured on any
public corpus, and nothing here has been compared head-to-head with Presidio yet.

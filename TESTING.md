# Testing

Every claim the tool makes is backed by a gate you can run yourself. A gate that
cannot fail is not a gate, so each one has a control that would catch it lying.

Measurements live in two places only: **our own fixtures** and **public
corpora**. Scores against any exam are produced by the examiner and are not
recorded here.

```bash
python tools/run_gates.py
```

The ordered list of gates lives in `tools/run_gates.py` and nowhere else; CI runs
the same file.

## What each gate proves

| Gate | Property |
|---|---|
| `check_world` | every planted leak exists exactly where the key says |
| `check_collect` | every carrier is reachable; the index holds no PHI |
| `check_detect` | all leaks found; nothing invented |
| `check_realsite` | on a realistic hospital site (doctor bios, bylines, trial investigators, sample cards, real vendor libraries) every planted leak is found and nothing else is flagged |
| `check_ai` | a model cannot add, remove or promote a finding |
| `check_crawl` | one host, GET only, robots obeyed, rate limited |
| `check_scale` | linear at volume, deduplicating, bounded memory |
| `lint_policy` | quoted rules still match downloaded eCFR text |
| `check_evasion` | realistic hiding techniques do not defeat it |
| `check_context` | covered-entity reports an identifier alone; public-web does not |
| `check_emit` | redacting our own spans and rescanning yields zero findings |

## The two contexts

`--context` decides what counts. It is not a severity knob; it changes the test.

- **covered-entity** (default for scanning files): every Safe Harbor identifier
  of a patient, relative, employer or household member is reportable on its own.
  Logs, rosters, exports and audit trails count. 45 CFR 164.514(b)(2)(i).
- **public-web** (default for `crawl`): identity plus a health fact. A page that
  names a doctor is not an exposure; a page that names a patient and their
  diagnosis is.

`fixtures/build_context.py` writes a log line that holds only an MRN and an
email, and a roster holding only names and dates of birth. `check_context.py`
requires both to be reported under covered-entity and suppressed under
public-web.

## Positional output

`--emit findings.jsonl` writes one line per occurrence, in three shapes:

```json
{"doc": "notes.txt", "start": 412, "end": 423}
{"doc": "scan.pdf", "text": "MASKED VALUE"}
{"doc": "photo.jpg", "has_phi": true}
```

Text files get code-point offsets, so a consumer can slice the source without
knowing our internals. Binary files get the value, because there is no reliable
character offset inside a DICOM header or a PDF object.

`--redact DIR` writes redacted copies using those same spans. `check_emit.py`
redacts the world, rescans the output, and requires **zero findings** — a
round-trip, which is the only proof the offsets are real.

## What is not covered

- No OCR. Text burned into an image is not read.
- No archive, e-mail or office-container recursion; those layers are unread.
- Spelled-out letters and digit substitution defeat the text detectors.
- Public benchmarks (n2c2, PhysioNet deid) need credentials or a data-use
  agreement and have not been run.

Stating these is part of the deliverable.

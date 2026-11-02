# phi-scan

A read-only scanner that looks for patient data exposed by a website or health
system, and explains each finding in plain English with the rule it relates to.

It never writes to the target, never stores a patient value in its output, and
never asserts that a law has been broken. It reports what it found, where it
found it, and how confident it can be.

---

## What it actually finds

A text scanner only reads the page. Most real leaks are not on the page.

| Where | Example |
|---|---|
| Page content | a testimonial with a diagnosis |
| The address bar | `?name=…&dx=B20` in a link |
| Page title | a patient name in the tab |
| Hidden HTML / CSS | off-screen text, `display:none`, `data-` attributes |
| JavaScript | a debug record left in a bundle, a source map |
| Browser storage | `localStorage.setItem('lastPatient', …)` |
| Third-party calls | a tracker URL carrying a record number |
| Build leftovers | `.env`, `.git/COMMIT_EDITMSG`, `robots.txt`, `sitemap.xml` |
| Files nobody links to | a CSV export, a database dump, a PDF |
| Formats | FHIR bundles, DICOM headers |

27 carriers in total. They are listed in `tools/check_world.py`.

## Quickstart

Two commands. The first builds a synthetic clinic with 60 hidden leaks and scans
it; nothing real is touched, and no patient data exists anywhere in the output.

```bash
python -m pip install -r requirements.lock
python -m phi_scan.cli demo
```

You get a report like:

```
phi-scan  -  possible PHI exposure, needs compliance review
target      fixtures/world
findings    60
levels      critical 55   high 5

CRITICAL  -  anyone could see this
  api/patient_1042.json    api_response   ******3836
                           id:names,mrn,dates  grade:B  bytes:214+10
```

Scan something of your own:

```bash
python -m phi_scan.cli scan --source ./my-export --out ./artifacts/mine
python -m phi_scan.cli crawl --url https://example.com --out ./artifacts/site
```

The spaCy model is required and pinned in `requirements.lock`. A missing model is
an error, not a silent fallback to regex names: that fallback once let the same
commit pass on one machine and fail in CI.

### Verify the whole thing

```bash
python tools/run_gates.py        # every gate, in order; exit 0 means all passed
```

### Using it as a library

```python
from pathlib import Path
from phi_scan.collect import collect
from phi_scan.detect import detect

collect(Path("my-site"), Path("out"))                 # evidence into a vault
for finding in detect(Path("out/index.jsonl"), Path("out/vault")):
    print(finding["level"], finding["path"], finding["value_mask"], finding["rules"])
```

`detect()` takes only the index, the vault, and the operator's own list of
authenticated URL prefixes. It never receives the answer key, so it cannot cheat.

## How it works

```
files or a crawl
      │
      ▼
  collect.py ── every interesting span is copied into a content-addressed vault.
      │          The index stores only a hash, an offset and a length.
      ▼
  detect.py ─── decides what is a finding, from the evidence and the rules.
      │          Identity + health, or a record number on its own.
      ▼
 severity.py ── the worse of "who can see this" and "what kind of carrier".
      │
      ▼
    ai.py ───── optional. Can annotate and lower a level by one. Cannot add,
                remove, or promote anything, and never sees a patient value.
```

Structured data does not use the model at all — see below.

## Structured data is read by its keys, not by a model

On a real clinical API response, the text-based name detector found **1 of 41**
identifiers and invented **887**. Every field label in a lab system is a
capitalised clinical term: *Delivery Note* is not distinguishable from *Jane
Smith* by vocabulary alone.

So for parsed JSON, identity comes from the key it sits under — `first_name`,
`last_name`, `subject_id`, `suid`, including nested and FHIR `name[].text`.
Text detection applies to prose and to source maps only.

```bash
python tools/key_scan.py capture.har    # key-anchored, no model, counts only
```

## How well it works

| Corpus | Result |
|---|---|
| Synthetic world, 60 planted leaks, 27 carriers | **60/60, zero false alarms** |
| 127 labelled public documents, name detection | **82.9% precision, 70.3% recall** |
| Microsoft Presidio, same corpus | 82.5% precision, 66.4% recall |
| Structured clinical JSON | 41/41 by key; text detection 1/41 |

The honest part: the first two rows are measured on data this project generated
or that is publicly labelled. Real production traffic has been seen exactly once.

## What it will not do

- It does not write. The fixture server rejects writes with `405`, and the
  collector has no write path.
- It does not store a patient value. Findings carry a mask (`***-**-1234`), a
  hash, and a byte offset. The raw bytes live in the vault, never in the report.
- It does not call anything a violation. Findings say "possible exposure, needs
  compliance review".
- It does not reach outside scope. One host, `robots.txt` obeyed, a delay before
  every request.
- It does not trust page content. Twenty hostile pages that instruct the scanner
  to ignore a leak are all still reported; the attack changes nothing.

## Limits

- No browser. Browser storage and dynamically fired beacons are found in source,
  not observed.
- No OCR, so text burned into a DICOM image is not read. The header is.
- A crawl sees only what is linked or in the sitemap. Against the fixture site it
  found 3 findings where a full read of the same files found 60.
- A single-token name (a mononym) is missed.
- Commercial scanners have not been tested against; only Presidio has.

## Repository layout

```
phi_scan/        the scanner: collect, detect, severity, crawl, vault, ai
policy/          the rules. 18 identifiers, 12 rule ids, severity ladder,
                 plus the eCFR text each quote was verified against
fixtures/        build_world.py generates the synthetic clinic and its answer key
tools/           check_*.py are the gates; each proves one property
docs/DESIGN.md   how the design got here, including what failed
```

Every claim above is reproducible with a `tools/check_*.py` script.

# Testing

Every claim the tool makes is backed by a gate you can run yourself. A gate that
cannot fail is not a gate, so each one has a control that would catch it lying.

```bash
python fixtures/build_world.py     # then any of:
python tools/check_world.py        # the answer key matches the files
python tools/check_collect.py      # every carrier reached, no PHI in the index
python tools/check_detect.py       # all leaks found, no false alarms
python tools/check_ai.py           # the AI layer cannot make it worse
python tools/check_crawl.py        # one host, GET only, robots obeyed
python tools/check_scale.py        # linear at 20x, memory bounded
python tools/lint_policy.py        # every quote still matches the law text
python fixtures/build_evasion.py   # then:
python tools/check_evasion.py      # can it be evaded?
```

## What each gate proves

| Gate | Property | Current result |
|---|---|---|
| `check_world` | every planted leak exists exactly where the key says | 60 leaks, 27 carriers, 34 files |
| `check_collect` | every carrier is reachable; the index holds no PHI | 27/27 carriers, 0 values in index, 20/20 replay |
| `check_detect` | all leaks found; nothing invented | **60/60, 0 false alarms** |
| `check_ai` | a model cannot add, remove or promote a finding | 0 values in requests, attack changes nothing |
| `check_crawl` | one host, GET only, robots obeyed, rate limited | 0.103 s minimum gap, 2 paths refused |
| `check_scale` | linear, deduplicating, bounded memory | 1,200 findings, 321 MB, 11 files/s |
| `lint_policy` | quoted rules still match downloaded eCFR text | 11 verified, 1 not required |
| `check_evasion` | realistic hiding techniques do not defeat it | **13 of 15 caught** |

## Evasion testing

The synthetic world uses honest markup. Nobody hides patient data in honest
markup. `fixtures/build_evasion.py` builds fifteen files, each holding one real
leak hidden the way a person with a browser would hide it.

Caught: HTML comments, SVG titles, JSON `\u` escapes, percent-encoded URLs, CSS
`content` properties, `<style>` blocks, names in filenames, record numbers broken
by spaces, SSNs broken by spaces, base64 encoded twice, names carrying
zero-width characters, HTML entities, names split from their diagnosis by other
text.

Not caught, and named rather than hidden:

| Technique | Why |
|---|---|
| Name split across two elements (`<span>Emeka</span> <span>Delgado</span>`) | the name and the diagnosis land in different text nodes; joining them needs a DOM renderer |
| Name written backwards | reversing text defeats every text pattern |

Both are recorded in `check_evasion.py` with a reason, are reported on every run,
and do not silently pass.

## The bug the evasion corpus found

The zero-width case failed at first, and the cause was not the zero-width
character.

The collector worked in **character** offsets and sliced **bytes**. For any file
containing a non-ASCII character — an accented name, a curly quote, an em dash —
every observation after that point was shifted, and the tail was cut off. The
scan read `invasive ductal carcinom` and matched no diagnosis.

That bug affected every non-ASCII document since the first version. A tidy
fixture made of ASCII could never have found it. Fixing it took one map per
document and moved three evasion cases from fail to pass.

## Field test: a 43-file exam

A blind exam of 43 files in 20 formats, written by someone else.

**First run, unmodified tool:**

| | |
|---|---|
| Files read | **22 of 43** |
| Findings | 14 |
| Plausibly real | ~7 — about 50% precision |
| Run to run | **14, 14, 14, and once 13** |

Twenty-one files were never opened. Thirteen were `.txt`: the collector had no
plain-text branch at all. The exam even included a file named
`D41_YOUNG_M_7730019.txt` — a patient identifier in the filename — and it was
missed twice over.

**Defects that exposed, all now fixed:**

| Defect | Fix |
|---|---|
| No `.txt`, `.md`, `.patch`, `.eml`, `.jsonl` handling | whole-file fallback |
| No HL7 or X12 | segment-per-record for both |
| `.docx` / `.xlsx` read as bytes | unzip and strip the XML |
| `.png` / `.jpg` read as bytes | printable strings from EXIF/PNG chunks — metadata, not pixels |
| Identifiers in filenames | path is a carrier; a 6+ digit run is a record number, rated review |
| "PDF", "Blvd", "MD", "Institute" as people | document-furniture stop list, applied to key-derived names too |
| Same input, different output | PDF metadata sorted before emitting |

**After:** 43 of 43 files read, 27 findings, world fixture still 60/60.

No OCR. Text burned into pixels is still not read, and the report says so.

## What is not covered

- **No DOM rendering.** Split text nodes and reversed text need a browser.
- **No OCR.** Text burned into a DICOM image is not read; the header is.
- **No commercial comparison.** Only Presidio has been benchmarked.
- **One real target.** Production traffic has been seen exactly once, and it was
  synthetic.
- **No soak test beyond 720 files.**

Stating these is part of the deliverable. A scanner that claims complete coverage
is one that has not been tested hard enough to find its own edges.

## The blind exam score, and what it changed

A separately written 43-document exam with 1,135 graded items — 537 patient
identifiers, 547 traps, 51 excluded. Traps mean precision is measurable: NPI
numbers, LOINC codes, eponyms, state abbreviations, bare years, measurements.

| | Before | After |
|---|---|---|
| Recall | **9.5%** | **53.1%** |
| Traps reported | 2 / 547 | 9 / 547 |
| Excluded reported | 1 / 51 | 12 / 51 |
| Findings | 27 | 87 |

**Still failing.** 285 of 537 identifiers found. Of the 252 missed, 146 are
present in text we hold — detectors not written yet — and 112 are transformed:
spelled-out letters, digit substitution, and pixels. Perfect recognition of
everything present would reach 80.3%, so the 90% target is abandoned until OCR
and de-obfuscation exist. See `GATES.md`.

Even the improved number is poor, and it is a **contaminated** measurement: the
fixes were written after reading the key, so it shows direction, not skill.
Four causes, three now fixed:

1. **Structure was flattened to text.** HL7, X12 and DICOM were parsed and the
   labels thrown away, so `NGUYEN^LAN^THI` and `30118442` arrived as anonymous
   strings. `phi_scan/structured.py` now reads these formats as labelled fields —
   the tag number and the field position *are* the evidence.
2. **Identifier shapes came from our own fixture.** We knew `MRN-123456` and
   `1952-01-01`. Real records use bare digits, `02/14/1936`, `March 4, 2026`,
   `19941102`. Added, plus ZIP beside a state code and bare 6-8 digit record
   numbers when a named person is in the same record.
3. **The reporting gate was narrower than the question.** A labelled identifier
   now stands on its own; a diagnosis beside it is no longer required.
4. **Obfuscation.** JWT payloads and URL-encoded values are decoded. Spelled-out
   letters and digit-for-letter substitution are still missed, and pixels still
   need OCR.

The lesson generalises beyond this exam: **where a format carries its own labels,
parse it. Never scan it.**


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

## What is not covered

- **No DOM rendering.** Split text nodes and reversed text need a browser.
- **No OCR.** Text burned into a DICOM image is not read; the header is.
- **No commercial comparison.** Only Presidio has been benchmarked.
- **One real target.** Production traffic has been seen exactly once, and it was
  synthetic.
- **No soak test beyond 720 files.**

Stating these is part of the deliverable. A scanner that claims complete coverage
is one that has not been tested hard enough to find its own edges.

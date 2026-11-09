# Disclosures

Departures from `eval/protocol.md` after the key was frozen. Each one weakens
what the held-out split can claim, so each is recorded here.

## 1. Held-out N8 inspected after G5 run 6 (2026-11-03)

- **What:** G5 run 6 failed the clean-page false-alarm criterion: 18 of 720 hard
  negatives were flagged, every one a held-out item in stratum N8 (consented
  testimonial), all from one layout, `N8.blockquote`. At the owner's decision
  ("Inspect and disclose") I opened that one template to find the cause.
- **What was seen:** the `N8.blockquote` template in `fixtures/build_corpus.py` (a
  quoted testimonial whose author sits in a `<cite>` inside the `<blockquote>`,
  with the consent note beside it) and the 18 flagged items' rows in the G5
  ledger (`eval/results.json`). No other held-out stratum or template was opened.
- **What changed:** `phi_scan/negatives.py` now compares text with all whitespace
  removed (`_squash`), because the renderer joins inline elements without a space
  (`helped."<cite>`) and the consent needle never matched; and a consent note
  counts when the consent phrase starts the note. Two probes copy the layout's
  shape with new text: `CITE_QUOTE` (must stay clean) and `CITE_QUOTE_NO_NOTE`
  (must still be flagged), in `tests/probes_prose.py`.
- **Effect:** held-out `N8.blockquote` flagged went from 18 to 0 of 18. Because the
  fix was made while looking at that template, the N8 held-out result after this
  date is a development result, not a held-out one. The other held-out strata
  (S1 to S6 positives, N1 to N7) remain uninspected.

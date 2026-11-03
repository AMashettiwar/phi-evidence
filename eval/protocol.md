# Evaluation protocol (pre-registered)

Frozen in `eval/frozen.json` (protocol_sha256) before the first scored run. `tools/gate_g5.py`
refuses to score if this file, the corpus key or the world key has changed since the freeze.

## Data

- **Corpus** (`fixtures/build_corpus.py`, key hash frozen): 6 primary strata x 160 positives,
  8 negative strata x 90 (720, 42.9%). Each stratum has a 20% held-out split.
- **World** (`fixtures/build_world.py`, key hash frozen): the servable synthetic clinic, 73
  planted leaks across every carrier, plus clean pages.
- **Disclosure.** The detector was developed with error analysis on the corpus **dev** split. The
  held-out split was never inspected. Full-set numbers are therefore optimistic; held-out recall is
  reported beside them. Benchmark and detector share an author, so independent validation needs the
  blind human review below.

## Arms

| Arm | Definition |
|---|---|
| presidio | Microsoft Presidio 2.2 with `en_core_web_sm`, entity types that are Safe Harbor identifiers, score >= 0.5, run on the same extracted text as the detector |
| rules | `phi_scan.detect`, context public-web |
| rules+llm | rules, then `phi_scan.ai.review_all` with Groq `openai/gpt-oss-120b`, temperature 0, seed 0, k = 1; the model may move a non-always-flag finding to Review (confidence >= 0.8, at most 25% of findings) |

An item is **flagged** when a finding on it is above Review. A positive is **caught** when a flagged
finding names the planted value (token match, label stripped) or covers its byte range.

## Metrics and acceptance (brief section 8)

| Criterion | Threshold | Decided by |
|---|---|---|
| Always-flag recall (SSN / MRN / plan id) | zero misses | corpus items with `always_flag`, and the world's always-flag records |
| Recall per primary stratum | point >= 0.95 and Wilson 95% lower bound >= 0.90 | 160 positives each: at least 152 caught |
| Precision | >= 0.85 overall | item level: caught positives / all flagged items |
| Planted leaks on the synthetic site | 100% | `tools/check_detect.py` |
| False alarms on clean pages | <= 0.5% of clean items | the 720 negatives: at most 3 |
| rules vs rules+llm | exact McNemar p < 0.05, delta reported | item correctness, same frozen set |
| LLM stability | Fleiss kappa >= 0.80 over k = 3 | `tools/gate_g4.py` with the real model |
| Reproducibility | identical canonical JSON across runs | `tools/gate_g2.py`, then a fresh clone (M9) |
| Cost | reported per scan | tokens x listed price, p95 latency (G4) |

**Undecidable is a failure.** If a threshold cannot be decided at the achieved n (for example
McNemar with too few discordant items, or no model key), the gate fails and states the number of
discordant pairs that would decide it.

## Power (printed before the run)

At n = 160 a stratum passes with >= 152 caught. The gate prints the chance of passing at true
recall 0.95, 0.97 and 0.99 before any result is shown.

## Ledger

Every miss and false alarm of every arm, with a reason code: `no_finding` (nothing on the item),
`wrong_value` (findings, none naming the planted value), `filtered_to_review` (found, then moved to
Review), `flagged_<carrier>` (a false alarm and where it came from).

## Blind human adjudication

`eval/review_packet.csv`: a fixed sample of 60 ambiguous items (consented testimonials, staff pages,
articles, identity without health, and positives from the same templates), shuffled with a fixed
seed, with no verdict shown. Two reviewers who have not seen the code fill `reviewer_a` and
`reviewer_b`; `eval/adjudication.py` reports Cohen's kappa and the detector's agreement with each.
**Pending human.**

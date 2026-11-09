# Design notes

Why the code looks the way it does. Each section is a decision that a test
forced, not a preference.

---

## 1. Rules first, code second

The policy was written and quoted before a line of detection code existed. Twelve
rule ids, eighteen identifiers, four severity levels. Eleven of the quotes are
verified character-for-character against eCFR text downloaded into
`policy/source/`, and `tools/lint_policy.py` re-checks them on every run.

The point is that a finding can never invent a law. A rule id that is not in the
list cannot appear in a report.

## 2. The vault

A scanner that stores patient data in its own output has created the problem it
was hired to find.

So bytes go into a content-addressed vault and the index holds only a digest, an
offset, a length and a carrier label. Two identical files cost one vault object,
which is also why the scanner stays linear at scale: 720 files produced 1,200
findings in 321 MB.

## 3. Evidence grade

Not all findings are equally provable:

- **A** confirmed by capture — a server log or a HAR
- **B** present in the source, transmission not observed
- **C** inferred

Static collection can only ever reach B. Saying so is part of the output rather
than a footnote.

## 4. Severity is the worse of two things

A finding is rated by two independent axes and takes the worse:

- **who can see it** — public, or behind the operator's own login prefix
- **what kind of carrier** — a page anyone loads, versus a file nobody links to

The audience is declared by the operator (`--auth-prefix`), never guessed. A
scanner that guesses who is logged in will guess wrong in the direction that
matters.

## 5. The model may only ever annotate

The AI layer can explain a finding and lower its severity by one step. It cannot
create, delete, or promote. Suppression is not an implemented operation, so a
malicious review has nothing to call.

It also never sees a patient value: names and record numbers are redacted to
`[NAME]` before the request, and an encoded payload becomes `[ENCODED_PAYLOAD]`.
That is why the tool can be used without a BAA — there is nothing to disclose.

Hostile pages are treated as data. Twenty pages instructing the scanner to
ignore their own leak are all still reported, and the attack changes nothing.

---

## Things that failed, and what they taught

These are kept because each one was invisible until a test caught it.

**A name with an apostrophe was skipped entirely.** The first pattern silently
excluded every one of them.

**"length wins" was wrong.** On overlapping candidates, the longest span won and
preferred `"Bhatt DEMO_PATIENT_MRN"` over the model's `"Freya Bhatt"`. Containment
beats priority; priority beats length.

**A place label on a surname deleted a whole name.** spaCy labels `Delgado` as a
GPE inside *Emeka Delgado*. A veto now needs 60% coverage.

**The model absorbs closing quotes.** `'Yuki Rahimi'` came back as `"Yuki Rahimi'"`
— corrupted, never matching anything.

**A consuming name pattern ate the next word.** In *"for Emeka Delgado"*, the pair
`("for", "Emeka")` failed the stop list and took `Emeka` with it. The pattern is
now a lookahead.

**Sleeping after a request does not rate-limit.** The delay moved to before every
request; the measured minimum gap went from 0.025 s to 0.103 s.

**A sanitised HAR looks exactly like an unauthenticated session.** A capture with
no cookie and no auth header appeared to be an open door. One query returning no
patient data proved otherwise: `401 No auth token`. Any audit reasoning from HAR
headers alone will raise a false critical.

**Text detection on structured data does not converge.** On a real clinical API
it found 1 of 41 identifiers and invented 887 names — *Delivery Note*,
*Collection*, *Sample*, *Bladder*. Vocabulary fixes each killed one label and
revealed the next. The answer was to stop guessing: in JSON the key says what the
value is. Same tool, 41 of 41, no model.

---

## What the gates are for

| Gate | Proves |
|---|---|
| `check_world.py` | every planted leak is where the answer key says |
| `check_collect.py` | the scanner reaches every carrier, and the index holds no PHI |
| `check_detect.py` | all leaks found, no false alarms, severity agrees |
| `check_ai.py` | the AI layer cannot make the scanner worse |
| `check_crawl.py` | one host, GET only, robots obeyed, rate limit held |
| `check_scale.py` | linear at 20×, vault deduplicates, memory bounded |
| `lint_policy.py` | every quoted rule still matches the source text |

A gate that cannot fail is not a gate. `check_ai.py` runs a control corpus with
the attack sentences stripped and requires the same findings from both.

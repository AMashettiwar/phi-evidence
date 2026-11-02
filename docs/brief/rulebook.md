# phi-scan — The Rulebook

Version 1. Draft for sign-off at gate G0b. This is not code. This is the document the code must obey.

---

## 1. What this tool does

It looks at one website, web app, or platform and answers one question: **is health information about a real person exposed, and how badly?**

It never fixes anything. It never decides a breach happened. Every finding is worded:

> **Possible PHI exposure, needs compliance review.**

## 2. What counts as a finding

A finding needs two things in the same record:

1. something that points to a person (one of HIPAA's 18 identifiers), and
2. something about that person's health, care, or payment.

Two things are findings **on their own**, with no health detail attached:

- **Social Security number, medical record number, or insurance ID.** Always. The AI may never clear these.
- **A street address.** This is your decision, and it is strict on purpose. It is rated **Medium**, not Critical, because there is no health information attached to it.

## 3. What a "record" means

Not a sentence. A sentence is a bad unit of measurement: a table row has no sentence, and a server log line has no full stop.

A record is one of these:

- a table row
- a JSON object
- a web address (URL)
- a log line
- an HL7 message segment group
- an API response object
- a set of form fields
- a list item

Two facts in different records are **not** linked. Two facts in the same record **are**.

## 4. Where the tool looks

Not just what a person sees on screen:

- text on the page
- hidden page code: comments, hidden elements, embedded data
- the web address itself
- the page title
- what the browser stores (cookies, local storage)
- what the site sends to outside companies (ads, analytics)
- data returned by the site's API
- downloadable files, including their hidden metadata
- error messages and logs

## 5. What is NOT a finding

Each of these needs **evidence**, not a hunch:

| Situation | Evidence required before we stay quiet |
|---|---|
| Doctor or staff profile | a staff-page address, or physician markup in the code, or a valid doctor ID that passes its checksum |
| Health article | no patient in a clinical role |
| Group statistics | the number describes a group, not a person |
| Fake or sample data | a reserved test value: invalid SSN range, example.com, 555-01xx phone, test IP range |
| Company contact details | matches the organisation's own contact block |
| Medical code reference | a code with no person attached |
| The test user's own record | matches the record of the account we logged in with |
| Testimonial with permission | a consent marker or a fiction label **visible on the page** |

**The last one is the trap.** A testimonial is not safe because someone called it a testimonial. If there is no visible consent marker, it is a finding. Posting patient testimonials without permission is one of the real leak types we are hunting.

## 6. Extra-sensitive categories

These raise the severity whenever they appear: HIV, mental health, drug or alcohol treatment, reproductive health, genetic results, cancer.

## 7. How serious is it

| Level | When |
|---|---|
| **Critical** | a never-clearable ID visible to anyone; or a person plus health detail visible to anyone; or either one sent to an outside company |
| **High** | another patient's data behind a login; or any identifier in a web address, page title, hidden code, or browser storage |
| **Medium** | an identifier on its own with no health detail. This is where a street address lands. |
| **Review** | a tracker with no patient data; a statistic about a very small group |

**How the two axes combine.** A thing can qualify for two levels at once: a patient's name and diagnosis in a web address is both "visible to anyone" (Critical) and "in a web address" (High). The rule is **take the worse of the two**. So:

- public page + data in a URL → **Critical** (public wins)
- logged-in page + data in a URL → **High** (URL raises it above plain authenticated access)
- the AI never gets to choose the level. It is computed from two facts: who can see it, and where it sits.

Two notes on this table:

- Sending data to an outside company on a **public** page is marked **contested**. A federal court threw out the government's guidance on that in 2024 and the government did not appeal. The report will say "contested risk" rather than claiming a clear rule was broken.
- A statistic about a group is not automatically safe. If the group is very small, the people in it may be identifiable. That becomes a **Review** item.

## 8. Rules the tool must never break

1. No finding without a precise location: a byte offset into stored evidence.
2. The AI may not clear a Social Security number, medical record number, or insurance ID.
3. No rule outside the fixed list in `rules.yaml`.
4. No unmasked value in any default output.
5. Every finding can be replayed from the stored evidence.

## 9. What the tool never says

- It never says "violation".
- It never decides a breach occurred.
- It never gives legal advice.
- It never claims a page is clean.

## 10. Why the severity is a fixed rule and not an AI judgement

An AI changes its mind between runs, and it can be talked out of a finding by text on the page it is reading. So the level is worked out by fixed rules in code from the facts: what was found, where it was found, and who can see it. The AI may write the explanation and may suggest that a borderline case is a doctor rather than a patient. It may not delete a Social Security number.

---

## Sign-off checklist for G0b

- [ ] The two-then-exceptions rule in section 2 matches what you want
- [ ] A street address alone as Medium is the right level
- [ ] The "record" definitions in section 3 cover how your platform stores data
- [ ] The do-not-flag table in section 5 has no gaps you care about
- [ ] The testimonial rule in section 5 is strict enough
- [ ] The severity table in section 7 reads correctly to you

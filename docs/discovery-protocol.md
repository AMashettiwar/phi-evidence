# Discovery protocol (fill in before any scan of a real target)

Derived from `policy/phi-exposure-spec.md` section 2.8. Scanning a live system can be the moment an organisation discovers an exposure, which may start the 60-day breach-notification clock (45 CFR 164.404). The scan also creates a new copy of whatever the target served. This page is a template: replace every `[ ]` blank, have counsel review it, and keep the signed copy with the scope file. This document is not legal advice.

The tool never determines whether a breach occurred. It reports possible PHI exposure that needs compliance review. That determination belongs to the organisation and its counsel.

| | |
|---|---|
| Target | [ ] |
| Scope file and version | [ ] |
| Scan window (dates, times, time zone) | [ ] |
| Operator (name, role) | [ ] |
| Protocol approved by (name, role, date) | [ ] |

## 1. Who is notified, and when

| Event | Who | Deadline | Contact |
|---|---|---|---|
| Before the scan starts | Privacy officer [ ]; security officer [ ]; target system owner [ ] | [ ] before the window | [ ] |
| Critical finding | Privacy officer [ ] | within one business day of the finding (spec default; change only with approval) | [ ] |
| Any authentication or transport finding | Security officer [ ] | [ ] | [ ] |
| Counsel informed | [ ] | [ ] | [ ] |

Discovery date and time of the first Critical finding: [ ]. Recorded by: [ ].

## 2. Breach-notification clock

The 60-day period under 45 CFR 164.404 may start at discovery. Who decides whether the clock has started: [ ] (name, role). Date counsel gave a view: [ ]. The tool takes no position.

## 3. What is sequestered

- The vault for each scan: `OUT/vault/` and its key in `~/.phi-evidence/keys` (or `PHI_EVIDENCE_KEYS`). Stored on: [ ] (encrypted volume). Key held by: [ ].
- The temporary working directory used during a scan: cleared and checked by [ ].
- Reports carry masks and hashes only, but are still sensitive.

## 4. Report classification

Classification label for every report and output folder: [ ]. Masking is not de-identification. Permitted recipients: [ ]. Storage location: [ ]. Sharing by email or chat: [ ] (allowed / not allowed).

## 5. Encryption

Vault bytes: AES-256-GCM, per-scan key, key stored apart from the ciphertext. Additional measures required here: [ ] (disk encryption, key escrow or none). Key backup: [ ] (the tool makes none; losing the key makes the evidence unreadable).

## 6. Access logging

Every vault read is appended to `OUT/vault/access.log` with time, actor, purpose and object. Who reviews the log, and how often: [ ]. Who may read the vault: [ ]. Reason required for each read: yes.

## 7. Retention and destruction

| | |
|---|---|
| Retention period | [ ] days (tool default and hard limit for reads: 30 days) |
| Destruction owner | [ ] |
| Destruction date | [ ] |
| Method | `Vault(...).destroy()`, then confirm the key file is gone and the log shows "destroy" |
| Legal hold check before destruction | [ ] (name, date) |

The tool deletes the key file; it does not overwrite storage. Additional media sanitisation: [ ].

## 8. Counsel access to raw bytes

Raw bytes are released only to counsel, by a logged vault read. Counsel contact: [ ]. Approval needed from: [ ]. Method of release: [ ]. Release recorded in: [ ].

## 9. Sign-off

| Role | Name | Date | Signature |
|---|---|---|---|
| Privacy officer | [ ] | [ ] | [ ] |
| Security officer | [ ] | [ ] | [ ] |
| Counsel | [ ] | [ ] | [ ] |
| Operator | [ ] | [ ] | [ ] |

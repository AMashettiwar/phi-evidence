# Threat model

What could go wrong when this tool scans a system that holds patient data, what the code does about it, and what is left over. "Residual risk" is what the controls do not cover. Every finding the tool produces reads "Possible PHI exposure, needs compliance review."

Status: written 2026-11-02 against the code in this repository. Controls marked "tested" have a gate in `tools/run_gates.py`; others are design only.

## 1. Assets

| Asset | Where | Why it matters |
|---|---|---|
| Vault ciphertext | `<out>/vault/objects/` | Every captured byte, including any real PHI the target served. AES-256-GCM, addressed by HMAC-SHA256. |
| Per-scan key | `~/.phi-evidence/keys/<key_id>.key` (override: `PHI_EVIDENCE_KEYS`) | Decrypts the vault. Stored apart from it. Losing it makes the vault unreadable; leaking it, with the ciphertext, makes it readable. |
| Reports | `findings.json`, `evidence.jsonl`, `capture.json`, rendered report | Masks, offsets, hashes and tokens, not raw values. Still sensitive: they say where PHI is. Masking is not de-identification. |
| Scope file | the file passed to `--scope` | Written authorisation. Also holds test-account session cookies, which are credentials. |
| Groq API key | `GROQ_API_KEY` or git-ignored `.env` | Spend and data-path control. |
| Vault access log | `<out>/vault/access.log` | Evidence of who read what and why. |

## 2. Actors

| Actor | Assumed capability |
|---|---|
| Operator | Runs the scan with good intent; can make mistakes (wrong scope, real target without a protocol). |
| Malicious target page | Controls all text and files the scanner reads. Can try to instruct the scanner or hide data. |
| Compromised or wrong LLM | Returns any JSON it likes, or is steered by page text. |
| Third-party tracker | Receives whatever the page sends it. Must not be probed. |
| Repository reader | Anyone with the git repo or an output folder, but not the key store. |

## 3. Threats

### 3.1 Prompt injection from page content

| | |
|---|---|
| Control | Page text never goes in the instruction channel: the system prompt is fixed and the record goes in the user message as JSON data, labelled untrusted. Before the request, `sanitize()` replaces any sentence matching a list of instruction phrases ("ignore previous instructions", "do not flag", "this is not PHI", and similar) with `[UNTRUSTED-INSTRUCTION-REMOVED]`. Each hit is recorded as its own finding (`injection_attempt`, level review). The model's reply is validated against a schema and applied by ordinary code; there is no operation that adds or deletes a finding. |
| Tested | `tools/check_ai.py`, `tools/gate_g4.py`, fixtures from `fixtures/build_injection.py`. |
| Residual | The phrase list is finite. A paraphrase that matches no pattern reaches the model. The limit is structural, not the filter: the worst a steered model can do is the capped demotion in 3.2. Injection into the explanation text is possible; that text is prose for a reviewer. |

### 3.2 LLM over-suppression

| | |
|---|---|
| Control | The model may only answer "keep" or "lower". Findings are never deleted. A lowering is one step, never below Medium, and never below High if the finding carries an always-flag identifier (SSN, MRN, plan id). A model may propose that a finding is staff, article or synthetic; the engine moves it to Review only when confidence is at least 0.8, no always-flag identifier is present, and at most 25% of the scan's findings are moved (`REVIEW_CAP`). Moved findings stay in the report. With k > 1 runs, a level is lowered only if every run asked for it. A reply that fails the schema, or cites a different finding id, changes nothing. |
| Tested | `tools/check_ai.py` (gate G4 targets 0 always-flag suppressions over 1,000 adversarial attempts). |
| Residual | Up to 25% of non-always-flag findings can be moved to Review by a wrong model. They stay visible but a reviewer may skim the Review queue. Whether the AI may move findings at all is an open owner decision (see `docs/handover.md`). |

### 3.3 PHI in artifacts

| | |
|---|---|
| Control | Findings carry a mask and an offset, not the value. Value identity uses `vault.token()`, an HMAC under the per-scan key, not a plain hash (a plain SHA-256 of an SSN can be brute-forced). The canonical `findings.json` holds no token, vault address or timestamp. Raw bytes live only in the encrypted vault. Screenshots are taken with all text made transparent and images blurred, then vaulted. The HAR goes straight into the vault. |
| Tested | `tools/check_collect.py` and `tools/gate_g2.py` scan artifacts for planted values; `tools/check_emit.py` redacts and rescans. |
| Residual | (a) While a scan runs, served bodies and the HAR sit unencrypted in an operating-system temp directory (`tempfile.TemporaryDirectory`); it is removed after collection, but a crash, power loss or disk snapshot can leave data behind on disk. Use an encrypted disk. (b) Masks show some characters (for example the last four digits). (c) `evidence.jsonl` holds HMAC tokens; with the key they allow confirming a guessed value. (d) The tool detects masks and offsets, not meaning: a report still reveals where PHI is. Treat every report as sensitive. |

### 3.4 Out-of-scope requests

| | |
|---|---|
| Control | One guard covers every request, including the browser's own sub-requests (a Playwright route). A URL is allowed only if its host is in `in_scope.hosts` and its path is not in `out_of_scope.paths`. Otherwise the request is aborted, never sent, and recorded (method, URL, Referer) as a `third_party` observation, so the report shows what would have left. Redirects are not followed by the browser path: each is recorded and queued, so its target is checked and paced like any URL. Stop conditions (429, three server errors in a row, request cap) halt all further requests. robots.txt is read and obeyed for pages. Concurrency 1, minimum gap plus jitter between requests. |
| Tested | `tools/check_collect.py` and `tools/gate_g2.py` (tracker receives 0 requests; minimum server-side gap measured). `tools/check_crawl.py` for the older crawler. |
| Residual | The guard matches on host:port exactly as written in the scope file; a wrong scope file means a wrong boundary. A host listed only under `out_of_scope.hosts` is blocked because it is absent from `in_scope.hosts`. DNS or CDN names that resolve to out-of-scope systems are not checked. Indexability is judged from robots.txt and `X-Robots-Tag` only; the tool does not query any search engine. |

### 3.5 Write actions

| | |
|---|---|
| Control | The tool navigates with GET (`page.goto`) and fetches with GET (`request.get`). It never fills or submits a form, never clicks, uploads, or logs in through a form. Login is a provisioned session cookie from the scope file. The older crawler (`phi_scan/crawl.py`) has no POST path and says GET and HEAD only. |
| Tested | `tools/check_crawl.py` (GET only). |
| Residual | The route also refuses every method other than GET and HEAD, including requests a page's own scripts make, and counts them as `write_requests_blocked` in `capture.json`. What it cannot know is a state-changing GET endpoint (a logout link, for instance): those are only protected if listed in `out_of_scope.paths`. List them. |

### 3.6 Key loss and retention

| | |
|---|---|
| Control | The key is separate from the ciphertext. Every vault read is appended to `access.log` with actor, purpose and object (the first read of each object per purpose is logged). The vault expires 30 days after creation (`TTL_DAYS`); after that, reads raise `VaultExpired`. `destroy()` deletes the objects and the key file and appends a "destroy" entry; the log of what existed stays. |
| Tested | `tests/test_vault.py`. |
| Residual | Key loss means the evidence cannot be replayed or released to counsel. There is no key backup by design. `destroy()` removes the key file with a normal delete; it does not overwrite the bytes, so on some storage the key may be recoverable until reused. Expiry is enforced by the tool's own `get()`; anyone holding the key and the ciphertext can decrypt with other software. The key store has no extra access control beyond the user's file permissions. The 30-day figure is a default in code, not a legal retention period. |

### 3.7 Data sent to Groq

| | |
|---|---|
| Control | The model receives only a redacted span, at most 600 characters: names, record numbers, SSNs, dates, phones, emails, IPs and long base64-like runs replaced by placeholders, plus the carrier, identifier type names and evidence grade. Redaction runs before the request is built. No BAA exists, so the design never sends raw spans. Calls use temperature 0 and a fixed seed; model id and `system_fingerprint` are recorded per call. |
| Tested | `tools/check_ai.py` checks that planted patient values do not appear in request payloads. |
| Residual | Redaction is pattern and name-finder based. Free text it does not recognise (a rare diagnosis, an address, a nickname) is sent unchanged. The benchmark and demonstrations use synthetic data only. Do not enable the LLM stage against a real target until compliance has accepted this residual or a BAA is in place. Groq's seed is best effort, so outputs may vary. |

### 3.8 Other

| Threat | Control | Residual |
|---|---|---|
| Third-party tracker probed | Never requested; only what pages send is observed. | None known in code. |
| Scope file leaked | Contains session cookies. | `.gitignore` does not exclude scope files. Keep real ones outside the repository and use short-lived cookies. |
| Wrong rule cited | Rule ids come from the closed registry `policy/rules.yaml`; `tools/lint_policy.py` checks quotes against stored eCFR text. | Registry content needs legal review. |
| Tool declares a page clean or a breach | The tool never claims a page is clean and never decides whether a breach occurred. | Readers may still infer it; the report wording is the control. |

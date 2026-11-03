"""Score findings on the corpus against its frozen key.

A positive item is caught when a finding on that item names the planted value
(its token is in the finding's value tokens) or covers its exact byte range in
the raw file. A negative item is a false alarm when any finding lands on it.
Every miss and false alarm is returned with a reason code, so the ledger the
brief asks for (section 7) is a by-product of scoring, not a second pass.
"""

from __future__ import annotations

import re
from collections import defaultdict

# A planted value may carry its label ("Member ID: SCU806859494"). The
# identifier is what follows the label; a detector that reports only that has
# found it.
LABEL = re.compile(r"^(?:MRN|MBI|Member ID|Medical Record #|Medical Record Number|MR#)\s*[:#-]?\s*",
                   re.I)


def score(items: list[dict], findings: list[dict], raw_docs: dict[str, str], token) -> dict:
    """items: corpus key items. findings: detector output over the corpus root.
    raw_docs: file -> vault address of the raw file. token: value -> token."""
    by_file: dict[str, list[dict]] = defaultdict(list)
    for finding in findings:
        by_file[finding["path"]].append(finding)

    rows = []
    for item in items:
        hits = by_file.get(item["file"], [])
        if item["expected_flag"]:
            wanted = {token(item["value"]), token(LABEL.sub("", item["value"]))}
            start, end = item["offset"], item["offset"] + item["length"]
            caught = any(
                wanted & set(hit["value_hashes"])
                or (hit["doc"] == raw_docs.get(item["file"])
                    and hit["offset"] < end and start < hit["offset"] + hit["length"])
                for hit in hits)
            reason = None if caught else ("no_finding" if not hits else "wrong_value")
        else:
            caught = bool(hits)
            reason = f"flagged_{hits[0]['carrier']}" if hits else None
        rows.append({"id": item["id"], "stratum": item["stratum"], "split": item["split"],
                     "expected": item["expected_flag"], "flagged": caught, "reason": reason,
                     "carrier": item["carrier"], "obfuscation": item["obfuscation"]})

    true_positive_findings = sum(1 for item in items if item["expected_flag"]
                                 for _ in by_file.get(item["file"], []))
    total_findings = sum(len(v) for v in by_file.values())
    return {"rows": rows, "findings": total_findings,
            "findings_on_positive_items": true_positive_findings}

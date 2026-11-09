"""Build the blind review packet (protocol: "Blind human adjudication").

60 items from the ambiguous end of the corpus: consented testimonials, staff
pages, articles, identity without health, and positives from look-alike
templates. Reviewers see an opaque id and the item's text, never its stratum,
template or expected verdict. The mapping back stays in review_key.json.

Run:  python -m eval.review_packet
"""

from __future__ import annotations

import csv
import html
import json
import random
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PICK = {"N8_consented_testimonial": 10, "N1_provider_staff_page": 8, "N2_public_health_article": 6,
        "N7_identity_without_health": 6, "S1_prose": 20, "S3_web_carriers": 10}
TAG = re.compile(r"<[^>]+>")


def main() -> int:
    items = json.loads((ROOT / "eval" / "keys" / "corpus_key.json").read_text(encoding="utf-8"))["items"]
    rng = random.Random(20261102)
    chosen = []
    for stratum, count in PICK.items():
        pool = [i for i in items if i["stratum"] == stratum and i["format"] in ("html", "txt", "json")]
        chosen += rng.sample(pool, count)
    rng.shuffle(chosen)
    rows, mapping = [], {}
    for number, item in enumerate(chosen, start=1):
        text = (ROOT / "fixtures" / "corpus" / item["file"]).read_text(encoding="utf-8")
        shown = " ".join(html.unescape(TAG.sub(" ", text)).split()) if item["format"] == "html" else text
        review_id = f"R{number:02d}"
        mapping[review_id] = item["id"]
        rows.append({"review_id": review_id, "text": shown[:600],
                     "reviewer_a": "", "reviewer_b": "", "notes": ""})
    with (ROOT / "eval" / "review_packet.csv").open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    (ROOT / "eval" / "review_key.json").write_text(json.dumps(mapping, indent=2) + "\n",
                                                  encoding="utf-8", newline="\n")
    print(f"wrote {len(rows)} items to eval/review_packet.csv; answers in reviewer_a / reviewer_b as "
          "'exposure' or 'not_exposure'")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

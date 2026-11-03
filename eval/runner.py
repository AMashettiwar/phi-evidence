"""Run the pre-registered evaluation (eval/protocol.md) over the frozen corpus.

Three arms on the same collected evidence:
  presidio    Microsoft Presidio, same spaCy model, Safe Harbor entity types
  rules       the deterministic detector
  rules+llm   the detector, then the model's review (k=1 here; agreement over
              k=3 is gate G4's job)

An item counts as flagged when a finding on it is above Review: a Review item
is queued for a person, not reported as an exposure. Nothing written here holds
a planted value: results carry ids, counts and reason codes.
"""

from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path

from .score import score
from .stats import mcnemar_exact, mcnemar_n_needed, min_successes, pass_probability, wilson

ROOT = Path(__file__).resolve().parents[1]
PRESIDIO_TYPES = {"PERSON", "US_SSN", "US_ITIN", "PHONE_NUMBER", "EMAIL_ADDRESS", "DATE_TIME",
                  "LOCATION", "IP_ADDRESS", "URL", "US_DRIVER_LICENSE", "MEDICAL_LICENSE",
                  "US_BANK_NUMBER", "US_PASSPORT", "CREDIT_CARD", "IBAN_CODE"}
ACCEPTANCE = {"recall_point": 0.95, "recall_lower": 0.90, "precision": 0.85,
              "clean_false_alarm_rate": 0.005, "mcnemar_alpha": 0.05}


def power_table(n: int) -> list[dict]:
    needed = min_successes(n, ACCEPTANCE["recall_point"], ACCEPTANCE["recall_lower"])
    return [{"n": n, "needed": needed, "true_rate": rate,
             "pass_probability": round(pass_probability(n, rate, needed), 3) if needed else 0.0}
            for rate in (0.95, 0.97, 0.99)]


def presidio_findings(rows: list[dict], vault, token) -> list[dict]:
    from presidio_analyzer import AnalyzerEngine  # noqa: PLC0415
    from presidio_analyzer.nlp_engine import NlpEngineProvider  # noqa: PLC0415

    engine = NlpEngineProvider(nlp_configuration={"nlp_engine_name": "spacy", "models": [
        {"lang_code": "en", "model_name": "en_core_web_sm"}]}).create_engine()
    analyzer = AnalyzerEngine(nlp_engine=engine, supported_languages=["en"])
    found = []
    for row in rows:
        data = vault.get(row["doc"], purpose="evaluate")[row["offset"]:row["offset"] + row["length"]]
        text = data.decode("utf-8", "replace")
        for hit in analyzer.analyze(text=text[:20000], language="en", score_threshold=0.5):
            if hit.entity_type not in PRESIDIO_TYPES:
                continue
            start = len(text[:hit.start].encode("utf-8"))
            found.append({"path": row["path"], "doc": row["doc"], "offset": row["offset"] + start,
                          "length": len(text[hit.start:hit.end].encode("utf-8")), "level": "high",
                          "carrier": row["carrier"], "value_hashes": [token(text[hit.start:hit.end])]})
    return found


def summarise(rows: list[dict]) -> dict:
    by_stratum: dict[str, list[dict]] = defaultdict(list)
    for row in rows:
        by_stratum[row["stratum"]].append(row)
    strata = {}
    for name, items in sorted(by_stratum.items()):
        if items[0]["expected"]:
            hit = sum(r["flagged"] for r in items)
            low, high = wilson(hit, len(items))
            held = [r for r in items if r["split"] == "heldout"]
            strata[name] = {"positives": len(items), "caught": hit, "recall": hit / len(items),
                            "wilson_low": low, "wilson_high": high,
                            "heldout_recall": sum(r["flagged"] for r in held) / len(held) if held else None}
    positives = [r for r in rows if r["expected"]]
    negatives = [r for r in rows if not r["expected"]]
    true_flags = sum(r["flagged"] for r in positives)
    false_flags = sum(r["flagged"] for r in negatives)
    return {"strata": strata,
            "precision": true_flags / (true_flags + false_flags) if true_flags + false_flags else 0.0,
            "clean_items": len(negatives), "false_alarms": false_flags,
            "clean_false_alarm_rate": false_flags / len(negatives) if negatives else 0.0,
            "false_alarms_by_stratum": {s: sum(r["flagged"] for r in negatives if r["stratum"] == s)
                                        for s in sorted({r["stratum"] for r in negatives})}}


def correct(row: dict) -> bool:
    return row["flagged"] == row["expected"]


def compare(first: list[dict], second: list[dict]) -> dict:
    """McNemar on item correctness: b = only `first` right, c = only `second` right."""
    b = sum(correct(x) and not correct(y) for x, y in zip(first, second))
    c = sum(correct(y) and not correct(x) for x, y in zip(first, second))
    p = mcnemar_exact(b, c)
    return {"only_first_right": b, "only_second_right": c, "p": p,
            "delta_correct": c - b,
            "pairs_needed_to_decide": mcnemar_n_needed(b or 0.5, c or 0.5) if p >= 0.05 else None}


def evaluate(corpus: Path, key_items: list[dict], out: Path, provider=None) -> dict:
    from phi_scan.ai import review_all  # noqa: PLC0415
    from phi_scan.collect import collect  # noqa: PLC0415
    from phi_scan.detect import detect  # noqa: PLC0415
    from phi_scan.vault import Vault  # noqa: PLC0415

    collect(corpus, out)
    vault = Vault(out / "vault", actor="evaluation")
    raw = {i["file"]: vault.address((corpus / i["file"]).read_bytes()) for i in key_items}
    reported = lambda fs: [f for f in fs if f["level"] != "review"]  # noqa: E731

    rules = detect(out / "index.jsonl", out / "vault", (), context="public-web")
    arms = {"rules": score(key_items, reported(rules), raw, vault.token)["rows"]}
    if provider is not None:
        reviewed, _ = review_all(rules, vault, provider)
        arms["rules+llm"] = score(key_items, reported(reviewed), raw, vault.token)["rows"]
    index_rows = [json.loads(line) for line in (out / "index.jsonl").read_text(encoding="utf-8").splitlines()]
    arms["presidio"] = score(key_items, presidio_findings(index_rows, vault, vault.token),
                             raw, vault.token)["rows"]

    results = {"acceptance": ACCEPTANCE,
               "power": power_table(min(s["positives"] for s in summarise(arms["rules"])["strata"].values())),
               "arms": {name: summarise(rows) for name, rows in arms.items()},
               "comparisons": {"rules_vs_presidio": compare(arms["presidio"], arms["rules"])}}
    if "rules+llm" in arms:
        results["comparisons"]["rules_vs_rules+llm"] = compare(arms["rules"], arms["rules+llm"])
    ledger = []
    for arm, rows in arms.items():
        for row in rows:
            if not correct(row):
                ledger.append({"arm": arm, "id": row["id"], "stratum": row["stratum"],
                               "split": row["split"], "carrier": row["carrier"],
                               "obfuscation": row["obfuscation"],
                               "kind": "miss" if row["expected"] else "false_alarm",
                               "reason": row["reason"] or ("filtered_to_review" if row["expected"] else "")})
    results["ledger"] = ledger
    return results

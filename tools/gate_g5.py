#!/usr/bin/env python3
"""Gate G5: the brief's acceptance table, decided on the frozen corpus.

Refuses to score unless the protocol and both answer keys match the freeze.
Prints the power analysis before any result. Writes eval/results.json (ids,
counts and reason codes only) and eval/report.md. Any criterion that fails,
or cannot be decided at the achieved n, fails the gate loudly.

Run:  python tools/gate_g5.py
"""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from eval.runner import ACCEPTANCE, evaluate, power_table  # noqa: E402
from phi_scan.ai import GroqProvider, groq_key  # noqa: E402

CORPUS = ROOT / "fixtures" / "corpus"
KEYS = ROOT / "eval" / "keys"


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> int:
    frozen = json.loads((ROOT / "eval" / "frozen.json").read_text(encoding="utf-8"))
    for name, path in (("protocol", ROOT / "eval" / "protocol.md"),
                       ("corpus_key", KEYS / "corpus_key.json"), ("world_key", KEYS / "world_key.json")):
        if frozen.get(f"{name}_sha256") != sha256(path):
            print(f"FAIL  {name} does not match eval/frozen.json; refusing to score")
            return 1
    items = json.loads((KEYS / "corpus_key.json").read_text(encoding="utf-8"))["items"]

    print("POWER (before the run)")
    for row in power_table(160):
        print(f"  n={row['n']} needs {row['needed']} caught; P(pass | true recall {row['true_rate']}) "
              f"= {row['pass_probability']}")

    key = groq_key(ROOT)
    provider = GroqProvider(key) if key else None
    results = evaluate(CORPUS, items, ROOT / "artifacts" / "g5", provider)
    rules = results["arms"]["rules"]

    rows: list[tuple[str, str, bool | None]] = []
    always = [i for i in items if i.get("always_flag")]
    always_missed = {e["id"] for e in results["ledger"]
                     if e["arm"] == "rules" and e["kind"] == "miss"} & {i["id"] for i in always}
    world = subprocess.run([sys.executable, str(ROOT / "tools" / "check_detect.py")], cwd=ROOT,
                           capture_output=True, text=True, encoding="utf-8", errors="replace")
    world_ok = world.returncode == 0
    rows.append(("Always-flag recall", f"{len(always) - len(always_missed)}/{len(always)} corpus, "
                 f"world {'clean' if world_ok else 'MISSES'}", not always_missed and world_ok))
    for stratum, s in rules["strata"].items():
        ok = s["recall"] >= ACCEPTANCE["recall_point"] and s["wilson_low"] >= ACCEPTANCE["recall_lower"]
        rows.append((f"Recall {stratum}", f"{s['caught']}/{s['positives']} = {s['recall']:.3f}, "
                     f"Wilson low {s['wilson_low']:.3f}, held-out {s['heldout_recall']:.3f}", ok))
    rows.append(("Precision", f"{rules['precision']:.3f}", rules["precision"] >= ACCEPTANCE["precision"]))
    rows.append(("Planted leaks, synthetic site", "check_detect " + ("PASS" if world_ok else "FAIL"),
                 world_ok))
    rows.append(("False alarms on clean pages",
                 f"{rules['false_alarms']}/{rules['clean_items']} = {rules['clean_false_alarm_rate']:.2%} "
                 f"{rules['false_alarms_by_stratum']}",
                 rules["clean_false_alarm_rate"] <= ACCEPTANCE["clean_false_alarm_rate"]))
    llm = results["comparisons"].get("rules_vs_rules+llm")
    if llm is None:
        rows.append(("rules vs rules+llm", "UNDECIDED: no GROQ_API_KEY, the LLM arm did not run", None))
    else:
        decided = llm["p"] < ACCEPTANCE["mcnemar_alpha"]
        rows.append(("rules vs rules+llm", f"b={llm['only_first_right']} c={llm['only_second_right']} "
                     f"p={llm['p']:.4f} delta={llm['delta_correct']}"
                     + ("" if decided else f"; UNDECIDED, needs ~{llm['pairs_needed_to_decide']} "
                                           "discordant items"), decided and llm["delta_correct"] > 0))
    g4_path = ROOT / "artifacts" / "g4_gate" / "g4.json"
    g4 = json.loads(g4_path.read_text(encoding="utf-8")) if g4_path.exists() else {}
    real = g4.get("provider") == "groq"
    rows.append(("LLM stability (Fleiss kappa, k=3)",
                 f"{g4.get('kappa', 'not run')} ({g4.get('provider', 'no run')})",
                 (g4.get("kappa", 0) >= 0.80) if real else None))
    g2 = [ROOT / "artifacts" / "g2" / f"run{n}" / "findings.json" for n in (1, 2)]
    same = all(p.exists() for p in g2) and g2[0].read_bytes() == g2[1].read_bytes()
    rows.append(("Reproducibility", "G2 canonical findings identical" if same else "G2 not run",
                 same or None))
    rows.append(("Cost per scan", json.dumps(g4.get("cost", {})), True if real else None))
    presidio = results["comparisons"]["rules_vs_presidio"]
    print("\nBASELINE  rules vs presidio: "
          f"presidio-only right {presidio['only_first_right']}, rules-only right "
          f"{presidio['only_second_right']}, p={presidio['p']:.2e}")
    for arm, summary in results["arms"].items():
        recalls = " ".join(f"{k.split('_')[0]}={v['recall']:.2f}" for k, v in summary["strata"].items())
        print(f"  {arm:10} {recalls}  precision={summary['precision']:.3f} "
              f"false alarms={summary['false_alarms']}/{summary['clean_items']}")

    print("\nACCEPTANCE")
    for name, value, ok in rows:
        print(f"  {'PASS' if ok else 'UNDECIDED' if ok is None else 'FAIL':9} {name:34} {value}")
    (ROOT / "eval" / "results.json").write_text(
        json.dumps({"acceptance": [{"criterion": n, "value": v, "pass": ok} for n, v, ok in rows],
                    **results}, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
    failed = [n for n, _, ok in rows if ok is not True]
    if failed:
        print(f"\nFAIL  {len(failed)} criteria not met or not decidable: {failed}")
        return 1
    print("\nPASS  every acceptance criterion met")
    return 0


if __name__ == "__main__":
    sys.exit(main())

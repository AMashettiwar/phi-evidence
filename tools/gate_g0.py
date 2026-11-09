#!/usr/bin/env python3
"""Gate G0: is the policy complete before any code depends on it?

Checks the closed rule registry against the brief's citation list, the 18
identifiers, the 8 negative predicates, the spec's sections, and that each
invariant names a gate that actually runs. Quotes are checked separately by
tools/lint_policy.py. Owner sign-off is reported, never assumed.

Run:  python tools/gate_g0.py
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
POLICY = ROOT / "policy"
sys.path.insert(0, str(ROOT / "tools"))

from run_gates import GATES  # noqa: E402

# The brief's eleven citations (PROMPT-v2 2.7); 164.514(b)(2)(i)/(ii) is two ids.
BRIEF_CITATIONS = {
    "45 CFR 160.103",
    "45 CFR 164.514(b)(1)",
    "45 CFR 164.514(b)(2)(i)",
    "45 CFR 164.514(b)(2)(ii)",
    "45 CFR 164.502(a)",
    "45 CFR 164.502(a)(5)(iii)",
    "45 CFR 164.312(e)(1)",
    "45 CFR 164.312(a),(b)",
    "45 CFR 164.308(a)(1)(ii)(D)",
    "45 CFR 164.528",
    "42 CFR Part 2",
    "Genetic Information Nondiscrimination Act of 2008",
}
ALWAYS_FLAG = {"ssn", "mrn", "plan_id"}
SPEC_SECTIONS = [f"## 2.{n} " for n in range(1, 10)]


def load(name: str) -> dict:
    return yaml.safe_load((POLICY / name).read_text(encoding="utf-8"))


def main() -> int:
    problems: list[str] = []

    rules = load("rules.yaml")["rules"]
    ids = [rule["id"] for rule in rules]
    citations = {rule["citation"] for rule in rules}
    if len(ids) != len(set(ids)):
        problems.append("duplicate rule ids")
    if citations != BRIEF_CITATIONS:
        problems.append(f"registry != brief: missing {sorted(BRIEF_CITATIONS - citations)}, "
                        f"extra {sorted(citations - BRIEF_CITATIONS)}")
    contested = [rule for rule in rules if rule.get("contested")]
    if not all("Becerra" in rule.get("contested_note", "") for rule in contested):
        problems.append("a contested rule does not cite AHA v. Becerra")
    print(f"rule registry        {len(citations & BRIEF_CITATIONS)}/{len(BRIEF_CITATIONS)} brief citations, "
          f"{len(contested)} contested")

    identifiers = load("identifiers.yaml")["identifiers"]
    letters = "".join(sorted(item["letter"] for item in identifiers))
    incomplete = [item["key"] for item in identifiers
                  if not item.get("must_pass_check") or not item.get("mask")
                  or not isinstance(item.get("always_flag"), bool)]
    always = {item["key"] for item in identifiers if item["always_flag"]}
    if letters != "ABCDEFGHIJKLMNOPQR":
        problems.append(f"identifier letters are {letters}, not A-R")
    if incomplete:
        problems.append(f"identifiers missing check, mask or always_flag: {incomplete}")
    if always != ALWAYS_FLAG:
        problems.append(f"always-flag set is {sorted(always)}, spec says {sorted(ALWAYS_FLAG)}")
    print(f"identifiers          {len(identifiers) - len(incomplete)}/18 complete, "
          f"always-flag {sorted(always)}")

    negatives = load("negatives.yaml")["predicates"]
    declared = [p for p in negatives
                if p.get("evidence") and p.get("implemented_by") and p.get("fixtures")]
    if len(negatives) != 8 or len(declared) != 8:
        problems.append(f"negative predicates declared {len(declared)}/8")
    print(f"negative predicates  {len(declared)}/8 with evidence, function and fixture")

    spec = (POLICY / "phi-exposure-spec.md").read_text(encoding="utf-8")
    absent = [s.strip() for s in SPEC_SECTIONS if s not in spec]
    if absent:
        problems.append(f"spec sections missing: {absent}")
    print(f"spec sections        {len(SPEC_SECTIONS) - len(absent)}/9")

    table = spec.split("## 2.9", 1)[-1]
    invariants = re.findall(r"^\| (\d) \| .+? \| `(tools/[\w./]+)` \|$", table, re.M)
    gated = {gate[0] for gate in GATES}
    unrun = [script for _, script in invariants if script not in gated]
    if len(invariants) != 5 or unrun:
        problems.append(f"invariants mapped {len(invariants)}/5, not run by run_gates: {unrun}")
    print(f"invariants           {len(invariants) - len(unrun)}/5 mapped to a running gate")

    signoff = POLICY / "SIGNOFF.md"
    print(f"owner sign-off       {'recorded' if signoff.exists() else 'PENDING HUMAN'}")

    if problems:
        print(f"FAIL  {len(problems)} problem(s)")
        for problem in problems:
            print(f"  - {problem}")
        return 1
    print("PASS  policy complete (quotes checked by lint_policy.py)")
    return 0


if __name__ == "__main__":
    sys.exit(main())

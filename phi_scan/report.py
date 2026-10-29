"""Turn findings into something a person can read.

A finding is a dictionary: a path, a carrier, a level, a mask, a byte offset and
the rule ids it relates to. This renders that as a table somebody can act on,
and never prints a patient value — only the mask that detect() produced.
"""

from __future__ import annotations

ORDER = ("critical", "high", "medium", "review")

WHAT_IT_MEANS = {
    "critical": "anyone could see this",
    "high": "reachable without being on the page",
    "medium": "visible in a less obvious place",
    "review": "looks like data; needs a human decision",
}


def tally(findings: list[dict]) -> dict[str, int]:
    counts = {level: 0 for level in ORDER}
    for finding in findings:
        counts[finding["level"]] = counts.get(finding["level"], 0) + 1
    return {level: counts[level] for level in ORDER if counts[level]}


def render(findings: list[dict], target: str, limit: int | None = 20) -> str:
    lines: list[str] = []
    counts = tally(findings)

    lines.append("")
    lines.append("phi-scan  -  possible PHI exposure, needs compliance review")
    lines.append("=" * 78)
    lines.append(f"target      {target}")
    lines.append(f"findings    {len(findings)}")
    if counts:
        lines.append("levels      " + "   ".join(f"{k} {v}" for k, v in counts.items()))
    lines.append("")

    if not findings:
        lines.append("Nothing found. That is not proof of safety: a scan only sees")
        lines.append("what it can reach. See the limits in README.md.")
        return "\n".join(lines)

    shown = 0
    for level in ORDER:
        group = [f for f in findings if f["level"] == level]
        if not group:
            continue
        if limit is not None and shown >= limit:
            break
        lines.append(f"{level.upper()}  -  {WHAT_IT_MEANS.get(level, '')}")
        lines.append("-" * 78)
        for finding in group:
            if limit is not None and shown >= limit:
                break
            shown += 1
            identifiers = ",".join(finding.get("identifiers") or [])
            rules = ",".join(finding.get("rules") or [])
            lines.append(
                f"  {finding['path']:<38} {finding['carrier']:<16} {finding['value_mask']}")
            lines.append(
                f"  {'':38} id:{identifiers}  grade:{finding.get('evidence_grade', '?')}"
                f"  bytes:{finding['offset']}+{finding['length']}  rules:{rules}")
        lines.append("")

    if limit is not None and len(findings) > limit:
        lines.append(f"... and {len(findings) - limit} more. Use --limit 0 to see all.")
        lines.append("")

    lines.append("Every finding names the exact byte range, so it can be checked.")
    lines.append("A finding is not a legal conclusion.")
    return "\n".join(lines)


def render_markdown(findings: list[dict], target: str) -> str:
    counts = tally(findings)
    lines = ["# phi-scan report", "", f"**Target:** `{target}`", "",
             f"**Findings:** {len(findings)}"]
    if counts:
        lines.append("")
        lines.append("| Level | Count | Meaning |")
        lines.append("|---|---|---|")
        for level, count in counts.items():
            lines.append(f"| {level} | {count} | {WHAT_IT_MEANS.get(level, '')} |")

    lines += ["", "| Level | Path | Carrier | Mask | Identifiers | Bytes |", "|---|---|---|---|---|---|"]
    for finding in findings:
        lines.append(
            f"| {finding['level']} | `{finding['path']}` | {finding['carrier']} | "
            f"`{finding['value_mask']}` | {', '.join(finding.get('identifiers') or [])} | "
            f"{finding['offset']}+{finding['length']} |")
    lines.append("")
    lines.append("Values are masked. A finding is not a legal conclusion.")
    return "\n".join(lines)

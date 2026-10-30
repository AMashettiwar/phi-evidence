"""Upload an exam zip, get the results. No tuning, no contamination.

The scanner runs on what you upload. Nothing is written outside a temporary
directory that is deleted when the run finishes, and every value shown is masked.
Optionally upload the answer key and it scores itself.
"""

from __future__ import annotations

import json
import tempfile
import zipfile
from collections import Counter
from pathlib import Path

import streamlit as st

from exam_core import extract, score
from phi_scan.collect import collect
from phi_scan.detect import detect

st.set_page_config(page_title="phi-scan exam runner", page_icon="🩺", layout="wide")

st.title("phi-scan — exam runner")
st.caption(
    "Upload a zip of documents. The scanner reads them, reports what it finds with "
    "every value masked, and — if you include the answer key — scores itself. "
    "Nothing is written outside a temporary folder that is deleted at the end of the run."
)

left, right = st.columns([3, 2])
with left:
    exam_zip = st.file_uploader("Exam zip", type=["zip"])
with right:
    key_file = st.file_uploader("Answer key (optional, .json)", type=["json"])

profile = st.radio(
    "Profile", ["extended", "safe_harbor"], horizontal=True,
    help="extended reports an identifier even with no diagnosis beside it; "
         "safe_harbor requires health context, matching the narrower HIPAA reading.",
)

if st.button("Scan", type="primary", disabled=exam_zip is None):
    with st.spinner("reading documents and deciding findings ..."):
        with tempfile.TemporaryDirectory(prefix="phi-exam-") as tmp:
            root = Path(tmp)
            source = root / "src"
            source.mkdir()
            with zipfile.ZipFile(exam_zip) as archive:
                files = extract(archive, source)

            out = root / "out"
            manifest = collect(source, out)
            findings = detect(out / "index.jsonl", out / "vault",
                              extended=(profile == "extended"))
            key = json.loads(key_file.read().decode("utf-8")) if key_file else None

        result = score(key, findings) if key else None

    levels = Counter(f["level"] for f in findings)
    carriers = Counter(f["carrier"] for f in findings)
    a, b, c, d = st.columns(4)
    a.metric("findings", len(findings))
    b.metric("files uploaded", files)
    c.metric("evidence spans", manifest["observations"])
    d.metric("carriers", len(carriers))

    if levels:
        st.write("**by level** — " + "   ".join(f"{k} {v}" for k, v in levels.most_common()))

    st.subheader("Findings")
    st.caption("Values are masked to the last four characters. A finding is not a legal conclusion.")
    st.dataframe(
        [{"level": f["level"], "path": f["path"], "carrier": f["carrier"],
          "masked value": f["value_mask"], "identifiers": ",".join(f["identifiers"]),
          "grade": f["evidence_grade"], "bytes": f"{f['offset']}+{f['length']}",
          "rules": ",".join(f["rules"])} for f in findings],
        use_container_width=True, height=420,
    )

    csv_lines = ["level,path,carrier,masked,identifiers,grade,offset,length,rules"]
    for f in findings:
        csv_lines.append(",".join([
            f["level"], json.dumps(f["path"]), f["carrier"],
            json.dumps(f["value_mask"]), json.dumps(",".join(f["identifiers"])),
            f["evidence_grade"], str(f["offset"]), str(f["length"]),
            json.dumps(",".join(f["rules"])),
        ]))
    st.download_button("Download findings (CSV)", "\n".join(csv_lines),
                       file_name="findings.csv", mime="text/csv")

    if result is not None:
        st.subheader("Score")
        a, b, c, d = st.columns(4)
        a.metric("recall", f"{result['recall']:.1%}",
                 f"{result['matched']}/{result['total']}")
        b.metric("precision", f"{result['precision']:.1%}")
        c.metric("traps reported", result["traps"])
        d.metric("excluded reported", result["excluded"])
        if result["by_cat"]:
            st.write("**missed, by category**")
            st.dataframe([{"category": k, "missed": v}
                          for k, v in result["by_cat"].most_common(20)],
                         use_container_width=True, height=260)
        st.download_button(
            "Download per-item result (CSV)",
            "doc,category,tier,kind,found\n" + "\n".join(
                f"{r['doc']},{json.dumps(str(r['category']))},{r['tier']},"
                f"{r['kind']},{r['found']}" for r in result["rows"]),
            file_name="per_item.csv", mime="text/csv")

st.divider()
st.caption(
    "Read-only. The scan writes nothing outside a temporary folder, keeps no patient value in "
    "its findings, and deletes the working copies when the run ends."
)

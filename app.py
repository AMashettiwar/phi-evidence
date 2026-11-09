"""Upload documents, get findings. No scoring, no key upload, no tuning.

The scanner runs on what you upload. Nothing is written outside a temporary
directory that is deleted when the run finishes, and every value shown is masked.

This app deliberately has no answer-key input. Scoring happens outside it, so
that nobody can tune the detector against a scored result.
"""

from __future__ import annotations

import json
import tempfile
import zipfile
from collections import Counter
from pathlib import Path

import streamlit as st

from exam_io import extract
from phi_scan.collect import collect
from phi_scan.detect import detect

st.set_page_config(page_title="phi-scan", page_icon="🩺", layout="wide")

st.title("phi-scan")
st.caption(
    "Upload a zip of documents. The scanner reads them and reports what it finds, "
    "with every value masked. Nothing is written outside a temporary folder that is "
    "deleted when the run ends."
)

left, right = st.columns([3, 2])
with left:
    exam_zip = st.file_uploader("Documents (.zip)", type=["zip"])
with right:
    context = st.radio(
        "Context", ["covered-entity", "public-web"], horizontal=True,
        help="covered-entity: an identifier is reportable on its own. "
             "public-web: identity plus a health fact.",
    )

if st.button("Scan", type="primary", disabled=exam_zip is None):
    with tempfile.TemporaryDirectory(prefix="phi-scan-") as tmp:
        root = Path(tmp)
        source = root / "src"
        source.mkdir()
        with zipfile.ZipFile(exam_zip) as archive:
            files = extract(archive, source)

        out = root / "out"
        manifest = collect(source, out)
        findings = detect(out / "index.jsonl", out / "vault",
                          context=context)

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

st.divider()
st.caption(
    "Read-only. The scan writes nothing outside a temporary folder, keeps no patient value in "
    "its findings, and deletes the working copies when the run ends."
)

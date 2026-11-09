#!/usr/bin/env python3
"""Build an evasion corpus: the same leaks, hidden the way a person would hide them.

The synthetic world uses honest markup. Real leaks are not honest. Each file here
contains one genuine patient record — identity plus a health fact, or a record
number on its own — obfuscated by a technique that anyone with a browser could
apply in a minute.

The answer key records what was hidden and how, so a failure names its technique
instead of just saying "missed".

Run:  python fixtures/build_evasion.py
"""

from __future__ import annotations

import base64
import html
import json
from pathlib import Path

OUT = Path(__file__).resolve().parent / "evasion"

PATIENTS = [
    ("Emeka Delgado", "MRN-881001", "invasive ductal carcinoma"),
    ("Marisol Lindqvist", "MRN-881002", "type 2 diabetes mellitus"),
    ("Yuki Rahimi", "MRN-881003", "relapsing-remitting multiple sclerosis"),
    ("Beatrix Yamamoto", "MRN-881004", "stage IIIA ovarian carcinoma"),
    ("Ingrid Vasquez", "MRN-881005", "hepatitis C with cirrhosis"),
    ("Tobias Feng", "MRN-881006", "bipolar disorder"),
    ("Priya Raghunathan", "MRN-881007", "chronic kidney disease"),
    ("Hassan Al-Rashid", "MRN-881008", "HIV positive"),
    ("Clara Watanabe", "MRN-881009", "major depressive disorder"),
    ("Rafael Ibarra", "MRN-881010", "schizophrenia"),
    ("Noor Haddad", "MRN-881011", "breast carcinoma"),
    ("Sofia Marchetti", "MRN-881012", "substance use disorder"),
    ("Omar Yamamoto", "MRN-881013", "sickle cell disease"),
    ("Freya Bhatt", "MRN-881014", "genetic variant BRCA1 pathogenic"),
]

key: list[dict] = []


def write(relative: str, content: str | bytes) -> None:
    path = OUT / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(content, bytes):
        path.write_bytes(content)
    else:
        path.write_text(content, encoding="utf-8")


def claim(relative: str, technique: str, value: str, note: str = "") -> None:
    key.append({"file": relative, "technique": technique, "value": value, "note": note})


def page(title: str, body: str) -> str:
    return (f"<!doctype html><html><head><title>{title}</title></head>"
            f"<body>{body}</body></html>")


def main() -> int:
    if OUT.exists():
        import shutil
        shutil.rmtree(OUT)
    OUT.mkdir(parents=True)

    n, mrn, dx = PATIENTS[0]
    # 1. zero-width characters inside the name
    write("01_zero_width.html", page("Record", f"<p>{n[:5]}\u200b {n[5:]} was treated for {dx}.</p>"))
    claim("01_zero_width.html", "zero-width space in the name", n)

    # 2. HTML entities
    n1, mrn1, dx1 = PATIENTS[1]
    write("02_entities.html", page("Record", f"<p>{html.escape(n1)} &mdash; {dx1}</p>"))
    claim("02_entities.html", "named HTML entity between name and diagnosis", n1)

    # 3. inside an HTML comment
    n2, _, dx2 = PATIENTS[2]
    write("03_comment.html", page("Report", f"<!-- {n2}: {dx2} --><p>Nothing to see.</p>"))
    claim("03_comment.html", "leak inside an HTML comment", n2)

    # 4. SVG title
    n3, _, dx3 = PATIENTS[3]
    write("04_svg.html", page("Chart", f"<svg><title>{n3} - {dx3}</title><rect/></svg>"))
    claim("04_svg.html", "leak inside an SVG title element", n3)

    # 5. name split across elements
    n4, _, dx4 = PATIENTS[4]
    first, last = n4.split()
    write("05_split_tags.html", page("Record",
          f"<p><span>{first}</span> <span>{last}</span> &mdash; {dx4}</p>"))
    claim("05_split_tags.html", "name split across two elements", n4)

    # 6. URL-encoded in a link
    n5, _, dx5 = PATIENTS[5]
    encoded = f"{n5.replace(' ', '%20')}"
    write("06_url_encoded.html", page("Referrals",
          f'<a href="/portal?name={encoded}&amp;dx=type%202%20diabetes">open</a>'))
    claim("06_url_encoded.html", "percent-encoded name in a link", n5)

    # 7. JSON unicode escapes
    n6, mrn6, dx6 = PATIENTS[6]
    escaped = "".join(f"\\u{ord(ch):04x}" if ch.isalpha() else ch for ch in n6)
    write("07_json_escape.json", json.dumps({}) .replace("{}",
          '{ "patient": {"name": "' + escaped + '", "mrn": "' + mrn6 +
          '", "dx": "' + dx6 + '"}}'))
    claim("07_json_escape.json", "name written as JSON \\u escapes", n6,
          "the raw file holds no readable name")

    # 8. SSN with spaces instead of hyphens. A real SSN area cannot start with
    # 9, and the first version of this fixture used a number the scanner is
    # right to reject — the test was wrong, not the tool.
    write("08_ssn_spaces.html", page("Form", "<p>SSN 456 78 9012 on file.</p>"))
    claim("08_ssn_spaces.html", "SSN separated by spaces", "456 78 9012")

    # 9. record number with spaces
    write("09_mrn_spaces.html", page("Labs", "<p>Accession MRN 881 011 result ready.</p>"))
    claim("09_mrn_spaces.html", "record number split by spaces", "MRN 881 011")

    # 10. double base64
    n9, _, dx9 = PATIENTS[8]
    inner = base64.b64encode(f"{n9}|{dx9}".encode()).decode()
    outer = base64.b64encode(inner.encode()).decode()
    write("10_double_b64.html", page("Debug", f'<div data-blob="{outer}"></div>'))
    claim("10_double_b64.html", "payload encoded twice", n9)

    # 11. PHI in the file path itself
    n10, mrn10, dx10 = PATIENTS[9]
    slug = n10.replace(" ", "-")
    write(f"11_path/{slug}_{mrn10}.html", page("Record", f"<p>{dx10}</p>"))
    claim(f"11_path/{slug}_{mrn10}.html", "identifiers in the filename, not the body",
          n10, "path carries name and record number; body carries the diagnosis")

    # 12. CSS generated content
    n11, _, dx11 = PATIENTS[10]
    write("12_css_content.html",
          f"<html><head><style>.patient::before{{content:'{n11} - {dx11}';}}</style>"
          f"</head><body><p class='patient'></p></body></html>")
    claim("12_css_content.html", "leak in a CSS content property", n11)

    # 13. split across a CSV row, far apart
    n12, mrn12, dx12 = PATIENTS[11]
    write("13_spread.csv",
          "id,note,lab,value,flag,reviewer,dx,comment\n"
          f"1,{n12},CBC,4.1,H,R Chen,{dx12},follow up\n")
    claim("13_spread.csv", "name and diagnosis far apart in one CSV row", n12)

    # 14. name in an attribute value, diagnosis in the text
    n13, _, dx13 = PATIENTS[12]
    write("14_attribute.html", page("Detail",
          f'<div data-patient="{n13}" aria-label="record"><p>{dx13}</p></div>'))
    claim("14_attribute.html", "name in an attribute, diagnosis in the text", n13)

    # 15. reversed characters are not obfuscation we claim to solve
    n14, _, _ = PATIENTS[13]
    write("15_reversed.html", page("Record", f"<p>{n14[::-1]} reviewed.</p>"))
    claim("15_reversed.html", "name written backwards", n14,
          "expected to fail; recorded to show the boundary")

    write("key.json", json.dumps(key, indent=2) + "\n")
    print(f"evasion files  {len(key)}")
    print(f"techniques     {len({entry['technique'] for entry in key})}")
    print(f"written to     {OUT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

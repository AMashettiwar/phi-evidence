"""Deployable End-to-End PHI Compliance Bot & Web Service (FastAPI).

Exposes:
  GET  /                               Interactive Compliance Dashboard
  GET  /api/health                     Bot status, OCR readiness, policy counts
  GET  /api/policy                     18 Safe Harbor identifiers + 12 eCFR rules
  POST /api/scan/demo                  Scan multimodal, world, or realsite benchmark
  POST /api/scan/inline                Scan raw text / HTML / JSON / FHIR / HL7 / X12
  POST /api/scan/upload                Scan uploaded PDFs, Office docs, images, DICOM, archives
  POST /api/scan/live                  Crawl & scan a live website or local synthetic clinic
  GET  /api/scans/{scan_id}            Fetch scan summary and masked findings
  POST /api/scans/{scan_id}/replay     Re-verify every finding's HMAC span in the AES-GCM vault
  GET  /api/scans/{scan_id}/export/{k} Download findings.json, findings.sarif, evidence.jsonl,
                                       report.html, or redacted.zip
"""

from __future__ import annotations

from email.message import EmailMessage
import hashlib
from http.server import ThreadingHTTPServer
import io
import json
from pathlib import Path
import re
import secrets
import shutil
import subprocess
import sys
import tempfile
import threading
import zipfile

from fastapi import FastAPI, File, Form, HTTPException, UploadFile
from fastapi.responses import HTMLResponse, JSONResponse, Response
from pydantic import BaseModel
import yaml

from . import __version__
from .ai import GroqProvider, StubProvider, groq_key, review_all
from .collect import collect
from .crawl import crawl
from .dashboard_ui import DASHBOARD_HTML
from .detect import detect
from .evidence import replay
from .pipeline import ROOT, finish, mask_path
from .positions import write_redacted
from .vault import Vault

app = FastAPI(
    title="phi-scan Autonomous HIPAA / PHI Exposure Bot",
    version=__version__,
    description="Read-only multi-modal PHI exposure scanner with AES-256-GCM evidence vault.",
)

SCAN_STORE = Path(tempfile.gettempdir()) / "phi-scan-bot-runs"
SCAN_STORE.mkdir(parents=True, exist_ok=True)
SCAN_INDEX: dict[str, dict] = {}
SAFE_ID = re.compile(r"^[a-z0-9_-]{4,40}$")


def _ocr_available() -> bool:
    return shutil.which("tesseract") is not None


def _select_provider(choice: str = "stub"):
    key = groq_key(ROOT)
    if choice in ("groq", "auto") and key:
        return GroqProvider(key)
    if choice in ("stub", "auto"):
        return StubProvider()
    return None


def _build_multimodal_demo(dest: Path) -> None:
    """Create a self-contained multi-modal synthetic hospital export covering:
      1. Scanned image-only PDF (OCR)
      2. Unflattened faux-redacted PDF + sticky-note annotation
      3. RTF transcription note
      4. MIME .eml email with CSV patient roster attachment
      5. HTML patient portal page with outbound SHA-256 + MD5 tracker pixel
      6. FHIR R4 Patient + Condition JSON bundle
      7. Clean physician directory page with valid Luhn NPI (negative control)
    """
    dest.mkdir(parents=True, exist_ok=True)
    import pymupdf as fitz  # noqa: PLC0415
    from PIL import Image, ImageDraw, ImageFont  # noqa: PLC0415

    # 1. Scanned image-only PDF
    img = Image.new("RGB", (900, 140), color=(255, 255, 255))
    draw = ImageDraw.Draw(img)
    try:
        font = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", 26)
    except Exception:  # noqa: BLE001
        font = ImageFont.load_default()
    draw.text((20, 45), "Patient: Emeka Delgado MRN-881001 Diagnosis: carcinoma", fill=(0, 0, 0), font=font)
    png_buf = io.BytesIO()
    img.save(png_buf, format="PNG")

    pdf1 = fitz.open()
    p1 = pdf1.new_page(width=612, height=792)
    p1.insert_image(fitz.Rect(36, 100, 576, 220), stream=png_buf.getvalue())
    (dest / "scanned_pathology_intake.pdf").write_bytes(pdf1.tobytes())
    pdf1.close()

    # 2. Unflattened faux-redacted PDF + sticky note annotation
    pdf2 = fitz.open()
    p2 = pdf2.new_page(width=612, height=792)
    rect = fitz.Rect(72, 100, 460, 135)
    p2.insert_text((72, 120), "Marisol Lindqvist MRN-881002 stage IIIA lymphoma", fontsize=12)
    shape = p2.new_shape()
    shape.draw_rect(rect)
    shape.finish(fill=(0, 0, 0), color=(0, 0, 0))
    shape.commit()
    p2.add_text_annot((100, 220), "Reviewer note: Yuki Rahimi MRN-881003 multiple sclerosis")
    (dest / "unflattened_redaction_chart.pdf").write_bytes(pdf2.tobytes())
    pdf2.close()

    # 3. RTF clinical note
    (dest / "discharge_note.rtf").write_text(
        r"{\rtf1\ansi\f0\pard Patient: Beatrix Yamamoto \par MRN-881004 \par Diagnosis: ovarian carcinoma \par}",
        encoding="utf-8",
    )

    # 4. MIME .eml with CSV attachment
    msg = EmailMessage()
    msg["Subject"] = "Oncology Consult Handover"
    msg["From"] = "triage@northbridge-clinic.example"
    msg["To"] = "oncology@northbridge-clinic.example"
    msg.set_content("Patient Ingrid Vasquez (MRN-881005) admitted with hepatitis C with cirrhosis.")
    msg.add_attachment(
        b"patient_name,mrn,diagnosis\nTobias Feng,MRN-881006,bipolar disorder\n",
        maintype="text",
        subtype="csv",
        filename="ward_roster.csv",
    )
    (dest / "referral_handover.eml").write_bytes(msg.as_bytes())

    # 5. HTML page with SHA-256 hashed email in third-party pixel
    email_addr = "clara.watanabe@patient-portal.org"
    email_sha = hashlib.sha256(email_addr.encode("utf-8")).hexdigest()
    (dest / "portal_tracker.html").write_text(
        f'<!doctype html><html><body><p>Portal login: {email_addr}</p>'
        f'<img src="https://px.ad-tracker.example/hit?em={email_sha}&ev=LabViewed" />'
        f"</body></html>",
        encoding="utf-8",
    )

    # 6. FHIR R4 Bundle
    (dest / "fhir_bundle.json").write_text(
        json.dumps({
            "resourceType": "Bundle",
            "entry": [
                {"fullUrl": "urn:uuid:pt-9", "resource": {"resourceType": "Patient", "id": "pt-9", "name": [{"text": "Rafael Ibarra"}]}},
                {"resource": {"resourceType": "Condition", "subject": {"reference": "urn:uuid:pt-9"}, "code": {"text": "Schizophrenia"}}},
            ],
        }, indent=2),
        encoding="utf-8",
    )

    # 7. Clean negative control: staff physician bio with valid Luhn NPI
    (dest / "doctors" / "dr_wells.html").parent.mkdir(parents=True, exist_ok=True)
    (dest / "doctors" / "dr_wells.html").write_text(
        '<!doctype html><html><body><div itemscope itemtype="https://schema.org/Physician">'
        "<p>Dr. Anika Wells, MD — Neurology — NPI 1234567893</p></div></body></html>",
        encoding="utf-8",
    )


def _execute_scan(source_dir: Path, scan_id: str, label: str,
                  context: str = "public-web", llm_choice: str = "stub") -> dict:
    out_dir = SCAN_STORE / scan_id / "out"
    src_copy = SCAN_STORE / scan_id / "src"
    if src_copy.exists():
        shutil.rmtree(src_copy)
    shutil.copytree(source_dir, src_copy)

    collect(src_copy, out_dir)
    cleared: list[dict] = []
    findings = detect(
        out_dir / "index.jsonl",
        out_dir / "vault",
        ("portal", "api/v2/patients"),
        context=context,
        cleared=cleared,
    )
    provider = _select_provider(llm_choice)
    run_meta = finish(out_dir, findings, cleared, provider, {"mode": "files", "source": label})
    if provider is not None:
        vault = Vault(out_dir / "vault")
        findings, _ = review_all(findings, vault, provider)
    for f in findings:
        f["masked_path"] = mask_path(f["path"])

    rep = replay(out_dir)
    record = {
        "scan_id": scan_id,
        "label": label,
        "context": context,
        "run": run_meta,
        "findings": findings,
        "replay": rep,
    }
    SCAN_INDEX[scan_id] = record
    return record


class DemoRequest(BaseModel):
    preset: str = "multimodal"
    llm: str = "stub"


class InlineRequest(BaseModel):
    filename: str = "snippet.txt"
    content: str
    context: str = "public-web"
    llm: str = "stub"


class LiveRequest(BaseModel):
    url: str = ""
    max_pages: int = 15
    ignore_robots: bool = True
    llm: str = "stub"


@app.get("/", response_class=HTMLResponse)
def dashboard() -> str:
    return DASHBOARD_HTML


@app.get("/api/health")
def api_health() -> dict:
    ids = yaml.safe_load((ROOT / "policy" / "identifiers.yaml").read_text(encoding="utf-8"))["identifiers"]
    rules = yaml.safe_load((ROOT / "policy" / "rules.yaml").read_text(encoding="utf-8"))["rules"]
    negs = yaml.safe_load((ROOT / "policy" / "negatives.yaml").read_text(encoding="utf-8"))["predicates"]
    return {
        "status": "ok",
        "version": __version__,
        "identifiers": len(ids),
        "rules": len(rules),
        "negative_predicates": len(negs),
        "ocr_ready": _ocr_available(),
        "groq_configured": bool(groq_key(ROOT)),
    }


@app.get("/api/policy")
def api_policy() -> dict:
    ids = yaml.safe_load((ROOT / "policy" / "identifiers.yaml").read_text(encoding="utf-8"))["identifiers"]
    rules = yaml.safe_load((ROOT / "policy" / "rules.yaml").read_text(encoding="utf-8"))["rules"]
    negs = yaml.safe_load((ROOT / "policy" / "negatives.yaml").read_text(encoding="utf-8"))["predicates"]
    return {"identifiers": ids, "rules": rules, "negative_predicates": negs}


@app.post("/api/scan/demo")
def api_scan_demo(req: DemoRequest) -> dict:
    scan_id = f"demo-{req.preset}-{secrets.token_hex(3)}"
    if req.preset == "world":
        world = ROOT / "fixtures" / "world"
        if not world.exists():
            subprocess.run([sys.executable, str(ROOT / "fixtures" / "build_world.py")],
                           check=True, cwd=str(ROOT))
        return _execute_scan(world, scan_id, "fixtures/world (73 planted leaks)", "public-web", req.llm)
    if req.preset == "realsite":
        realsite = ROOT / "artifacts" / "realsite" / "site"
        if not realsite.exists():
            from fixtures.build_realsite import build as build_realsite  # noqa: PLC0415

            build_realsite(realsite)
        return _execute_scan(realsite, scan_id, "fixtures/realsite (realistic hospital portal)", "public-web", req.llm)

    mm_dir = SCAN_STORE / scan_id / "generated"
    _build_multimodal_demo(mm_dir)
    return _execute_scan(
        mm_dir,
        scan_id,
        "Multi-Modal Suite (Scanned OCR PDF + Unflattened PDF + RTF + EML + Tracker Hash + FHIR)",
        "public-web",
        req.llm,
    )


@app.post("/api/scan/inline")
def api_scan_inline(req: InlineRequest) -> dict:
    scan_id = f"inline-{secrets.token_hex(4)}"
    tmp_src = SCAN_STORE / scan_id / "raw_in"
    safe_rel = Path(req.filename or "snippet.txt").as_posix().lstrip("/")
    if ".." in safe_rel.split("/"):
        safe_rel = Path(safe_rel).name or "snippet.txt"
    target = tmp_src / safe_rel
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(req.content, encoding="utf-8")
    return _execute_scan(
        tmp_src,
        scan_id,
        f"inline:{safe_rel}",
        req.context if req.context in ("covered-entity", "public-web") else "public-web",
        req.llm,
    )


@app.post("/api/scan/upload")
async def api_scan_upload(
    files: list[UploadFile] = File(...),
    context: str = Form("covered-entity"),
) -> dict:
    scan_id = f"upload-{secrets.token_hex(4)}"
    tmp_src = SCAN_STORE / scan_id / "uploaded"
    tmp_src.mkdir(parents=True, exist_ok=True)
    for item in files[:50]:
        name = Path(item.filename or "file.bin").name
        data = await item.read()
        (tmp_src / name).write_bytes(data[:25_000_000])
    ctx = context if context in ("covered-entity", "public-web") else "covered-entity"
    return _execute_scan(tmp_src, scan_id, f"uploaded ({len(files)} file(s))", ctx, "stub")


@app.post("/api/scan/live")
def api_scan_live(req: LiveRequest) -> dict:
    scan_id = f"live-{secrets.token_hex(4)}"
    crawl_dir = SCAN_STORE / scan_id / "crawl"
    max_pages = max(1, min(int(req.max_pages or 15), 50))

    # If no URL is provided, spin up the local synthetic clinic HTTP server on an ephemeral port
    if not req.url:
        world = ROOT / "fixtures" / "world"
        if not world.exists():
            subprocess.run([sys.executable, str(ROOT / "fixtures" / "build_world.py")],
                           check=True, cwd=str(ROOT))
        sys.path.insert(0, str(ROOT / "fixtures"))
        import serve  # noqa: PLC0415

        server = ThreadingHTTPServer(("127.0.0.1", 0), serve.SiteHandler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        try:
            url = f"http://127.0.0.1:{server.server_address[1]}/site/index.html"
            crawl(url, crawl_dir, max_pages=max_pages, delay=0.05)
        finally:
            server.shutdown()
        return _execute_scan(crawl_dir / "pages", scan_id, "live://synthetic-clinic", "public-web", req.llm)

    if not req.url.startswith(("http://", "https://")):
        raise HTTPException(status_code=400, detail="URL must start with http:// or https://")
    crawl(req.url, crawl_dir, max_pages=max_pages, delay=0.2)
    return _execute_scan(crawl_dir / "pages", scan_id, req.url, "public-web", req.llm)


@app.get("/api/scans")
def api_list_scans() -> list[dict]:
    return [
        {
            "scan_id": s["scan_id"],
            "label": s["label"],
            "findings": len(s["findings"]),
            "levels": s["run"].get("levels", {}),
            "created": s["run"].get("created", ""),
        }
        for s in reversed(list(SCAN_INDEX.values()))
    ]


@app.get("/api/scans/{scan_id}")
def api_get_scan(scan_id: str) -> dict:
    if not SAFE_ID.match(scan_id) or scan_id not in SCAN_INDEX:
        raise HTTPException(status_code=404, detail="Scan not found")
    return SCAN_INDEX[scan_id]


@app.post("/api/scans/{scan_id}/replay")
def api_replay_scan(scan_id: str) -> dict:
    if not SAFE_ID.match(scan_id) or scan_id not in SCAN_INDEX:
        raise HTTPException(status_code=404, detail="Scan not found")
    out_dir = SCAN_STORE / scan_id / "out"
    res = replay(out_dir)
    SCAN_INDEX[scan_id]["replay"] = res
    return res


@app.get("/api/scans/{scan_id}/export/{kind}")
def api_export_scan(scan_id: str, kind: str) -> Response:
    if not SAFE_ID.match(scan_id) or scan_id not in SCAN_INDEX:
        raise HTTPException(status_code=404, detail="Scan not found")
    out_dir = SCAN_STORE / scan_id / "out"
    src_dir = SCAN_STORE / scan_id / "src"

    if kind in ("findings.json", "findings.sarif", "evidence.jsonl", "report.html", "run.json"):
        target = out_dir / kind
        if not target.exists():
            raise HTTPException(status_code=404, detail=f"{kind} not found")
        media = "text/html" if kind.endswith(".html") else "application/json"
        return Response(content=target.read_bytes(), media_type=media)

    if kind == "redacted.zip":
        redacted_dir = SCAN_STORE / scan_id / "redacted"
        if redacted_dir.exists():
            shutil.rmtree(redacted_dir)
        write_redacted(SCAN_INDEX[scan_id]["findings"], src_dir, redacted_dir)
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            for path in sorted(redacted_dir.rglob("*")):
                if path.is_file():
                    zf.write(path, path.relative_to(redacted_dir).as_posix())
        return Response(
            content=buf.getvalue(),
            media_type="application/zip",
            headers={"Content-Disposition": f'attachment; filename="{scan_id}-redacted.zip"'},
        )

    raise HTTPException(status_code=400, detail="Unsupported export kind")


def run_server(host: str = "127.0.0.1", port: int = 43821) -> None:
    import uvicorn  # noqa: PLC0415

    uvicorn.run(app, host=host, port=port, log_level="info")


if __name__ == "__main__":
    run_server()

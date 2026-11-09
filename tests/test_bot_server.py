"""End-to-end tests for the deployable phi-scan web dashboard & API server."""

from __future__ import annotations

from fastapi.testclient import TestClient

from phi_scan.bot_server import app


def test_bot_server_health_policy_and_scans(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("PHI_EVIDENCE_KEYS", str(tmp_path / "keys"))
    client = TestClient(app)

    # 1. Dashboard HTML
    home = client.get("/")
    assert home.status_code == 200
    assert "Autonomous HIPAA" in home.text

    # 2. Health and policy endpoints
    health = client.get("/api/health").json()
    assert health["status"] == "ok"
    assert health["identifiers"] == 18
    assert health["rules"] == 12
    assert health["negative_predicates"] == 8

    policy = client.get("/api/policy").json()
    assert len(policy["identifiers"]) == 18
    assert len(policy["rules"]) == 12

    # 3. Multimodal demo scan + vault replay + exports
    demo_res = client.post("/api/scan/demo", json={"preset": "multimodal", "llm": "stub"})
    assert demo_res.status_code == 200
    demo = demo_res.json()
    scan_id = demo["scan_id"]
    assert len(demo["findings"]) >= 5
    assert demo["replay"]["mismatched"] == []

    # Verify replay endpoint
    rep = client.post(f"/api/scans/{scan_id}/replay").json()
    assert rep["checked"] == len(demo["findings"])
    assert rep["mismatched"] == []

    # Verify exports (findings.json, findings.sarif, report.html, redacted.zip)
    for kind in ("findings.json", "findings.sarif", "evidence.jsonl", "report.html", "redacted.zip"):
        exp = client.get(f"/api/scans/{scan_id}/export/{kind}")
        assert exp.status_code == 200 and len(exp.content) > 0

    # 4. Inline clinical payload scan
    inline = client.post("/api/scan/inline", json={
        "filename": "note.txt",
        "content": "Patient Emeka Delgado (MRN-881001) diagnosed with stage III carcinoma.",
        "context": "public-web",
        "llm": "stub",
    }).json()
    assert len(inline["findings"]) >= 1
    assert "Emeka Delgado" not in str(inline["findings"])

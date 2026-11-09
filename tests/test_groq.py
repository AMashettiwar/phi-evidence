import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from phi_scan.ai import GroqProvider, Request, apply_review, consensus, fleiss_kappa


class FakeGroq(BaseHTTPRequestHandler):
    """Answers like Groq's chat completions endpoint; scripted per test."""
    script: list = []
    seen: list = []

    def log_message(self, *args):
        return

    def do_POST(self):
        self.seen.append((dict(self.headers), json.loads(self.rfile.read(int(self.headers["Content-Length"])))))
        status, content = self.script.pop(0)
        body = json.dumps({"model": "openai/gpt-oss-120b", "system_fingerprint": "fp_test",
                           "usage": {"prompt_tokens": 100, "completion_tokens": 40},
                           "choices": [{"message": {"content": content}}]}).encode()
        self.send_response(status)
        if status == 429:
            self.send_header("retry-after", "0")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


@pytest.fixture()
def groq():
    FakeGroq.script, FakeGroq.seen = [], []
    server = ThreadingHTTPServer(("127.0.0.1", 0), FakeGroq)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield GroqProvider("test-key", url=f"http://127.0.0.1:{server.server_port}/v1/chat/completions")
    server.shutdown()


REQUEST = Request("f00007", "page_text", ["names"], "B", "[NAME] - type 2 diabetes mellitus")
GOOD = json.dumps({"finding_id": "f00007", "assessment": "patient", "confidence": 0.9,
                   "level_recommendation": "keep", "explanation": "Possible PHI exposure."})


def test_request_is_deterministic_json_and_redacted(groq):
    FakeGroq.script = [(200, GOOD)]
    review = groq.review(REQUEST)
    headers, body = FakeGroq.seen[0]
    assert headers["Authorization"] == "Bearer test-key"
    assert body["temperature"] == 0 and body["seed"] == 0
    assert body["response_format"] == {"type": "json_object"}
    assert "untrusted data" in body["messages"][0]["content"]
    assert json.loads(body["messages"][1]["content"])["redacted_context"] == "[NAME] - type 2 diabetes mellitus"
    assert review["assessment"] == "patient"


def test_rate_limit_is_retried_and_cost_is_counted(groq):
    FakeGroq.script = [(429, "{}"), (200, GOOD)]
    assert groq.review(REQUEST)["assessment"] == "patient"
    cost = groq.cost()
    assert cost["calls"] == 1 and cost["tokens_in"] == 100 and cost["fingerprints"] == ["fp_test"]
    assert cost["usd"] == pytest.approx((100 * 0.15 + 40 * 0.60) / 1e6)


def test_a_broken_answer_leaves_the_finding_alone(groq):
    FakeGroq.script = [(200, "this is not json")]
    finding = {"finding_id": "f00007", "level": "critical", "identifiers": ["mrn"]}
    out = apply_review(finding, groq.review(REQUEST), "groq")
    assert out["level"] == "critical" and not out["ai"]["valid"]


def test_a_review_citing_another_finding_is_rejected():
    finding = {"finding_id": "f00007", "level": "high", "identifiers": ["names"]}
    other = json.loads(GOOD) | {"finding_id": "f00099", "level_recommendation": "lower"}
    assert apply_review(finding, other)["level"] == "high"


def test_consensus_lowers_only_when_every_run_agrees():
    lower = json.loads(GOOD) | {"assessment": "staff", "level_recommendation": "lower"}
    keep = json.loads(GOOD)
    assert consensus([lower, lower, lower])["level_recommendation"] == "lower"
    assert consensus([lower, lower, keep])["level_recommendation"] == "keep"


def test_fleiss_kappa():
    assert fleiss_kappa([["patient"] * 3, ["staff"] * 3, ["patient"] * 3]) == 1.0
    assert fleiss_kappa([["patient", "staff", "unclear"], ["staff", "patient", "unclear"]]) < 0


def test_moving_to_review_is_capped_and_never_for_always_flag():
    from phi_scan.ai import review_all

    class Staff:
        name = "fake"

        def review(self, request):
            return {"finding_id": request.finding_id, "assessment": "staff", "confidence": 0.95,
                    "level_recommendation": "lower", "explanation": "A clinician."}

    class OneVault:
        def get(self, doc, purpose="detect"):
            return b"Dr. Ana Ruiz, NPI 1234567893"

    findings = [{"finding_id": f"f{i:05d}", "doc": "d", "offset": 0, "length": 5, "carrier": "page_text",
                 "identifiers": ["names"] if i < 8 else ["mrn"], "evidence_grade": "B", "level": "critical"}
                for i in range(10)]
    out, _ = review_all(findings, OneVault(), Staff())
    moved = [f for f in out if f["level"] == "review"]
    assert len(moved) == 2  # 25% of 10
    assert all("mrn" not in f["identifiers"] for f in moved)
    assert all(f["level"] in ("critical", "high") for f in out if "mrn" in f["identifiers"])

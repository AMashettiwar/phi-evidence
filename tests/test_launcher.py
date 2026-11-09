"""The point-and-click launcher: what it writes, what it refuses."""

from __future__ import annotations

import threading
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

import pytest

from phi_scan import launcher
from phi_scan.browser import Guard


def test_public_scan_needs_only_the_address():
    scope = launcher.build_scope({"target": "https://clinic.test/", "pages": "20"})
    assert scope == {"target": "https://clinic.test", "rate_limit": {"page_cap": 20}}


def test_two_accounts_and_api_paths():
    scope = launcher.build_scope({"target": "https://clinic.test", "cookie_a": "s=1; t=2",
                                  "cookie_b": "s=3", "id_b": "31", "api_by_id": "/api/p/{id}"})
    assert scope["scan_as"] == "A"
    assert scope["accounts"] == [{"name": "A", "cookie": "s=1; t=2"},
                                 {"name": "B", "cookie": "s=3", "patient_id": "31"}]
    assert scope["api"] == {"by_id": "/api/p/{id}"}


def test_form_refusals(monkeypatch, tmp_path):
    monkeypatch.setattr(launcher, "SCANS", tmp_path)
    assert launcher.start({"target": "clinic.test", "permission": "on"})[1].startswith("Type the full")
    assert "permission" in launcher.start({"target": "https://clinic.test"})[1]
    assert "account 1" in launcher.start({"target": "https://clinic.test", "permission": "on",
                                          "cookie_b": "s=3"})[1]
    assert not list(tmp_path.iterdir())


def test_failed_scan_keeps_no_cookies(monkeypatch, tmp_path):
    """The cookie reaches the scan through a temporary scope file only; what
    stays in the results folder has it removed, even when the scan fails."""
    seen = {}

    def scan_live(scope_path, out, provider):
        seen["scope"] = scope_path.read_text(encoding="utf-8")
        raise RuntimeError("site unreachable with cookie abc123")

    monkeypatch.setattr(launcher, "scan_live", scan_live)
    scope = launcher.build_scope({"target": "https://clinic.test", "cookie_a": "session=abc123"})
    job = {"out": tmp_path}
    launcher.run_scan(job, scope, None)
    assert "abc123" in seen["scope"]
    assert job["state"] == "failed" and job["error"].endswith("site unreachable with cookie [cookie]")
    saved = (tmp_path / "scope.yaml").read_text(encoding="utf-8")
    assert "abc123" not in saved and "name: A" in saved
    assert "abc123" not in (tmp_path / "error.txt").read_text(encoding="utf-8")
    assert not any("abc123" in p.read_text(encoding="utf-8", errors="ignore")
                   for p in Path(launcher.tempfile.gettempdir()).glob("tmp*.yaml"))


def test_errors_in_plain_words():
    assert "could not be reached" in launcher.plain("Error: connect ECONNREFUSED 127.0.0.1:8899")
    assert "install.bat" in launcher.plain("Executable doesn't exist at C:\\ms-playwright\\chrome")
    assert "error.txt" in launcher.plain("KeyError: 'pages'")


@pytest.mark.parametrize("path, allowed", [
    ("/logout", False), ("/account/sign-out", False), ("/auth/logoff.php", False),
    ("/catalogoutlet", True), ("/blog/outdoors", True), ("/patients/me", True)])
def test_scan_never_signs_itself_out(path, allowed):
    assert Guard({"target": "https://clinic.test"}).allowed("https://clinic.test" + path) is allowed


def test_server_refuses_forged_requests():
    server = launcher.ThreadingHTTPServer(("127.0.0.1", 0), launcher.Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{server.server_address[1]}"
    try:
        assert launcher.TOKEN in urllib.request.urlopen(base + "/").read().decode("utf-8")
        # Another site's page can post the form but cannot read the token.
        forged = urllib.parse.urlencode({"target": "https://victim.test", "permission": "on"})
        with pytest.raises(urllib.error.HTTPError) as refused:
            urllib.request.urlopen(base + "/scan", data=forged.encode())
        assert refused.value.code == 403
        # A domain pointed at 127.0.0.1 (DNS rebinding) names itself in Host.
        rebound = urllib.request.Request(base + "/", headers={"Host": "evil.test"})
        with pytest.raises(urllib.error.HTTPError) as refused:
            urllib.request.urlopen(rebound)
        assert refused.value.code == 403
    finally:
        server.shutdown()

"""A page in your own browser for running a scan without typing commands.

    python -m phi_scan.launcher          (start.bat does this)

It listens on 127.0.0.1 only, so nothing else on the network can reach it, and
every form carries a one-time token so another website open in the same
browser cannot start a scan. Results go to ~/PHI-Scans/<site>-<time>/.
Session cookies are used for the scan and never written to disk: the scope
file saved with the results has them removed.
"""

from __future__ import annotations

import argparse
import html
import json
import re
import secrets
import tempfile
import threading
import time
import traceback
import webbrowser
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import yaml

from .ai import GroqProvider, groq_key
from .evidence import replay
from .pipeline import ROOT, scan_live

SCANS = Path.home() / "PHI-Scans"
TOKEN = secrets.token_urlsafe(24)
JOBS: dict[str, dict] = {}
esc = html.escape

STYLE = """
:root { color-scheme: light dark; --line: #8885; --accent: #2563eb; --bad: #c0392b; --muted: #8a8a8a; }
body { font: 16px/1.55 system-ui, sans-serif; max-width: 760px; margin: 2rem auto; padding: 0 16px; }
h1 { font-size: 1.6rem; margin-bottom: .2rem; }
fieldset { border: 1px solid var(--line); border-radius: 10px; margin: 1.2rem 0; padding: .6rem 1rem 1rem; }
legend { font-weight: 600; padding: 0 .4rem; }
label { display: block; margin-top: .8rem; font-weight: 500; }
input[type=text], input[type=url], input[type=number], input[type=password] {
  width: 100%; box-sizing: border-box; padding: .5rem .6rem; font: inherit;
  border: 1px solid var(--line); border-radius: 6px; }
.check { display: flex; gap: .6rem; align-items: flex-start; font-weight: 500; }
.check input { margin-top: .35rem; }
.hint { color: var(--muted); font-size: .9rem; margin: .2rem 0 0; }
button { margin-top: 1.2rem; padding: .7rem 1.6rem; font: inherit; font-weight: 600; color: white;
  background: var(--accent); border: 0; border-radius: 8px; cursor: pointer; }
details { margin-top: .8rem; } summary { cursor: pointer; }
.error { border-left: 4px solid var(--bad); padding: .4rem .8rem; }
table { border-collapse: collapse; } td { padding: .25rem 1rem .25rem 0; vertical-align: top; }
code { font-size: .9em; }
"""


def page(title: str, body: str, refresh: int = 0) -> bytes:
    meta = f'<meta http-equiv="refresh" content="{refresh}">' if refresh else ""
    return (f'<!doctype html><html lang="en"><head><meta charset="utf-8">'
            f'<meta name="viewport" content="width=device-width, initial-scale=1">{meta}'
            f"<title>{esc(title)}</title><style>{STYLE}</style></head><body>{body}</body></html>"
            ).encode("utf-8")


FORM = """
<h1>PHI exposure scan</h1>
<p>Looks at a website the way a visitor's browser does and reports places where patient
information may be exposed. It only reads: it never submits forms or changes anything on the site.</p>
{error}
<form method="post" action="/scan">
<input type="hidden" name="token" value="{token}">
<fieldset><legend>1. The website</legend>
  <label for="target">Website address</label>
  <input type="url" id="target" name="target" required placeholder="https://portal.example-clinic.org" value="{target}">
  <label class="check"><input type="checkbox" name="permission" required>
    I own this website, or I have written permission from its owner to scan it.</label>
  <label for="pages">Most pages to visit</label>
  <input type="number" id="pages" name="pages" min="1" max="2000" value="{pages}">
  <p class="hint">The scan waits about a second between requests so it never strains the site.
  200 pages takes roughly 10 to 30 minutes; try 20 for a quick first look.</p>
</fieldset>

<fieldset><legend>2. Logged-in test (optional)</legend>
  <p class="hint">Leave this empty to scan only what the public can see. To check whether one
  patient can open another patient's records, make two <b>test</b> patient accounts on the site
  (never real patients), log in to each, and paste its cookie line below.</p>
  <details><summary>How do I copy a cookie line?</summary>
  <ol class="hint">
    <li>In Chrome or Edge, log in to the site as the test account.</li>
    <li>Press <b>F12</b>, open the <b>Network</b> tab, then reload the page (F5).</li>
    <li>Click the first row in the list, then <b>Headers</b>, and scroll to <b>Request Headers</b>.</li>
    <li>Find the line that starts with <b>cookie:</b>, right-click its value, and copy it.</li>
    <li>Paste it here. It is used for this scan only and never saved.</li>
    <li>For the second account, use a private (incognito) window so the first login is kept.</li>
  </ol></details>
  <label for="cookie_a">Test account 1 cookie line</label>
  <input type="password" id="cookie_a" name="cookie_a" autocomplete="off" placeholder="sessionid=...; csrftoken=...">
  <label for="cookie_b">Test account 2 cookie line</label>
  <input type="password" id="cookie_b" name="cookie_b" autocomplete="off" placeholder="sessionid=...; csrftoken=...">
  <p class="hint">The scan browses as account 1. With both accounts it also tries to open account 2's
  record while logged in as account 1. It finds the record addresses by itself from the site's API
  description (OpenAPI or Swagger) when the site publishes one.</p>
  <details><summary>Advanced: tell it the record addresses yourself</summary>
    <p class="hint">Only needed when the site does not publish an API description. Ask the site's
    developers; each box takes a path on the same site.</p>
    <label for="api_schema">API description address</label>
    <input type="text" id="api_schema" name="api_schema" placeholder="/openapi.json">
    <label for="api_self">"My record" address</label>
    <input type="text" id="api_self" name="api_self" placeholder="/api/patients/me">
    <label for="api_by_id">"Record by number" address, with {{id}} where the number goes</label>
    <input type="text" id="api_by_id" name="api_by_id" placeholder="/api/patients/{{id}}">
    <label for="id_a">Account 1's record number</label>
    <input type="text" id="id_a" name="id_a">
    <label for="id_b">Account 2's record number</label>
    <input type="text" id="id_b" name="id_b">
  </details>
</fieldset>

<fieldset><legend>3. AI second opinion (optional)</legend>
  <label class="check"><input type="checkbox" name="ai" {ai_checked}>
    Ask an AI model (Groq) to review each finding.</label>
  <p class="hint">Off by default. It sends short, masked snippets around each finding to Groq, which
  has not signed a HIPAA agreement. Leave it off for sites that may hold real patient data unless
  your organisation has approved it. The scan works fully without it.</p>
  <label for="groq_key">Groq API key {key_state}</label>
  <input type="password" id="groq_key" name="groq_key" autocomplete="off" placeholder="gsk_...">
</fieldset>

<button type="submit">Start scan</button>
</form>
"""


def form(error: str = "", target: str = "", pages: str = "200", ai: bool = False) -> bytes:
    key_state = ("(one is already saved; leave empty to keep it)" if groq_key(ROOT)
                 else "(saved on this computer for next time)")
    body = FORM.format(token=TOKEN, target=esc(target), pages=esc(pages),
                       ai_checked="checked" if ai else "", key_state=key_state,
                       error=f'<p class="error">{esc(error)}</p>' if error else "")
    return page("PHI exposure scan", body)


def save_key(key: str) -> None:
    """Write GROQ_API_KEY into the repository's git-ignored .env, keeping other lines."""
    env = ROOT / ".env"
    lines = env.read_text(encoding="utf-8").splitlines() if env.exists() else []
    lines = [line for line in lines if line.partition("=")[0].strip() != "GROQ_API_KEY"]
    env.write_text("\n".join(lines + [f"GROQ_API_KEY={key}"]) + "\n", encoding="utf-8")


def build_scope(fields: dict[str, str]) -> dict:
    scope: dict = {"target": fields["target"].rstrip("/"),
                   "rate_limit": {"page_cap": int(fields.get("pages") or 200)}}
    accounts = []
    for name, cookie, record in (("A", "cookie_a", "id_a"), ("B", "cookie_b", "id_b")):
        if fields.get(cookie):
            account = {"name": name, "cookie": fields[cookie]}
            if fields.get(record):
                account["patient_id"] = fields[record]
            accounts.append(account)
    if accounts:
        scope["accounts"], scope["scan_as"] = accounts, accounts[0]["name"]
    api = {key: fields[f"api_{key}"] for key in ("schema", "self", "by_id") if fields.get(f"api_{key}")}
    if api:
        scope["api"] = api
    return scope


def run_scan(job: dict, scope: dict, provider) -> None:
    """The scan itself, in a thread. The full scope, cookies included, exists
    only as a temporary file for the length of the scan."""
    out = job["out"]
    handle = tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False, encoding="utf-8")
    try:
        with handle:
            yaml.safe_dump(scope, handle, sort_keys=False)
        job["run"] = scan_live(Path(handle.name), out, provider)
        job["capture"] = json.loads((out / "capture.json").read_text(encoding="utf-8"))
        job["replay"] = replay(out)
        job["state"] = "done"
    except Exception as error:  # shown to the person on the status page
        secrets_in = [part.partition("=")[2].strip() for a in scope.get("accounts", [])
                      for part in a["cookie"].split(";")]
        message, details = f"{type(error).__name__}: {error}", traceback.format_exc()
        for value in filter(None, secrets_in):
            message, details = message.replace(value, "[cookie]"), details.replace(value, "[cookie]")
        job["state"], job["error"] = "failed", message
        (out / "error.txt").write_text(details, encoding="utf-8")
    finally:
        Path(handle.name).unlink(missing_ok=True)
        # Written last: the scan clears its output folder when it starts.
        saved = {**scope, "accounts": [{k: v for k, v in a.items() if k != "cookie"}
                                        for a in scope.get("accounts", [])]}
        (out / "scope.yaml").write_text("# Cookies were used for the scan and removed from this copy.\n"
                                        + yaml.safe_dump(saved, sort_keys=False), encoding="utf-8")
        job["finished"] = time.monotonic()


def start(fields: dict[str, str]) -> tuple[str | None, str]:
    """Check the form and start a scan. Returns (job id, error)."""
    target = fields.get("target", "").strip()
    parsed = urlparse(target)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        return None, "Type the full website address, starting with https://"
    if not fields.get("permission"):
        return None, "Tick the box to confirm you own the site or have written permission to scan it."
    if not (fields.get("pages") or "200").isdigit():
        return None, "Most pages to visit must be a whole number."
    if fields.get("cookie_b") and not fields.get("cookie_a"):
        return None, "Fill in test account 1 first; account 2 is only used together with account 1."
    if any(job["state"] == "running" for job in JOBS.values()):
        return None, "A scan is already running. Wait for it to finish, then start the next."
    provider = None
    if fields.get("ai"):
        if fields.get("groq_key"):
            save_key(fields["groq_key"].strip())
        key = groq_key(ROOT)
        if not key:
            return None, "The AI second opinion needs a Groq API key, or untick it."
        provider = GroqProvider(key)
    fields["target"] = target
    scope = build_scope(fields)
    name = re.sub(r"[^A-Za-z0-9.]+", "-", parsed.netloc).strip("-")
    out = SCANS / f"{name}-{datetime.now():%Y%m%d-%H%M%S}"
    out.mkdir(parents=True)
    job_id = secrets.token_hex(4)
    JOBS[job_id] = job = {"state": "running", "out": out, "target": target,
                          "started": time.monotonic(), "ai": provider is not None}
    threading.Thread(target=run_scan, args=(job, scope, provider), daemon=True).start()
    return job_id, ""


REASONS = (  # (words in the error, what to tell the person)
    (("ECONNREFUSED", "ENOTFOUND", "ERR_NAME_NOT_RESOLVED", "EAI_AGAIN", "ETIMEDOUT",
      "ECONNRESET", "Timeout"),
     "The website could not be reached. Check the address opens in your browser on this computer."),
    (("CERT", "SSL", "certificate"),
     "The website's security certificate was refused. Check the address, or ask the site's owner."),
    (("Executable doesn't exist", "playwright install"),
     "The scanner's browser is missing. Double-click install.bat again."),
)


def plain(error: str) -> str:
    for words, advice in REASONS:
        if any(word in error for word in words):
            return advice
    return "Something unexpected went wrong. Send error.txt from the results folder to whoever set this up."


def minutes(seconds: float) -> str:
    seconds = int(seconds)
    return f"{seconds // 60} min {seconds % 60} s"


def access_words(test: dict) -> str:
    if not test.get("ran"):
        return f"Not run: {test.get('reason', 'no test accounts given')}."
    crossed = test["records_read_across_accounts"]
    words = (f"<b>Account 1 could open another account's record</b> ({crossed} address(es)). "
             f"This is listed in the report at level High."
             if crossed else "Account 1 could not open account 2's record at the addresses tested.")
    words += (f" Addresses tested: {test['record_addresses']}, found in "
              f"{esc(test.get('api_description', ''))}.")
    if test.get("note"):
        words += f" Note: {esc(test['note'])}."
    return words


def status(job_id: str) -> bytes:
    job = JOBS[job_id]
    elapsed = minutes((job.get("finished") or time.monotonic()) - job["started"])
    folder = f"<p>Results folder: <code>{esc(str(job['out']))}</code></p>"
    if job["state"] == "running":
        return page("Scanning", f"<h1>Scanning {esc(job['target'])}</h1>"
                    f"<p>Running for {elapsed}. This page refreshes by itself; you can leave it open "
                    f"or come back later. Keep the black launcher window open until it finishes.</p>"
                    + folder, refresh=5)
    if job["state"] == "failed":
        return page("Scan stopped", f"<h1>The scan stopped</h1><p class='error'>{plain(job['error'])}</p>"
                    f"<p class='hint'>Technical details: {esc(job['error'])}</p>"
                    "<p>The full details are in <code>error.txt</code> in the results folder.</p>"
                    + folder + "<p><a href='/'>Start another scan</a></p>")
    run, capture, check = job["run"], job["capture"], job["replay"]
    levels = "".join(f"<tr><td>{esc(level.title())}</td><td>{count}</td></tr>"
                     for level, count in run["levels"].items())
    empty = ("<p class='error'>No pages could be read. Check the address, and that the site is up "
             "and reachable from this computer.</p>" if not capture["pages"] else "")
    stopped = (f"<p class='error'>The scan stopped early: {esc(capture['stopped'])}.</p>"
               if capture.get("stopped") else "")
    verified = ("every finding was re-read from the stored evidence and matched"
                if check["checked"] and not check["mismatched"]
                else f"{len(check['mismatched'])} of {check['checked']} findings did not match their evidence")
    return page("Scan finished", f"""<h1>Scan finished</h1>
<p>{esc(job['target'])}, {elapsed}. Pages read: {capture['pages']}; requests sent:
{capture['requests_sent']}; scanned as: {esc(capture['scan_as'])}.</p>{empty}{stopped}
<h2>{run['findings']} possible exposure(s)</h2>
<table>{levels}</table>
<p><a href="/report/{job_id}" target="_blank"><b>Open the report</b></a> (masked values only; treat it as sensitive).</p>
<h2>Logged-in access test</h2><p>{access_words(capture.get('access_test') or {})}</p>
<h2>Checks</h2><p>Evidence: {verified}. AI second opinion: {'on' if job['ai'] else 'off'}.</p>
{folder}<p>Every finding means "possible PHI exposure, needs compliance review": it is not a breach
decision. Real patient data in these results stays on this computer.</p>
<p><a href="/">Start another scan</a></p>""")


class Handler(BaseHTTPRequestHandler):
    def send(self, body: bytes, code: int = 200, kind: str = "text/html; charset=utf-8") -> None:
        self.send_response(code)
        self.send_header("Content-Type", kind)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def local(self) -> bool:
        """Refuse a request that names another host: a web page cannot point
        a domain it controls at this server and read the answers."""
        host = self.headers.get("Host", "").rsplit(":", 1)[0]
        if host in ("127.0.0.1", "localhost"):
            return True
        self.send(b"forbidden", 403, "text/plain")
        return False

    def do_GET(self) -> None:  # noqa: N802
        if not self.local():
            return
        path = urlparse(self.path).path
        parts = path.strip("/").split("/")
        if path == "/":
            self.send(form())
        elif len(parts) == 2 and parts[0] == "status" and parts[1] in JOBS:
            self.send(status(parts[1]))
        elif len(parts) == 2 and parts[0] == "report" and parts[1] in JOBS \
                and (JOBS[parts[1]]["out"] / "report.html").exists():
            self.send((JOBS[parts[1]]["out"] / "report.html").read_bytes())
        else:
            self.send(page("Not found", "<p>Not found. <a href='/'>Back</a></p>"), 404)

    def do_POST(self) -> None:  # noqa: N802
        if not self.local():
            return
        length = int(self.headers.get("Content-Length") or 0)
        fields = {k: v[0] for k, v in parse_qs(self.rfile.read(length).decode("utf-8")).items()}
        if self.path != "/scan" or not secrets.compare_digest(fields.get("token", ""), TOKEN):
            self.send(page("Expired", "<p>This form has expired. <a href='/'>Open a fresh one</a>.</p>"), 403)
            return
        job_id, error = start(fields)
        if error:
            self.send(form(error, fields.get("target", ""), fields.get("pages", "200"),
                           bool(fields.get("ai"))), 400)
            return
        self.send_response(303)
        self.send_header("Location", f"/status/{job_id}")
        self.end_headers()

    def log_message(self, *args) -> None:  # keep the window readable
        pass


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="phi-scan-launcher")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--no-browser", action="store_true", help="do not open a browser tab")
    args = parser.parse_args(argv)
    server = ThreadingHTTPServer(("127.0.0.1", args.port), Handler)
    url = f"http://127.0.0.1:{server.server_address[1]}/"
    print(f"PHI exposure scan is open at {url}")
    print("Keep this window open while you use it. Close it when you are done.")
    if not args.no_browser:
        webbrowser.open(url)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

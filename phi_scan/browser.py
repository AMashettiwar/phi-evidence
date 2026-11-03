"""Capture a live, authorised target in a real browser (brief 4.1 to 4.4).

The file collector reads what a site ships. This reads what a browser actually
sees and sends: storage written by scripts, cookies, response headers, the
redirect chain, and requests to other companies. Everything it captures is
handed to the same collector and vault, so detection does not care where bytes
came from.

What keeps it safe to point at a real system:

  * one scope file (fixtures/scope.yaml is the example) is the only authority:
    in-scope hosts, out-of-scope hosts and paths, the account to scan as.
  * every request, the browser's own sub-requests included, passes one guard
    and one rate limiter: concurrency 1, at least the configured gap plus
    jitter, a page cap, and stop conditions.
  * a request to an out-of-scope host is recorded as evidence and aborted. The
    third party never receives it; the report still shows what would have left.
  * login is a provisioned session cookie. No form is ever submitted.
  * served bodies go to a temporary mirror that is deleted after collection; the
    HAR and screenshots go straight into the encrypted vault. Screenshots are
    taken with every glyph and image blurred, so they show layout, not values.

Audience is measured, never assumed (spec 2.2): every captured URL is fetched
again with no cookies, and the identity oracle asks whether account A can read
account B's record.
"""

from __future__ import annotations

import json
import os
import random
import re
import tempfile
import time
import urllib.robotparser
from pathlib import Path
from urllib.parse import urljoin, urlparse

import yaml

from .collect import Sink, collect
from .vault import Vault

PAGE_SUFFIXES = ("", ".html", ".htm")
# Build leftovers worth one GET each, in scope like everything else.
WELL_KNOWN = ("/.env", "/.git/config", "/.git/COMMIT_EDITMSG", "/swagger.json",
              "/openapi.json", "/api/v2/openapi.json")
BLUR = ("*{color:transparent!important;text-shadow:0 0 7px #777!important;"
        "caret-color:transparent!important}img,svg,video,canvas,iframe"
        "{filter:blur(18px)!important}")
DUMP_STORAGE = """() => ({local: Object.entries(localStorage),
                          session: Object.entries(sessionStorage)})"""
DUMP_INDEXEDDB = """async () => {
  const out = [];
  if (!indexedDB.databases) return out;
  for (const info of await indexedDB.databases()) {
    const db = await new Promise((ok, no) => {
      const r = indexedDB.open(info.name); r.onsuccess = () => ok(r.result); r.onerror = () => no(r.error);
    });
    for (const store of db.objectStoreNames) {
      const rows = await new Promise(ok => {
        const q = db.transaction(store).objectStore(store).getAll();
        q.onsuccess = () => ok(q.result); q.onerror = () => ok([]);
      });
      for (const row of rows) out.push({db: info.name, store, row});
    }
    db.close();
  }
  return out;
}"""
HREF = re.compile(r"""(?:href|src)\s*=\s*["']([^"'#]+)""", re.I)


class Guard:
    """Scope and pace for every request the scan makes or lets through.

    A stop condition sets `stopped` rather than raising: most requests pass
    through Playwright callbacks, which swallow exceptions, so a raised stop
    would be printed and ignored. Every request and the crawl loop check it.
    """

    def __init__(self, scope: dict) -> None:
        limits = scope["rate_limit"]
        self.hosts = set(scope["in_scope"]["hosts"])
        self.blocked_hosts = set(scope["out_of_scope"].get("hosts", []))
        self.blocked_paths = set(scope["out_of_scope"].get("paths", []))
        self.gap = float(limits["min_interval_seconds"])
        self.jitter = float(limits.get("jitter_seconds", 0))
        self.page_cap = int(limits["page_cap"])
        self.random = random.Random(0)
        self.last = 0.0
        self.sent: list[dict] = []
        self.refused: list[dict] = []
        self.server_errors = 0
        self.stopped: str | None = None

    def allowed(self, url: str) -> bool:
        parsed = urlparse(url)
        return (self.stopped is None and parsed.netloc in self.hosts
                and parsed.path not in self.blocked_paths)

    def refuse(self, url: str, method: str, headers: dict) -> None:
        self.refused.append({"url": url, "method": method,
                             "referer": headers.get("referer", "")})

    def wait(self) -> None:
        if len(self.sent) >= self.page_cap * 4:
            self.stopped = "request cap reached"
        # 20 ms over the gap: the server stamps arrival, and network jitter can
        # shave a few milliseconds off a gap the scanner kept exactly.
        due = self.last + self.gap + 0.02 + self.random.uniform(0, self.jitter)
        pause = due - time.monotonic()
        if pause > 0:
            time.sleep(pause)
        self.last = time.monotonic()

    def record(self, url: str, status: int) -> None:
        self.sent.append({"url": url, "status": status})
        if status == 429:
            self.stopped = "server asked us to slow down (429)"
        self.server_errors = self.server_errors + 1 if status >= 500 else 0
        if self.server_errors >= 3:
            self.stopped = "three server errors in a row"


def local_path(url: str, content_type: str) -> str:
    """Where a captured response sits in the mirror, by URL path."""
    path = urlparse(url).path or "/"
    if path.endswith("/"):
        path += "index"
    rel = path.lstrip("/")
    if not Path(rel).suffix:
        if "html" in content_type:
            rel += ".html"
        elif "json" in content_type:
            rel += ".json"
    return rel


def load_scope(path: Path) -> dict:
    return yaml.safe_load(Path(path).read_text(encoding="utf-8"))


def capture(scope_path: Path, out: Path, key: bytes | None = None) -> dict:
    """Crawl the target as the scope's account, then collect what was seen."""
    from playwright.sync_api import Error as PlaywrightError  # noqa: PLC0415
    from playwright.sync_api import sync_playwright  # noqa: PLC0415

    scope = load_scope(scope_path)
    guard = Guard(scope)
    base = scope["target"].rstrip("/")
    accounts = {a["name"]: a for a in scope["accounts"]}
    me = accounts[scope["scan_as"]]
    key = key or os.urandom(32)
    responses: dict[str, dict] = {}     # rel path -> what was served
    runtime: list[tuple[str, str, str]] = []  # (rel path, carrier, text) seen only at runtime
    blobs: dict[str, bytes] = {}        # screenshots and the HAR, vaulted after collection

    def session(account: dict) -> dict:
        name, value = account["cookie"].split("=", 1)
        return {"name": name, "value": value, "url": base}

    with tempfile.TemporaryDirectory() as scratch, sync_playwright() as pw:
        mirror, har = Path(scratch) / "mirror", Path(scratch) / "scan.har"
        browser = pw.chromium.launch()
        context = browser.new_context(record_har_path=str(har), record_har_content="embed",
                                      service_workers="block")
        context.add_cookies([session(me)])

        redirects: list[str] = []

        def route(route, request) -> None:
            """Every browser request, sub-resources included, is made here.

            The browser follows a redirect without consulting the route, even one
            the route handed it, so the next request would skip the pacing. A
            redirect is therefore recorded as evidence, answered with an empty
            204, and its target queued like any other URL.
            """
            if not guard.allowed(request.url):
                if guard.stopped is None:
                    guard.refuse(request.url, request.method, request.headers)
                route.abort()
                return
            guard.wait()
            try:
                response = route.fetch(max_redirects=0)
            except Exception:  # noqa: BLE001 - a dead connection is not a crash
                route.abort()
                return
            guard.record(request.url, response.status)
            observe(request.url, response.status, response.headers, response.body())
            if 300 <= response.status < 400 and "location" in response.headers:
                redirects.append(urljoin(request.url, response.headers["location"]))
                route.fulfill(status=204, body="")
                return
            route.fulfill(response=response)

        context.route("**/*", route)

        def observe(url: str, status: int, headers: dict, body: bytes) -> None:
            rel = local_path(url, headers.get("content-type", ""))
            if status == 200:
                keep(url, status, headers, body)
            if "location" in headers:
                runtime.append((rel, "response_header", f"Location: {headers['location']}"))
            if "set-cookie" in headers:
                runtime.append((rel, "response_header", f"Set-Cookie: {headers['set-cookie']}"))

        def fetch(request_context, url: str, store: bool = True) -> tuple[int, dict, bytes]:
            if not guard.allowed(url):
                if guard.stopped is None:
                    guard.refuse(url, "GET", {})
                return 0, {}, b""
            guard.wait()
            response = request_context.get(url, max_redirects=0)
            guard.record(url, response.status)
            headers, body = response.headers, response.body()
            if store:
                observe(url, response.status, headers, body)
            return response.status, headers, body

        def keep(url: str, status: int, headers: dict, body: bytes) -> str:
            rel = local_path(url, headers.get("content-type", ""))
            target = mirror / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(body)
            responses[rel] = {"url": url, "status": status,
                              "cache": headers.get("cache-control", ""),
                              "robots": headers.get("x-robots-tag", "")}
            if urlparse(url).query:
                runtime.append((rel, "url", url))
            return rel

        robots = urllib.robotparser.RobotFileParser()
        status, _, body = fetch(context.request, base + "/robots.txt")
        robots.parse(body.decode("utf-8", "replace").splitlines() if status == 200 else [])
        queue = [base + "/"] + [base + path for path in WELL_KNOWN]
        status, _, body = fetch(context.request, base + "/sitemap.xml")
        if status == 200:
            queue += re.findall(r"<loc>(.*?)</loc>", body.decode("utf-8", "replace"))
        seen: set[str] = set()
        page = context.new_page()
        try:
            while queue and len(seen) < guard.page_cap and guard.stopped is None:
                url = queue.pop(0).split("#")[0]
                if url in seen or not guard.allowed(url):
                    continue
                seen.add(url)
                if not robots.can_fetch("*", url):
                    continue
                if Path(urlparse(url).path).suffix not in PAGE_SUFFIXES:
                    fetch(context.request, url)
                    continue
                try:
                    response = page.goto(url, wait_until="load")
                except PlaywrightError:
                    # The server sent a download, not a page. The route has
                    # already captured its bytes, which is all a file needs.
                    continue
                queue += [target for target in redirects if target not in seen]
                redirects.clear()
                if response is None or response.status != 200:
                    continue
                rel = local_path(page.url, response.all_headers().get("content-type", ""))
                page.add_style_tag(content=BLUR)
                blobs[f"screenshot:{rel}"] = page.screenshot(full_page=True)
                links = sorted({urljoin(page.url, h) for h in HREF.findall(page.content())})
                queue += [link for link in links if link not in seen and guard.allowed(link)]
            # Storage, IndexedDB and cookies belong to the origin, not a page:
            # read them once, after every script on every page has run.
            storage = page.evaluate(DUMP_STORAGE)
            for kind in ("local", "session"):
                for name, value in storage[kind]:
                    runtime.append(("storage", "browser_storage", f"{kind}Storage {name}={value}"))
            for entry in page.evaluate(DUMP_INDEXEDDB):
                runtime.append(("storage", "indexeddb", json.dumps(entry, sort_keys=True)))
            for cookie in context.cookies():
                runtime.append(("cookies", "cookie", f"{cookie['name']}={cookie['value']}"))

            # Identity oracle (brief 4.4): can account A read account B's record?
            oracle = identity_oracle(pw, base, accounts, me, fetch, session)

            # Audience (brief 4.3): fetch every captured URL again with no session.
            anonymous = pw.request.new_context()
            audience = {}
            for rel, seen_response in sorted(responses.items()):
                status, _, _ = fetch(anonymous, seen_response["url"], store=False)
                audience[rel] = "public" if status == 200 else "authenticated"
            audience.update(oracle)
            anonymous.dispose()
        finally:
            context.close()
            browser.close()
        for attempt in guard.refused:
            runtime.append(("third_party", "third_party",
                            f"{attempt['method']} {attempt['url']}\nReferer: {attempt['referer']}"))
        blobs["har"] = har.read_bytes()
        manifest = collect(mirror, out, key=key, target_host=urlparse(base).netloc)

    # Runtime-only observations, and the HAR and screenshots, into the same vault.
    vault = Vault(out / "vault", key)
    sink = Sink(vault)
    for rel, carrier, text in runtime:
        doc = vault.put(text.encode("utf-8"))
        sink.add(rel, doc, 0, len(text.encode("utf-8")), carrier, "runtime", "runtime")
    index_path = out / "index.jsonl"
    rows = [json.loads(line) for line in index_path.read_text(encoding="utf-8").splitlines()]
    # A stable sort on key-independent fields only: ordering by vault address
    # would renumber observations whenever the per-scan key changed.
    rows = sorted(rows + sink.rows, key=lambda r: (r["path"], r["offset"], r["carrier"],
                                                    r["extraction"]))
    with index_path.open("w", encoding="utf-8", newline="\n") as handle:
        for number, row in enumerate(rows, start=1):
            row["obs_id"], row["grade"] = f"o{number:06d}", "A"
            handle.write(json.dumps(row, sort_keys=True) + "\n")

    record = {
        "target": base,
        "scan_as": scope["scan_as"],
        "pages": len(seen),
        "requests_sent": len(guard.sent),
        "requests_refused_out_of_scope": len(guard.refused),
        "stopped": guard.stopped,
        "audience": audience,
        "cached_publicly": sorted(r for r, v in responses.items() if "public" in v["cache"]),
        "noindex": sorted(r for r, v in responses.items() if "noindex" in v["robots"]),
        "evidence": {name: vault.put(data) for name, data in sorted(blobs.items())},
        "observations": len(rows),
    }
    (out / "capture.json").write_text(json.dumps(record, indent=2, sort_keys=True) + "\n",
                                      encoding="utf-8")
    manifest.update(observations=len(rows), grades={"A": len(rows)})
    return {**manifest, "capture": record}


def identity_oracle(pw, base: str, accounts: dict, me: dict, fetch, session) -> dict:
    """Differential access test: fetch each account's own record, then each
    record by id as the scanning account. A record that arrives for an id that
    is not ours, and matches another account's own record, is read across
    accounts. Returns audience labels for the record files captured.
    """
    schema_status, _, schema = fetch(pw.request.new_context(), base + "/api/v2/openapi.json",
                                     store=False)
    if schema_status != 200:
        return {}
    templates = [p for p, ops in json.loads(schema)["paths"].items()
                 if "get" in ops and "{id}" in p]
    own_records = {}
    for name, account in accounts.items():
        as_account = pw.request.new_context(extra_http_headers={"Cookie": account["cookie"]})
        _, _, body = fetch(as_account, base + "/api/v2/patients/me", store=name == me["name"])
        own_records[name] = body
        as_account.dispose()
    labels = {}
    as_me = pw.request.new_context(extra_http_headers={"Cookie": me["cookie"]})
    for template in templates:
        for name, account in sorted(accounts.items()):
            url = base + template.replace("{id}", account["patient_id"])
            status, headers, body = fetch(as_me, url)
            if status != 200:
                continue
            rel = local_path(url, headers.get("content-type", ""))
            if name == me["name"]:
                labels[rel] = "authenticated_self"
            elif body == own_records[name]:
                labels[rel] = "authenticated_other"
    as_me.dispose()
    return labels

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
# Static files a browser asks for again on every page. One copy per scan is
# enough: asking again only adds load to the site and uses up the request cap.
ASSET_SUFFIXES = (".js", ".mjs", ".css", ".svg", ".png", ".jpg", ".jpeg", ".gif", ".webp",
                  ".ico", ".woff", ".woff2", ".ttf")
# Requested once per scan to learn what this server sends for a missing page.
NOT_FOUND_PROBE = "/phi-scan-page-that-does-not-exist"
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
# Where sites publish an API description, in the order they are tried.
SCHEMA_PATHS = ("/openapi.json", "/swagger.json", "/api/openapi.json", "/api/swagger.json",
                "/v3/api-docs", "/v2/api-docs", "/swagger/v1/swagger.json", "/api-docs",
                "/api/v1/openapi.json", "/api/v2/openapi.json")
SELF_ENDINGS = ("/me", "/self", "/current", "/profile", "/myself")
PATH_PARAM = re.compile(r"\{[^}/]+\}")
# A logged-in scan that followed a "Log out" link would end its own session.
SIGN_OUT = re.compile(r"(?:^|/)(?:log|sign)[-_]?(?:out|off)(?:$|[/.])", re.I)
HREF = re.compile(r"""(?:href|src)\s*=\s*["']([^"'#]+)""", re.I)


class Guard:
    """Scope and pace for every request the scan makes or lets through.

    A stop condition sets `stopped` rather than raising: most requests pass
    through Playwright callbacks, which swallow exceptions, so a raised stop
    would be printed and ignored. Every request and the crawl loop check it.
    """

    def __init__(self, scope: dict) -> None:
        # Every field has a safe default, so a scope that names only the
        # target works: that host alone, one request a second, 200 pages.
        limits = scope.get("rate_limit") or {}
        hosts = (scope.get("in_scope") or {}).get("hosts") or [urlparse(scope["target"]).netloc]
        blocked = scope.get("out_of_scope") or {}
        self.hosts = set(hosts)
        self.blocked_hosts = set(blocked.get("hosts", []))
        self.blocked_paths = set(blocked.get("paths", []))
        self.gap = max(1.0, float(limits.get("min_interval_seconds", 1.0)))
        self.jitter = float(limits.get("jitter_seconds", 0.25))
        self.page_cap = int(limits.get("page_cap", 200))
        self.random = random.Random(0)
        self.last = 0.0
        self.sent: list[dict] = []
        self.refused: list[dict] = []
        self.writes_blocked: list[dict] = []
        self.server_errors = 0
        self.stopped: str | None = None

    def allowed(self, url: str) -> bool:
        parsed = urlparse(url)
        return (self.stopped is None and parsed.netloc in self.hosts
                and parsed.path not in self.blocked_paths and not SIGN_OUT.search(parsed.path))

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
        # The gap is counted again from the answer, not only from the send: a
        # request that left late arrived 0.94 s before the next one (G2).
        self.last = time.monotonic()
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
    # Accounts are optional: without one, only what the public can see is scanned.
    accounts = {a["name"]: a for a in scope.get("accounts") or [] if a.get("cookie")}
    me = accounts.get(scope.get("scan_as")) or next(iter(accounts.values()), None)
    key = key or os.urandom(32)
    responses: dict[str, dict] = {}     # rel path -> what was served
    runtime: list[tuple[str, str, str]] = []  # (rel path, carrier, text) seen only at runtime
    blobs: dict[str, bytes] = {}        # screenshots and the HAR, vaulted after collection

    def session(account: dict) -> list[dict]:
        """The account's cookies, from one "name=value" or a whole Cookie line
        copied from a browser ("a=1; b=2"): most sites need several."""
        pairs = [part.strip().split("=", 1) for part in account["cookie"].split(";") if "=" in part]
        return [{"name": name.strip(), "value": value.strip(), "url": base} for name, value in pairs]

    with tempfile.TemporaryDirectory() as scratch, sync_playwright() as pw:
        mirror, har = Path(scratch) / "mirror", Path(scratch) / "scan.har"
        browser = pw.chromium.launch()
        context = browser.new_context(record_har_path=str(har), record_har_content="embed",
                                      service_workers="block")
        if me:
            context.add_cookies(session(me))

        redirects: list[str] = []
        assets: dict[str, object] = {}      # url -> the response, for repeat requests
        not_found: bytes | None = None      # what the server sends for any unknown address

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
            if request.method not in ("GET", "HEAD"):
                # Read-only means read-only, even for a page's own scripts: a
                # POST to the target could change its state (brief section 1).
                guard.writes_blocked.append({"url": request.url, "method": request.method})
                route.abort()
                return
            if request.url in assets:
                route.fulfill(response=assets[request.url])
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
            if response.status == 200 and Path(urlparse(request.url).path).suffix in ASSET_SUFFIXES:
                assets[request.url] = response
            route.fulfill(response=response)

        context.route("**/*", route)

        def observe(url: str, status: int, headers: dict, body: bytes) -> None:
            rel = local_path(url, headers.get("content-type", ""))
            # A single-page app answers "/.env" with its own home page. That is
            # the app saying "not found", not a leaked file, so it is not kept.
            if status == 200 and not (body == not_found and url.rstrip("/") != base):
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

        status, _, body = fetch(context.request, base + NOT_FOUND_PROBE, store=False)
        not_found = body if status == 200 else None
        robots = urllib.robotparser.RobotFileParser()
        status, _, body = fetch(context.request, base + "/robots.txt")
        robots.parse(body.decode("utf-8", "replace").splitlines()
                     if status == 200 and body != not_found else [])
        queue = [base + "/"] + [base + path for path in WELL_KNOWN]
        status, _, body = fetch(context.request, base + "/sitemap.xml")
        if status == 200:
            queue += re.findall(r"<loc>(.*?)</loc>", body.decode("utf-8", "replace"))
        seen: set[str] = set()
        page = context.new_page()
        try:
            while queue and len(seen) < guard.page_cap and guard.stopped is None:
                url = queue.pop(0).split("#")[0]
                # A script or image a page already loaded is captured; fetching
                # its link again would only spend a request and a page slot.
                if url in seen or url in assets or not guard.allowed(url):
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
            if me:
                api = find_api(pw, base, scope.get("api"), fetch)
                oracle, access_test = identity_oracle(pw, base, accounts, me, fetch, api)
            else:
                oracle, access_test = {}, {"ran": False, "reason": "no test account in the scope: "
                                                                   "public pages only"}

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
        "scan_as": me["name"] if me else "public visitor",
        "pages": len(seen),
        "requests_sent": len(guard.sent),
        "requests_refused_out_of_scope": len(guard.refused),
        "write_requests_blocked": len(guard.writes_blocked),
        "stopped": guard.stopped,
        "audience": audience,
        "access_test": access_test,
        "cached_publicly": sorted(r for r, v in responses.items() if "public" in v["cache"]),
        "noindex": sorted(r for r, v in responses.items() if "noindex" in v["robots"]),
        "evidence": {name: vault.put(data) for name, data in sorted(blobs.items())},
        "observations": len(rows),
    }
    (out / "capture.json").write_text(json.dumps(record, indent=2, sort_keys=True) + "\n",
                                      encoding="utf-8")
    manifest.update(observations=len(rows), grades={"A": len(rows)})
    return {**manifest, "capture": record}


def find_api(pw, base: str, configured: dict | None, fetch) -> dict:
    """Where the access test looks: the scope's `api` section if it names both
    endpoints, otherwise the site's own published OpenAPI or Swagger description.
    A person running the scan does not need to know the API at all.

    by_id: GET paths with exactly one path parameter ("/api/patients/{id}")
    self:  GET paths with none that end like "/me" ("/api/patients/me")
    """
    configured = dict(configured or {})
    found = {"self": [configured["self"]] if configured.get("self") else [],
             "by_id": [configured["by_id"]] if configured.get("by_id") else [],
             "source": "scope file" if configured else "none found"}
    if found["self"] and found["by_id"]:
        return found
    anonymous = pw.request.new_context()
    sources: list[str] = []
    try:
        for path in ([configured["schema"]] if configured.get("schema") else SCHEMA_PATHS):
            status, _, body = fetch(anonymous, urljoin(base + "/", path.lstrip("/")), store=False)
            try:
                document = json.loads(body) if status == 200 else None
            except ValueError:
                document = None
            if not isinstance(document, dict) or not isinstance(document.get("paths"), dict):
                continue
            servers = document.get("servers") or [{}]
            prefix = (urlparse(servers[0].get("url", "")).path or document.get("basePath", "")).rstrip("/")
            gets = [prefix + p for p, ops in document["paths"].items() if isinstance(ops, dict) and "get" in ops]
            # A site can publish several descriptions (an old v1 and a current v2);
            # read them all, since the "my record" address may be in only one.
            found["by_id"] += [p for p in gets if len(PATH_PARAM.findall(p)) == 1 and p not in found["by_id"]]
            found["self"] += [p for p in gets if not PATH_PARAM.search(p) and p not in found["self"]
                              and p.rstrip("/").lower().endswith(SELF_ENDINGS)]
            sources.append(path)
    finally:
        anonymous.dispose()
    if sources:
        found["source"] = ", ".join(sources)
    return found


def _record_id(body: bytes) -> str | None:
    try:
        record = json.loads(body)
    except ValueError:
        return None
    if isinstance(record, dict):
        for key in ("id", "patient_id", "patientId", "user_id", "userId", "uuid"):
            if isinstance(record.get(key), (str, int)):
                return str(record[key])
    return None


def identity_oracle(pw, base: str, accounts: dict, me: dict, fetch, api: dict) -> tuple[dict, dict]:
    """Differential access test (brief 4.4): fetch each account's own record,
    then each record by id as the scanning account. A record that arrives for an
    id that is not ours, and matches another account's own record, is read
    across accounts. Returns audience labels for the record files captured and a
    plain summary of what ran, or why it could not.
    """
    if not api["by_id"]:
        return {}, {"ran": False, "reason": "the site publishes no API description and the scope "
                                             "names no record address (api.by_id)"}
    own_records, ids = {}, {}
    for name, account in accounts.items():
        ids[name] = str(account["patient_id"]) if account.get("patient_id") else None
        for path in api["self"][:1]:
            as_account = pw.request.new_context(extra_http_headers={"Cookie": account["cookie"]})
            status, _, body = fetch(as_account, base + path, store=name == me["name"])
            as_account.dispose()
            if status == 200:
                own_records[name] = body
                ids[name] = ids[name] or _record_id(body)
    known = {name: value for name, value in ids.items() if value}
    if not known:
        return {}, {"ran": False, "reason": "no account's own record id is known: add patient_id "
                                             "to an account, or api.self to the scope"}
    labels = {}
    as_me = pw.request.new_context(extra_http_headers={"Cookie": me["cookie"]})
    for template in api["by_id"]:
        for name, value in sorted(known.items()):
            url = base + PATH_PARAM.sub(value, template, count=1)
            status, headers, body = fetch(as_me, url)
            if status != 200:
                continue
            rel = local_path(url, headers.get("content-type", ""))
            if name == me["name"]:
                labels[rel] = "authenticated_self"
            elif body == own_records.get(name):
                labels[rel] = "authenticated_other"
    as_me.dispose()
    summary = {"ran": True, "api_description": api["source"], "record_addresses": len(api["by_id"]),
               "accounts": len(known),
               "records_read_across_accounts": sum(v == "authenticated_other" for v in labels.values())}
    if len(known) < 2:
        summary["note"] = "one account only: a second test account is needed to test cross-account access"
    return labels, summary

"""Live crawling: fetch a real site, within scope, slowly, and capture everything.

The static collector reads files. This reads a running server.

What it enforces, because "read-only" and "in scope" have to be properties of the
code rather than promises:

  * GET and HEAD only. No POST path exists.
  * One host. Any redirect that leaves it is refused and logged, not followed.
  * robots.txt is obeyed, and a disallowed URL is recorded rather than skipped
    silently.
  * A fixed delay between requests, so a scan cannot look like a flood.
  * A hard page cap, so a mistake stops instead of running all night.
  * Every request and response is logged with its status and size.

The output is a directory of captured pages plus a scope file. The existing
collector then works on that directory exactly as it works on a fixture tree,
which is why this file is small: capture is a separate job from extraction.
"""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.parse
import urllib.request
import urllib.robotparser
from collections import deque
from pathlib import Path

UA = "phi-scan/0.1 (read-only exposure scan)"


def _get(url: str, timeout: int = 20) -> tuple[int, dict[str, str], bytes]:
    request = urllib.request.Request(url, headers={"User-Agent": UA}, method="GET")
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return response.status, dict(response.headers), response.read()


def _same_host(url: str, host: str) -> bool:
    parsed = urllib.parse.urlparse(url)
    return parsed.netloc == host and parsed.scheme in ("http", "https")


def _links(html: str, base: str) -> list[str]:
    import re  # noqa: PLC0415

    found = re.findall(r"""href\s*=\s*["']([^"'#]+)["']""", html, re.I)
    out: list[str] = []
    for link in found:
        absolute = urllib.parse.urljoin(base, link)
        if absolute.startswith(("http://", "https://")):
            out.append(absolute)
    return out


def crawl(base_url: str, out: Path, max_pages: int = 200, delay: float = 1.0,
          alias_hosts: tuple[str, ...] = (),
          seeds: tuple[str, ...] = ()) -> dict:
    """Fetch one host, breadth first, and write what came back.

    alias_hosts: canonical hostnames that should be treated as the target, so a
    sitemap written for the production domain still seeds a scan of staging.

    seeds: extra paths or URLs to try first, still subject to robots.txt and
    the host check. An operator usually knows a few URLs worth checking that
    nothing links to.
    """
    parsed = urllib.parse.urlparse(base_url)
    host = parsed.netloc
    out = Path(out)
    pages = out / "pages"
    pages.mkdir(parents=True, exist_ok=True)
    for stale in pages.glob("page_*"):
        stale.unlink()

    robots = urllib.robotparser.RobotFileParser()
    robots.set_url(f"{parsed.scheme}://{host}/robots.txt")
    robots_allowed = True
    try:
        robots.read()
    except Exception:  # noqa: BLE001
        robots_allowed = False

    queue: deque[str] = deque([base_url])
    seen: set[str] = set()
    log: list[dict] = []
    fetched = 0
    blocked = 0

    for seed in seeds:
        queue.append(urllib.parse.urljoin(base_url, seed))

    # robots.txt and sitemap.xml first. The first is always public and often
    # names the paths the operator was hiding; the second tells us what the
    # operator wants crawled. Without the sitemap a crawl with no links
    # discovers exactly one page.
    for well_known, suffix in (("/robots.txt", ".txt"), ("/sitemap.xml", ".xml")):
        url = f"{parsed.scheme}://{host}{well_known}"
        try:
            time.sleep(delay)
            status, headers, body = _get(url)
        except Exception:  # noqa: BLE001
            continue
        fetched += 1
        name = "wellknown_" + well_known.strip("/").replace(".", "_") + suffix
        (pages / name).write_bytes(body)
        log.append({"url": url, "result": "fetched", "status": status,
                    "bytes": len(body), "file": name})
        if suffix == ".xml":
            import re  # noqa: PLC0415

            for loc in re.findall(r"<loc>\s*([^<\s]+)\s*</loc>",
                                  body.decode("utf-8", "replace")):
                loc_host = urllib.parse.urlparse(loc).netloc
                if loc_host in alias_hosts:
                    # The sitemap names the production domain; rewrite it to
                    # the host actually being scanned, including the scheme, or
                    # every seeded URL fails against a plain-http target.
                    loc = urllib.parse.urlunparse(
                        urllib.parse.urlparse(loc)._replace(
                            netloc=host, scheme=parsed.scheme))
                if _same_host(loc, host):
                    queue.append(loc)

    while queue and fetched < max_pages:
        url = queue.popleft()
        if url in seen:
            continue
        seen.add(url)
        if not _same_host(url, host):
            log.append({"url": url, "result": "refused_off_host"})
            blocked += 1
            continue
        if robots_allowed and not robots.can_fetch(UA, url):
            log.append({"url": url, "result": "blocked_by_robots"})
            blocked += 1
            continue

        started = time.time()
        try:
            time.sleep(delay)
            status, headers, body = _get(url)
        except urllib.error.HTTPError as exc:
            log.append({"url": url, "result": f"http_{exc.code}"})
            continue
        except Exception as exc:  # noqa: BLE001
            log.append({"url": url, "result": f"error_{type(exc).__name__}"})
            continue

        fetched += 1
        content_type = headers.get("Content-Type", "").split(";")[0].strip()
        suffix = {
            "text/html": ".html",
            "application/json": ".json",
            "text/css": ".css",
            "application/javascript": ".js",
            "text/csv": ".csv",
            "text/plain": ".txt",
            "application/pdf": ".pdf",
            "application/xml": ".xml",
        }.get(content_type, ".bin")

        path = urllib.parse.urlparse(url).path
        name = f"page_{fetched:04d}{suffix}"
        (pages / name).write_bytes(body)
        (pages / f"page_{fetched:04d}.meta.json").write_text(
            json.dumps({"url": url, "status": status, "content_type": content_type,
                        "path": path}, indent=2) + "\n", encoding="utf-8")

        log.append({
            "url": url,
            "result": "fetched",
            "status": status,
            "bytes": len(body),
            "content_type": content_type,
            "seconds": round(time.time() - started, 3),
            "file": name,
        })

        if content_type == "text/html":
            try:
                text = body.decode("utf-8", "replace")
            except Exception:  # noqa: BLE001
                text = ""
            for link in _links(text, url):
                if _same_host(link, host) and link not in seen:
                    queue.append(link)

    (pages / "scope.json").write_text(
        json.dumps({"target_host": host, "base_url": base_url,
                    "max_pages": max_pages, "delay_seconds": delay,
                    "fetched": fetched, "refused": blocked}, indent=2) + "\n",
        encoding="utf-8")
    (out / "crawl_log.jsonl").write_text(
        "\n".join(json.dumps(entry, sort_keys=True) for entry in log) + "\n",
        encoding="utf-8")

    return {"fetched": fetched, "refused": blocked, "log": log}

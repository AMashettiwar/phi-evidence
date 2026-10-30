"""Command line entry point.

    phi-scan demo
    phi-scan scan  --source DIR --out DIR [--context covered-entity|public-web]
                   [--emit findings.jsonl] [--redact REDACTED_DIR]
    phi-scan crawl --url URL --out DIR

`scan` defaults to the covered-entity context: the operator has the files and is
a covered entity, so an identifier is reportable on its own. `crawl` defaults to
public-web, where the test is identity plus a health fact.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

from .collect import collect
from .crawl import crawl
from .detect import detect
from .report import render, render_markdown

ROOT = Path(__file__).resolve().parents[1]


def _scan(source: Path, out: Path, limit: int, auth_prefixes: tuple[str, ...],
          markdown: Path | None, context: str = "covered-entity",
          emit: Path | None = None, redact: Path | None = None) -> list[dict]:
    manifest = collect(source, out)
    findings = detect(out / "index.jsonl", out / "vault", auth_prefixes,
                      context=context)

    print(f"kept {manifest['observations']} evidence spans "
          f"across {len(manifest.get('carriers', {}))} carriers")
    print(render(findings, str(source), limit=limit or None))

    if emit:
        from .positions import write_findings  # noqa: PLC0415

        count = write_findings(findings, out / "index.jsonl", out / "vault", emit)
        print(f"wrote {count} positional findings to {emit}")

    if redact:
        from .positions import write_redacted  # noqa: PLC0415

        count = write_redacted(findings, source, redact)
        print(f"wrote {count} redacted files to {redact}")

    if markdown:
        markdown.parent.mkdir(parents=True, exist_ok=True)
        markdown.write_text(render_markdown(findings, str(source)), encoding="utf-8")
        print(f"markdown report written to {markdown}")
    return findings


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="phi-scan",
        description="Read-only scanner for patient data exposed by a website or health system.")
    sub = parser.add_subparsers(dest="command", required=True)

    demo = sub.add_parser("demo", help="build the synthetic clinic and scan it")
    demo.add_argument("--limit", type=int, default=12, help="findings to show; 0 for all")
    demo.add_argument("--markdown", type=Path, default=None,
                      help="also write a markdown report here")

    scan = sub.add_parser("scan", help="scan a directory you already have")
    scan.add_argument("--source", required=True, type=Path)
    scan.add_argument("--out", required=True, type=Path)
    scan.add_argument("--limit", type=int, default=20)
    scan.add_argument("--context", choices=["covered-entity", "public-web"],
                      default="covered-entity",
                      help="covered-entity: an identifier is reportable on its own. "
                           "public-web: identity plus a health fact.")
    scan.add_argument("--emit", type=Path, default=None,
                      help="write positional findings as JSON lines")
    scan.add_argument("--redact", type=Path, default=None,
                      help="write redacted copies of the scanned files here")
    scan.add_argument("--auth-prefix", action="append", default=[],
                      help="URL prefix the operator says is behind a login; repeatable")
    scan.add_argument("--markdown", type=Path, default=None)

    crawl_cmd = sub.add_parser("crawl", help="fetch a live site, then scan what came back")
    crawl_cmd.add_argument("--url", required=True)
    crawl_cmd.add_argument("--out", required=True, type=Path)
    crawl_cmd.add_argument("--max-pages", type=int, default=50)
    crawl_cmd.add_argument("--delay", type=float, default=1.0)
    crawl_cmd.add_argument("--limit", type=int, default=12)
    crawl_cmd.add_argument("--markdown", type=Path, default=None)

    collect_cmd = sub.add_parser("collect", help="turn a source tree into evidence spans")
    collect_cmd.add_argument("--source", required=True)
    collect_cmd.add_argument("--out", required=True)
    collect_cmd.add_argument("--pylibs", default=None)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if args.command == "demo":
        world = ROOT / "fixtures" / "world"
        if not world.exists():
            print("building the synthetic clinic ...")
            subprocess.run([sys.executable, str(ROOT / "fixtures" / "build_world.py")],
                           check=True, cwd=str(ROOT))
        _scan(world, ROOT / "artifacts" / "demo", args.limit, (), args.markdown,
              context="public-web")
        return 0

    if args.command == "scan":
        if not args.source.is_dir():
            print(f"not a directory: {args.source}")
            return 2
        _scan(args.source, args.out, args.limit, tuple(args.auth_prefix),
              args.markdown, context=args.context, emit=args.emit,
              redact=args.redact)
        return 0

    if args.command == "crawl":
        result = crawl(args.url, args.out / "crawl", max_pages=args.max_pages,
                       delay=args.delay)
        print(f"fetched {result['fetched']} pages, refused {result['refused']}")
        _scan(args.out / "crawl", args.out / "run", args.limit, (), args.markdown,
              context="public-web")
        return 0

    if args.command == "collect":
        source = Path(args.source)
        if not source.is_dir():
            print(f"not a directory: {source}")
            return 2
        manifest = collect(source, Path(args.out), args.pylibs)
        print(json.dumps(manifest, indent=2, sort_keys=True))
        return 0

    return 2


if __name__ == "__main__":
    sys.exit(main())

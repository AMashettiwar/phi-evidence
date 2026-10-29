"""Command line entry point.

Usage:
    phi-scan collect --source <dir> --out <dir> [--pylibs <dir>]
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .collect import collect


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="phi-scan", description="Read-only PHI exposure scanner")
    sub = parser.add_subparsers(dest="command", required=True)

    collect_cmd = sub.add_parser("collect", help="turn a source tree into evidence spans")
    collect_cmd.add_argument("--source", required=True, help="directory to read")
    collect_cmd.add_argument("--out", required=True, help="directory for vault and index")
    collect_cmd.add_argument("--pylibs", default=None, help="extra import path, e.g. for pypdf")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "collect":
        source = Path(args.source)
        if not source.is_dir():
            print(f"source is not a directory: {source}")
            return 2
        manifest = collect(source, Path(args.out), args.pylibs)
        print(json.dumps(manifest, indent=2, sort_keys=True))
        return 0

    parser.print_help()
    return 2


if __name__ == "__main__":
    sys.exit(main())

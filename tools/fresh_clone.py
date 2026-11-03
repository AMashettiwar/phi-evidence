#!/usr/bin/env python3
"""M9: everything again, from nothing but the repository.

Clones the committed HEAD into a fresh directory, builds a new virtual
environment from requirements.lock alone, installs Chromium, runs every gate,
and compares the clone's acceptance table with the committed eval/results.json.
The Docker daemon was unreachable on the build machine, so a fresh clone and a
fresh venv stand in for a fresh container (tasks/todo.md).

GROQ_API_KEY is passed through from the environment or this checkout's .env,
because the clone has no .env of its own.

Run:  python tools/fresh_clone.py [target-directory]
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from phi_scan.ai import groq_key  # noqa: E402


def run(command: list[str], cwd: Path, env: dict | None = None) -> int:
    print("$", " ".join(command), flush=True)
    return subprocess.run(command, cwd=cwd, env=env).returncode


def main() -> int:
    # A short path: Windows refuses a working directory past 260 characters.
    target = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(tempfile.gettempdir()) / "phi-fresh"
    shutil.rmtree(target, ignore_errors=True)
    if run(["git", "clone", "-q", str(ROOT), str(target)], ROOT):
        return 1
    base = getattr(sys, "_base_executable", sys.executable)
    if run([base, "-m", "venv", ".venv"], target):
        return 1
    python = str(target / ".venv" / ("Scripts/python.exe" if os.name == "nt" else "bin/python"))
    for step in ([python, "-m", "pip", "install", "-q", "--upgrade", "pip"],
                 [python, "-m", "pip", "install", "-q", "-r", "requirements.lock"],
                 [python, "-m", "playwright", "install", "chromium"]):
        if run(step, target):
            return 1
    env = dict(os.environ)
    key = groq_key(ROOT)
    if key:
        env["GROQ_API_KEY"] = key
    gates = run([python, "tools/run_gates.py"], target, env)

    ours = json.loads((ROOT / "eval" / "results.json").read_text(encoding="utf-8"))["acceptance"]
    theirs = json.loads((target / "eval" / "results.json").read_text(encoding="utf-8"))["acceptance"]
    same = [(a["criterion"], a["value"]) for a in ours] == [(b["criterion"], b["value"]) for b in theirs]
    print(f"\nfresh clone gates exit {gates}; acceptance table identical to the committed one: {same}")
    if not same:
        for a, b in zip(ours, theirs):
            if a != b:
                print(f"  committed {a['criterion']}: {a['value']}\n  clone     {b['criterion']}: {b['value']}")
    return 0 if same else 1


if __name__ == "__main__":
    sys.exit(main())

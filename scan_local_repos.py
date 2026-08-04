#!/usr/bin/env python3
"""
Discover locally cloned Git repos under one or more directories and run an
incident hunter script against each repo (default: the TanStack hunter).
"""

import argparse
import hashlib
import os
import subprocess
import sys
from pathlib import Path


SCRIPT_DIR = Path(__file__).resolve().parent
DEFAULT_HUNTER = SCRIPT_DIR / "hunt_tanstack_2026_05.py"
SKIP_DISCOVERY_DIRS = {".git", "node_modules", "__pycache__"}


def discover_repos(roots, include_scanner_repo=False):
    repos = []
    seen = set()
    scanner_repo = SCRIPT_DIR.resolve()

    for root in roots:
        for current, dirnames, filenames in os.walk(root):
            current_path = Path(current)
            if ".git" in dirnames or ".git" in filenames:
                resolved = current_path.resolve()
                if include_scanner_repo or resolved != scanner_repo:
                    key = str(resolved)
                    if key not in seen:
                        repos.append(resolved)
                        seen.add(key)
                dirnames[:] = []
                continue

            dirnames[:] = [name for name in dirnames if name not in SKIP_DISCOVERY_DIRS]

    return repos


def log_path_for(logs_dir, repo):
    digest = hashlib.sha256(str(repo).encode("utf-8")).hexdigest()[:12]
    safe_name = "".join(char if char.isalnum() or char in "._-" else "_" for char in repo.name)
    return logs_dir / f"{safe_name}-{digest}.log"


def run_hunter(hunter, repo, max_file_mb, hunter_args):
    command = [
        sys.executable,
        str(hunter),
        "--root",
        str(repo),
        "--max-file-mb",
        str(max_file_mb),
        *hunter_args,
    ]
    return subprocess.run(
        command,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )


def print_block(text, indent="    "):
    stripped = text.strip()
    if not stripped:
        print(f"{indent}<no output>")
        return
    for line in stripped.splitlines():
        print(f"{indent}{line}")


def parse_args(argv):
    parser = argparse.ArgumentParser(
        description="Recursively find local Git repos and run an incident hunter on each one."
    )
    parser.add_argument(
        "directories",
        nargs="+",
        help="One or more directories to recursively search for Git repos.",
    )
    parser.add_argument(
        "--hunter",
        default=str(DEFAULT_HUNTER),
        help="Hunter script to run per repo. Default: hunt_tanstack_2026_05.py.",
    )
    parser.add_argument(
        "--hunter-arg",
        action="append",
        default=[],
        help="Extra argument passed to the hunter (repeatable), e.g. --hunter-arg=--bad-file --hunter-arg=FILE.",
    )
    parser.add_argument(
        "--logs-dir",
        default="hunt-logs",
        help="Directory for per-repo hunter logs. Default: hunt-logs.",
    )
    parser.add_argument(
        "--max-file-mb",
        type=int,
        default=10,
        help="Maximum size for text IOC scanning per file. Default: 10.",
    )
    parser.add_argument(
        "--include-scanner-repo",
        action="store_true",
        help="Include this scanner repo if it appears under an input directory.",
    )
    return parser.parse_args(argv)


def main(argv=None):
    args = parse_args(sys.argv[1:] if argv is None else argv)

    roots = []
    invalid = []
    for directory in args.directories:
        root = Path(directory).expanduser().resolve()
        if root.is_dir():
            roots.append(root)
        else:
            invalid.append(root)

    if invalid:
        for root in invalid:
            print(f"Error: not a directory: {root}", file=sys.stderr)
        return 2

    hunter = Path(args.hunter).expanduser().resolve()
    if not hunter.is_file():
        print(f"Error: hunter script not found: {hunter}", file=sys.stderr)
        return 2

    logs_dir = Path(args.logs_dir).expanduser().resolve()
    logs_dir.mkdir(parents=True, exist_ok=True)

    repos = discover_repos(roots, include_scanner_repo=args.include_scanner_repo)
    findings = []
    errors = []

    for repo in repos:
        result = run_hunter(hunter, repo, args.max_file_mb, args.hunter_arg)
        repo_log = log_path_for(logs_dir, repo)
        repo_log.write_text(result.stdout, encoding="utf-8")

        # Hunter exit-code contract: 0 clean, 1 critical findings, 3 warnings only.
        if result.returncode in (1, 3):
            findings.append((repo, repo_log, result.stdout))
        elif result.returncode != 0:
            errors.append((repo, repo_log, result.returncode, result.stdout))

    print("LOCAL REPO SCAN SUMMARY")
    print("=======================")
    print(f"Hunter: {hunter}")
    print("Input directories:")
    for root in roots:
        print(f"- {root}")
    print(f"Repos discovered:  {len(repos)}")
    print(f"Repos with hits:   {len(findings)}")
    print(f"Scan errors:       {len(errors)}")
    print(f"Per-repo logs:     {logs_dir}")

    if findings:
        print()
        print("FINDINGS")
        for repo, repo_log, output in findings:
            print(f"- {repo}")
            print(f"  log: {repo_log}")
            print_block(output)

    if errors:
        print()
        print("SCAN ERRORS")
        for repo, repo_log, returncode, output in errors:
            print(f"- {repo}")
            print(f"  exit status: {returncode}")
            print(f"  log: {repo_log}")
            print_block(output)

    if errors:
        return 2
    if findings:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())

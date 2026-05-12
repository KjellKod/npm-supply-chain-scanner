#!/usr/bin/env python3
"""
Discover locally cloned Git repos under one or more directories and run the
TanStack incident hunter against each repo.
"""

import argparse
import hashlib
import os
import subprocess
import sys
from pathlib import Path


SCRIPT_DIR = Path(__file__).resolve().parent
HUNTER = SCRIPT_DIR / "hunt_tanstack_2026_05.py"
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


def run_hunter(repo, max_file_mb):
    command = [
        sys.executable,
        str(HUNTER),
        "--root",
        str(repo),
        "--max-file-mb",
        str(max_file_mb),
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
        description="Recursively find local Git repos and run the TanStack incident hunter on each one."
    )
    parser.add_argument(
        "directories",
        nargs="+",
        help="One or more directories to recursively search for Git repos.",
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

    logs_dir = Path(args.logs_dir).expanduser().resolve()
    logs_dir.mkdir(parents=True, exist_ok=True)

    repos = discover_repos(roots, include_scanner_repo=args.include_scanner_repo)
    findings = []
    errors = []

    for repo in repos:
        result = run_hunter(repo, args.max_file_mb)
        repo_log = log_path_for(logs_dir, repo)
        repo_log.write_text(result.stdout, encoding="utf-8")

        if result.returncode == 1:
            findings.append((repo, repo_log, result.stdout))
        elif result.returncode != 0:
            errors.append((repo, repo_log, result.returncode, result.stdout))

    print("TANSTACK LOCAL REPO SCAN SUMMARY")
    print("================================")
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

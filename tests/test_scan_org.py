"""
Tests for scan_org.sh using stubbed `gh` and `git` executables on PATH.

These cover the org-listing paths that cannot be exercised against real
GitHub: archived-repo labelling, --skip-archived, repo-description sweeps,
and the error paths where a silent "clean" result would be dangerous.
"""

import json
import os
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
BAD_FILE = REPO_ROOT / "2026-08-shai-hulud-here-we-go-again.txt"
IOC_FILE = REPO_ROOT / "2026-08-shai-hulud-iocs.tsv"

GH_STUB = r"""#!/bin/bash
# Stub gh. Repo list comes from GH_STUB_REPOS as "name|description|archived;..."
case "$1" in
  auth) exit 0 ;;
  repo)
    case "$2" in
      list)
        [[ "${GH_STUB_FAIL:-0}" == "1" ]] && exit 1
        IFS=';' read -ra entries <<< "${GH_STUB_REPOS:-}"
        for entry in "${entries[@]+"${entries[@]}"}"; do
          [[ -z "$entry" ]] && continue
          IFS='|' read -r name desc archived <<< "$entry"
          printf '%s\t%s\t%s\n' "$name" "$desc" "${archived:-false}"
        done
        exit 0 ;;
      view)
        target="${3##*/}"
        IFS=';' read -ra entries <<< "${GH_STUB_REPOS:-}"
        for entry in "${entries[@]+"${entries[@]}"}"; do
          IFS='|' read -r name desc archived <<< "$entry"
          if [[ "$name" == "$target" ]]; then
            printf '%s\n' "${archived:-false}"
            exit 0
          fi
        done
        printf 'false\n'
        exit 0 ;;
    esac ;;
esac
exit 0
"""

GIT_STUB = r"""#!/bin/bash
# Stub git. `clone` materializes a checkout whose package.json comes from
# GIT_STUB_PKG; `-C ... log` yields no commits.
if [[ "$1" == "clone" ]]; then
  dest=""
  for arg in "$@"; do dest="$arg"; done
  mkdir -p "$dest"
  printf '%s' "${GIT_STUB_PKG:-{\}}" > "$dest/package.json"
  exit 0
fi
exit 0
"""


def write_stub(directory, name, body):
    path = directory / name
    path.write_text(body, encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return path


class ScanOrgTests(unittest.TestCase):
    def run_scan_org(self, *args, repos="", pkg=None, gh_fail=False):
        with tempfile.TemporaryDirectory() as td:
            stubs = Path(td) / "bin"
            stubs.mkdir()
            write_stub(stubs, "gh", GH_STUB)
            write_stub(stubs, "git", GIT_STUB)

            env = dict(os.environ)
            env["PATH"] = f"{stubs}{os.pathsep}{env['PATH']}"
            env["GH_STUB_REPOS"] = repos
            env["GH_STUB_PKG"] = json.dumps(pkg if pkg is not None else {"name": "clean"})
            env["GIT_STUB_PKG"] = env["GH_STUB_PKG"]
            if gh_fail:
                env["GH_STUB_FAIL"] = "1"

            return subprocess.run(
                ["bash", str(REPO_ROOT / "scan_org.sh"), *args],
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                env=env,
                cwd=str(REPO_ROOT),
            )

    def scan_flags(self):
        return ["--bad-file", str(BAD_FILE), "--ioc-file", str(IOC_FILE)]

    def test_archived_repos_are_scanned_and_tagged_by_default(self):
        result = self.run_scan_org(
            *self.scan_flags(),
            "testorg",
            repos="live|a normal repo|false;attic|an old repo|true",
        )

        self.assertEqual(0, result.returncode, result.stdout)
        self.assertIn("Archived repos: 1 (scanned and tagged", result.stdout)
        self.assertIn("testorg/attic (archived)", result.stdout)
        self.assertIn("testorg/live ", result.stdout)
        self.assertIn("Total repos scanned: 2", result.stdout)

    def test_skip_archived_excludes_them_and_reports_the_count(self):
        result = self.run_scan_org(
            *self.scan_flags(),
            "--skip-archived",
            "testorg",
            repos="live|a normal repo|false;attic|an old repo|true",
        )

        self.assertEqual(0, result.returncode, result.stdout)
        self.assertIn("Archived repos: 1 (skipping", result.stdout)
        self.assertIn("SKIP: archived repo (--skip-archived)", result.stdout)
        self.assertIn("Total repos scanned: 1", result.stdout)
        self.assertIn("Skipped (archived):  1", result.stdout)

    def test_archived_tag_carries_into_findings_summary(self):
        result = self.run_scan_org(
            *self.scan_flags(),
            "testorg",
            repos="attic|an old repo|true",
            pkg={"name": "victim", "dependencies": {"keyv": "6.0.0"}},
        )

        self.assertEqual(1, result.returncode, result.stdout)
        self.assertIn("Repos with critical hits: 1", result.stdout)
        self.assertIn("- attic (archived)", result.stdout)

    def test_warning_only_repo_does_not_count_as_a_hit(self):
        result = self.run_scan_org(
            *self.scan_flags(),
            "testorg",
            repos="noisy|has a legit setup script|false",
            pkg={"name": "legit", "scripts": {"preinstall": "node check-versions.js"}},
        )

        self.assertEqual(3, result.returncode, result.stdout)
        self.assertIn("Repos with critical hits: 0", result.stdout)
        self.assertIn("Repos with warnings only: 1", result.stdout)

    def test_suspicious_repo_description_is_reported_and_fails(self):
        result = self.run_scan_org(
            *self.scan_flags(),
            "testorg",
            repos="exfil|Shai-Hulud: Here We Go Again|false",
        )

        self.assertEqual(1, result.returncode, result.stdout)
        self.assertIn("SUSPICIOUS REPO DESCRIPTION: exfil", result.stdout)
        self.assertIn("Suspicious repo descriptions: 1", result.stdout)

    def test_repo_list_failure_is_an_error_not_a_clean_scan(self):
        result = self.run_scan_org(*self.scan_flags(), "testorg", gh_fail=True)

        self.assertEqual(2, result.returncode, result.stdout)
        self.assertIn("failed", result.stdout)
        self.assertNotIn("SCAN SUMMARY", result.stdout)

    def test_empty_repo_list_is_an_error_not_a_clean_scan(self):
        result = self.run_scan_org(*self.scan_flags(), "testorg", repos="")

        self.assertEqual(2, result.returncode, result.stdout)
        self.assertIn("no repos found", result.stdout)
        self.assertNotIn("SCAN SUMMARY", result.stdout)

    def test_non_numeric_limit_is_a_usage_error(self):
        result = self.run_scan_org(*self.scan_flags(), "--limit", "abc", "testorg")

        self.assertEqual(2, result.returncode, result.stdout)
        self.assertIn("--limit must be a positive integer", result.stdout)

    def test_specific_repos_still_resolve_archived_status(self):
        result = self.run_scan_org(
            *self.scan_flags(),
            "testorg",
            "attic",
            repos="attic|an old repo|true",
        )

        self.assertEqual(0, result.returncode, result.stdout)
        self.assertIn("testorg/attic (archived)", result.stdout)


if __name__ == "__main__":
    unittest.main()

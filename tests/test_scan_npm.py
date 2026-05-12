import json
import subprocess
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]


def run_scan(root, *extra_args):
    return subprocess.run(
        ["python3", str(REPO_ROOT / "scan_npm.py"), "--root", str(root), *extra_args],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )


class ScanNpmTests(unittest.TestCase):
    def test_requires_bad_file_or_ioc_file_for_scanning(self):
        with tempfile.TemporaryDirectory() as td:
            result = run_scan(td)

        self.assertEqual(2, result.returncode)
        self.assertIn("at least one --bad-file or --ioc-file", result.stdout)

    def test_bad_file_matches_manifest_lockfile_and_installed_metadata(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            bad_file = root / "bad.txt"
            bad_file.write_text("@scope/pkg\t= 1.2.3\n@scope/installed\t= 4.5.6\n", encoding="utf-8")
            (root / "package.json").write_text(
                json.dumps({"dependencies": {"@scope/pkg": "1.2.3"}}),
                encoding="utf-8",
            )
            (root / "package-lock.json").write_text(
                json.dumps(
                    {
                        "lockfileVersion": 3,
                        "packages": {"node_modules/@scope/pkg": {"version": "1.2.3"}},
                    }
                ),
                encoding="utf-8",
            )
            installed = root / "node_modules" / "@scope" / "installed"
            installed.mkdir(parents=True)
            (installed / "package.json").write_text(
                json.dumps({"name": "@scope/installed", "version": "4.5.6"}),
                encoding="utf-8",
            )

            result = run_scan(root, "--bad-file", str(bad_file))

        self.assertEqual(1, result.returncode)
        self.assertIn("dependencies: @scope/pkg@1.2.3", result.stdout)
        self.assertIn("@scope/pkg@1.2.3 (node_modules/@scope/pkg)", result.stdout)
        self.assertIn("@scope/installed@4.5.6", result.stdout)

    def test_bad_file_matches_pnpm_and_yarn_lockfiles(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            bad_file = root / "bad.txt"
            bad_file.write_text(
                "\n".join(
                    [
                        "@scope/pnpm\t= 1.0.0",
                        "@scope/yarn\t= 2.0.0",
                        "@scope/separate\t= 3.0.0",
                    ]
                ),
                encoding="utf-8",
            )
            (root / "pnpm-lock.yaml").write_text(
                """
packages:
  /@scope/pnpm@1.0.0:
    resolution: {integrity: sha512-example}
  '@scope/separate':
    version: 3.0.0
""",
                encoding="utf-8",
            )
            (root / "yarn.lock").write_text(
                """
"@scope/yarn@2.0.0":
  version "2.0.0"
""",
                encoding="utf-8",
            )

            result = run_scan(root, "--bad-file", str(bad_file))

        self.assertEqual(1, result.returncode)
        self.assertIn("@scope/pnpm@1.0.0", result.stdout)
        self.assertIn("@scope/yarn@2.0.0", result.stdout)
        self.assertIn("@scope/separate@3.0.0", result.stdout)

    def test_scans_repo_that_contains_the_scanner_script(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            bad_file = root / "bad.txt"
            bad_file.write_text("@scope/pkg\t= 1.2.3\n", encoding="utf-8")
            nested_repo = root / "scanner-copy"
            nested_repo.mkdir()
            (nested_repo / "scan_npm.py").write_text("# scanner script placeholder\n", encoding="utf-8")
            (nested_repo / "package.json").write_text(
                json.dumps({"dependencies": {"@scope/pkg": "1.2.3"}}),
                encoding="utf-8",
            )

            result = run_scan(root, "--bad-file", str(bad_file))

        self.assertEqual(1, result.returncode)
        self.assertIn("scanner-copy/package.json", result.stdout)
        self.assertIn("dependencies: @scope/pkg@1.2.3", result.stdout)

    def test_ioc_file_matches_strings_files_and_paths(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            ioc_file = root / "iocs.tsv"
            ioc_file.write_text(
                "\n".join(
                    [
                        "Kind\tValue\tSeverity\tDescription",
                        "string\tevil.example\tcritical\tnetwork IOC",
                        "file\tpayload.js\tcritical\tpayload filename",
                        "path\t.vscode/setup.mjs\twarning\tpersistence path",
                    ]
                ),
                encoding="utf-8",
            )
            (root / "package-lock.json").write_text("evil.example", encoding="utf-8")
            (root / "payload.js").write_text("console.log('x')", encoding="utf-8")
            vscode = root / ".vscode"
            vscode.mkdir()
            (vscode / "setup.mjs").write_text("console.log('setup')", encoding="utf-8")

            result = run_scan(root, "--ioc-file", str(ioc_file))

        self.assertEqual(1, result.returncode)
        self.assertIn("CRITICAL | ioc string", result.stdout)
        self.assertIn("evil.example (network IOC)", result.stdout)
        self.assertIn("CRITICAL | ioc file", result.stdout)
        self.assertIn("payload.js (payload filename)", result.stdout)
        self.assertIn("WARNING | ioc path", result.stdout)
        self.assertIn(".vscode/setup.mjs (persistence path)", result.stdout)

    def test_tanstack_package_and_ioc_files_work_together(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "package.json").write_text(
                json.dumps(
                    {
                        "dependencies": {"@tanstack/react-router": "1.169.8"},
                        "optionalDependencies": {
                            "@tanstack/setup": "github:tanstack/router#79ac49eedf774dd4b0cfa308722bc463cfe5885c"
                        },
                    }
                ),
                encoding="utf-8",
            )
            (root / "router_init.js").write_text("filev2.getsession.org", encoding="utf-8")

            result = run_scan(
                root,
                "--bad-file",
                str(REPO_ROOT / "2026-05-tanstack-ghsa-g7cv-rxg3-hmpx.txt"),
                "--ioc-file",
                str(REPO_ROOT / "2026-05-tanstack-iocs.tsv"),
            )

        self.assertEqual(1, result.returncode)
        self.assertIn("dependencies: @tanstack/react-router@1.169.8", result.stdout)
        self.assertIn("@tanstack/setup (malicious optional dependency package name)", result.stdout)
        self.assertIn("github:tanstack/router#79ac49eedf774dd4b0cfa308722bc463cfe5885c", result.stdout)
        self.assertIn("router_init.js (malicious payload filename)", result.stdout)
        self.assertIn("filev2.getsession.org (exfiltration domain)", result.stdout)


if __name__ == "__main__":
    unittest.main()

import json
import subprocess
import tempfile
import unittest
from pathlib import Path

import hunt_tanstack_2026_05 as hunt


REPO_ROOT = Path(__file__).resolve().parents[1]


class TanStackHuntTests(unittest.TestCase):
    def scan(self, root):
        return hunt.scan_path(Path(root), 10 * 1024 * 1024)

    def details_for(self, findings, kind):
        return [finding["detail"] for finding in findings if finding["kind"] == kind]

    def test_clean_tree_has_no_findings(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "package.json").write_text(
                json.dumps({"dependencies": {"@tanstack/react-router": "1.169.9"}}),
                encoding="utf-8",
            )

            self.assertEqual([], self.scan(root))

    def test_finds_affected_manifest_dependency(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "package.json").write_text(
                json.dumps({"dependencies": {"@tanstack/react-router": "1.169.5"}}),
                encoding="utf-8",
            )

            findings = self.scan(root)

        self.assertIn(
            "dependencies: @tanstack/react-router@1.169.5",
            self.details_for(findings, "affected manifest dependency"),
        )

    def test_finds_package_lock_and_installed_package_metadata(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "package-lock.json").write_text(
                json.dumps(
                    {
                        "lockfileVersion": 3,
                        "packages": {
                            "node_modules/@tanstack/history": {"version": "1.161.12"}
                        },
                    }
                ),
                encoding="utf-8",
            )
            installed = root / "node_modules" / "@tanstack" / "router-core"
            installed.mkdir(parents=True)
            (installed / "package.json").write_text(
                json.dumps({"name": "@tanstack/router-core", "version": "1.169.8"}),
                encoding="utf-8",
            )

            findings = self.scan(root)

        lock_details = self.details_for(findings, "affected package-lock package")
        metadata_details = self.details_for(findings, "affected package metadata")
        self.assertTrue(any("@tanstack/history@1.161.12" in detail for detail in lock_details))
        self.assertIn("@tanstack/router-core@1.169.8", metadata_details)

    def test_finds_pnpm_and_yarn_lock_text_entries(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "pnpm-lock.yaml").write_text(
                """
packages:
  /@tanstack/react-start@1.167.71:
    resolution: {integrity: sha512-example}
""",
                encoding="utf-8",
            )
            (root / "yarn.lock").write_text(
                """
"@tanstack/vue-router@1.169.8":
  version "1.169.8"
""",
                encoding="utf-8",
            )

            findings = self.scan(root)

        details = self.details_for(findings, "affected lockfile entry")
        self.assertIn("@tanstack/react-start@1.167.71", details)
        self.assertIn("@tanstack/vue-router@1.169.8", details)

    def test_finds_confirmed_manifest_and_file_iocs(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "package.json").write_text(
                json.dumps(
                    {
                        "optionalDependencies": {
                            "@tanstack/setup": "github:tanstack/router#79ac49eedf774dd4b0cfa308722bc463cfe5885c"
                        }
                    }
                ),
                encoding="utf-8",
            )
            payload_dir = root / "node_modules" / "@tanstack" / "history"
            payload_dir.mkdir(parents=True)
            (payload_dir / "router_init.js").write_text(
                "filev2.getsession.org\nhttps://litter.catbox.moe/h8nc9u.js",
                encoding="utf-8",
            )

            findings = self.scan(root)

        self.assertTrue(
            any(
                "@tanstack/setup -> github:tanstack/router#79ac49eedf774dd4b0cfa308722bc463cfe5885c"
                in detail
                for detail in self.details_for(findings, "confirmed IOC")
            )
        )
        self.assertIn("router_init.js", self.details_for(findings, "confirmed IOC file"))
        self.assertTrue(
            any("filev2.getsession.org" in detail for detail in self.details_for(findings, "confirmed IOC"))
        )
        self.assertTrue(
            any("https://litter.catbox.moe/h8nc9u.js" in detail for detail in self.details_for(findings, "confirmed IOC"))
        )

    def test_finds_broader_campaign_persistence_warnings(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            vscode = root / ".vscode"
            vscode.mkdir()
            (vscode / "setup.mjs").write_text("console.log('setup')", encoding="utf-8")
            (vscode / "tasks.json").write_text("node .claude/setup.mjs", encoding="utf-8")

            findings = self.scan(root)

        self.assertTrue(
            any(
                finding["severity"] == "warning"
                and finding["kind"] == "suspicious persistence path"
                and finding["path"].endswith(".vscode/setup.mjs")
                for finding in findings
            )
        )
        self.assertTrue(
            any(
                finding["severity"] == "warning"
                and finding["kind"] == "suspicious broader-campaign IOC"
                and "node .claude/setup.mjs" in finding["detail"]
                for finding in findings
            )
        )

    def test_standard_scanner_can_use_tanstack_bad_file(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "package.json").write_text(
                json.dumps({"dependencies": {"@tanstack/react-router": "1.169.8"}}),
                encoding="utf-8",
            )

            result = subprocess.run(
                [
                    "python3",
                    str(REPO_ROOT / "scan_npm.py"),
                    "--root",
                    str(root),
                    "--bad-file",
                    str(REPO_ROOT / "2026-05-tanstack-ghsa-g7cv-rxg3-hmpx.txt"),
                ],
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )

        self.assertEqual(1, result.returncode)
        self.assertIn("@tanstack/react-router@1.169.8", result.stdout)


if __name__ == "__main__":
    unittest.main()

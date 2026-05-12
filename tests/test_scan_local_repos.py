import json
import subprocess
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]


class ScanLocalReposTests(unittest.TestCase):
    def make_repo(self, root, name, package_data):
        repo = root / name
        repo.mkdir()
        (repo / ".git").mkdir()
        (repo / "package.json").write_text(json.dumps(package_data), encoding="utf-8")
        return repo

    def test_scans_local_repos_and_prints_one_summary(self):
        with tempfile.TemporaryDirectory() as td:
            workspace = Path(td) / "repos"
            logs = Path(td) / "logs"
            workspace.mkdir()
            clean = self.make_repo(
                workspace,
                "clean",
                {"dependencies": {"@tanstack/react-router": "1.169.9"}},
            )
            affected = self.make_repo(
                workspace,
                "affected",
                {"dependencies": {"@tanstack/react-router": "1.169.5"}},
            )

            result = subprocess.run(
                [
                    "python3",
                    str(REPO_ROOT / "scan_local_repos.py"),
                    "--logs-dir",
                    str(logs),
                    str(workspace),
                ],
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )

        self.assertEqual(1, result.returncode)
        self.assertEqual("", result.stderr)
        self.assertIn("TANSTACK LOCAL REPO SCAN SUMMARY", result.stdout)
        self.assertIn("Repos discovered:  2", result.stdout)
        self.assertIn("Repos with hits:   1", result.stdout)
        self.assertIn(str(affected), result.stdout)
        self.assertNotIn(str(clean) + "\n    No TanStack", result.stdout)
        self.assertIn("dependencies: @tanstack/react-router@1.169.5", result.stdout)

    def test_missing_input_directory_is_usage_error(self):
        with tempfile.TemporaryDirectory() as td:
            missing = Path(td) / "missing"

            result = subprocess.run(
                ["python3", str(REPO_ROOT / "scan_local_repos.py"), str(missing)],
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )

        self.assertEqual(2, result.returncode)
        self.assertIn("not a directory", result.stderr)
        self.assertEqual("", result.stdout)


if __name__ == "__main__":
    unittest.main()

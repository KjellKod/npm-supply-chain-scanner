import os
import sys
import json
import argparse
from pathlib import Path

DEFAULT_BAD_FILE = Path(__file__).parent / "bad-packages.txt"

# ------------------------------------------------------------------------------
# Load compromised packages list
# ------------------------------------------------------------------------------
def load_bad_packages(bad_file=None):
    bad = {}
    with open(bad_file or DEFAULT_BAD_FILE) as f:
        for line in f:
            line = line.strip()
            if not line or "=" not in line:
                continue

            name, versions = line.split("=", 1)
            name = name.strip()

            version_list = []
            for part in versions.split("||"):
                v = part.strip().lstrip("=").strip()
                if v:
                    version_list.append(v)

            bad[name] = version_list
    return bad

BAD = None

def is_bad(name, version):
    version = version.strip().lstrip("^~")
    return name in BAD and version in BAD[name]

# ------------------------------------------------------------------------------
# Print repo directories as they are visited
# ------------------------------------------------------------------------------
def list_repos(root):
    seen = set()
    for pkg in root.rglob("package.json"):
        repo = pkg.parent
        seen.add(repo)

    for lock in root.rglob("package-lock.json"):
        repo = lock.parent
        seen.add(repo)

    # sort for stable output
    return sorted(seen, key=lambda p: str(p))

# ------------------------------------------------------------------------------
# Extract package name from lockfile v2 key
# ------------------------------------------------------------------------------
def _extract_name_from_lockfile_key(key, fallback_name):
    """Extract package name from a lockfile v2 key like 'node_modules/@scope/pkg'."""
    if key:
        parts = key.rsplit("node_modules/", 1)
        return parts[-1] if len(parts) > 1 else key
    return fallback_name

# ------------------------------------------------------------------------------
# Scan package.json
# ------------------------------------------------------------------------------
def scan_package_json(path, results):
    try:
        with open(path) as f:
            data = json.load(f)
    except Exception:
        return

    for sec in ["dependencies", "devDependencies", "peerDependencies", "optionalDependencies"]:
        for name, version in data.get(sec, {}).items():
            clean = version.lstrip("^~")
            if is_bad(name, clean):
                results.append(("package.json", path, name, version))

# ------------------------------------------------------------------------------
# Scan package-lock.json (supports npm v1 + v2+)
# ------------------------------------------------------------------------------
def scan_package_lock(path, results):
    try:
        with open(path) as f:
            data = json.load(f)
    except Exception:
        return

    # npm v2+ lockfile
    if "packages" in data:
        for key, meta in data["packages"].items():
            version = meta.get("version")
            if not version:
                continue
            name = _extract_name_from_lockfile_key(key, data.get("name"))
            if name and is_bad(name, version):
                results.append(("package-lock.json (v2)", path, name, version))
        return

    # npm v1 lockfile
    if "dependencies" in data:
        stack = list(data["dependencies"].items())
        while stack:
            name, meta = stack.pop()
            version = meta.get("version")
            if version and is_bad(name, version):
                results.append(("package-lock.json (v1)", path, name, version))
            nested = meta.get("dependencies")
            if isinstance(nested, dict):
                stack.extend(nested.items())

# ------------------------------------------------------------------------------
# Inventory mode
# ------------------------------------------------------------------------------
def inventory_all_packages(root):
    found = set()

    for path in root.rglob("package.json"):
        try:
            with open(path) as f:
                data = json.load(f)
        except Exception:
            continue

        for sec in ["dependencies", "devDependencies", "peerDependencies", "optionalDependencies"]:
            found.update(data.get(sec, {}).keys())

    for path in root.rglob("package-lock.json"):
        try:
            with open(path) as f:
                data = json.load(f)
        except Exception:
            continue

        # v2+
        if "packages" in data:
            for key in data["packages"].keys():
                name = _extract_name_from_lockfile_key(key, data.get("name"))
                if name:
                    found.add(name)

        # v1
        if "dependencies" in data:
            stack = list(data["dependencies"].items())
            while stack:
                name, meta = stack.pop()
                found.add(name)
                nested = meta.get("dependencies")
                if isinstance(nested, dict):
                    stack.extend(nested.items())

    return sorted(found)

# ------------------------------------------------------------------------------
# Main
# ------------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(description="Scan npm packages for compromised dependencies")
    parser.add_argument("--root", default=".", help="Root directory to scan (default: current directory)")
    parser.add_argument("--bad-file", action="append", default=[], help="Path to bad-packages list (repeatable; default: bad-packages.txt)")
    parser.add_argument("--inventory", action="store_true", help="List all found packages instead of scanning")
    args = parser.parse_args()

    global BAD
    if not args.bad_file:
        print("Error: at least one --bad-file is required.")
        sys.exit(2)
    BAD = {}
    for f in args.bad_file:
        for name, versions in load_bad_packages(f).items():
            BAD.setdefault(name, []).extend(v for v in versions if v not in BAD.get(name, []))
    root = Path(args.root)

    # inventory mode
    if args.inventory:
        for pkg in inventory_all_packages(root):
            print(pkg)
        return

    # standard scan with repo printing
    repos = list_repos(root)
    results = []

    for repo in repos:
        print(f"Checking: {repo}")
        pkg_json = repo / "package.json"
        pkg_lock = repo / "package-lock.json"

        if pkg_json.exists():
            scan_package_json(pkg_json, results)

        if pkg_lock.exists():
            scan_package_lock(pkg_lock, results)

    # output results
    if not results:
        print("\nNo compromised packages found.")
        return

    print("\nCOMPROMISED PACKAGES FOUND:\n")
    for kind, path, name, version in results:
        print(f"{kind} | {path} | {name}@{version}")

    sys.exit(1)

if __name__ == "__main__":
    main()

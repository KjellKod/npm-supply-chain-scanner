import argparse
import json
import re
import sys
from pathlib import Path

DEFAULT_BAD_FILE = Path(__file__).parent / "bad-packages.txt"
DEPENDENCY_SECTIONS = [
    "dependencies",
    "devDependencies",
    "peerDependencies",
    "optionalDependencies",
    "bundledDependencies",
    "bundleDependencies",
]

LOCKFILE_NAMES = {
    "package-lock.json",
    "npm-shrinkwrap.json",
    "pnpm-lock.yaml",
    "yarn.lock",
}

TEXT_SUFFIXES = {
    ".json",
    ".lock",
    ".yaml",
    ".yml",
    ".js",
    ".mjs",
    ".cjs",
    ".ts",
    ".tsx",
    ".jsx",
    ".txt",
    ".log",
    ".md",
    ".toml",
    ".ini",
    ".conf",
}

SKIP_DIRS = {".git", "__pycache__"}

BAD = {}
IOC_RULES = []
EXCLUDED_FILES = set()


def load_bad_packages(bad_file=None):
    bad = {}
    with open(bad_file or DEFAULT_BAD_FILE) as f:
        for line in f:
            line = line.strip()
            if not line or "=" not in line:
                continue

            name, versions = line.split("=", 1)
            name = name.strip()
            if not name or name.lower() == "package":
                continue

            version_list = []
            for part in versions.split("||"):
                v = part.strip().lstrip("=").strip()
                if v:
                    version_list.append(v)

            bad[name] = version_list
    return bad


def load_ioc_file(ioc_file):
    rules = []
    with open(ioc_file) as f:
        for line_no, line in enumerate(f, 1):
            raw = line.strip()
            if not raw or raw.startswith("#"):
                continue

            parts = [part.strip() for part in raw.split("\t")]
            if len(parts) < 2:
                raise ValueError(f"{ioc_file}:{line_no}: expected tab-separated kind and value")

            kind, value = parts[0].lower(), parts[1]
            if kind in {"kind", "type"}:
                continue
            if kind not in {"string", "file", "path"}:
                raise ValueError(f"{ioc_file}:{line_no}: unsupported IOC kind {kind!r}")
            if not value:
                raise ValueError(f"{ioc_file}:{line_no}: empty IOC value")

            severity = parts[2].lower() if len(parts) > 2 and parts[2] else "critical"
            if severity not in {"critical", "warning"}:
                raise ValueError(f"{ioc_file}:{line_no}: severity must be critical or warning")
            description = parts[3] if len(parts) > 3 else ""
            rules.append(
                {
                    "kind": kind,
                    "value": value,
                    "severity": severity,
                    "description": description,
                    "source": str(ioc_file),
                }
            )
    return rules


def normalize_version(version):
    if not isinstance(version, str):
        return ""
    return version.strip().lstrip("^~=").strip()


def is_bad(name, version):
    return name in BAD and normalize_version(version) in BAD[name]


def add_result(results, kind, path, detail, severity="critical"):
    results.append(
        {
            "severity": severity,
            "kind": kind,
            "path": str(path),
            "detail": detail,
        }
    )


def dedupe_results(results):
    seen = set()
    unique = []
    for result in results:
        key = (result["severity"], result["kind"], result["path"], result["detail"])
        if key in seen:
            continue
        seen.add(key)
        unique.append(result)
    return unique


def iter_files(root):
    for path in root.rglob("*"):
        if path.is_dir():
            continue
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        resolved = path.resolve()
        if resolved in EXCLUDED_FILES:
            continue
        yield path


def list_repos(root):
    seen = set()
    for path in iter_files(root):
        if path.name == "package.json" or path.name in LOCKFILE_NAMES:
            seen.add(path.parent)
    return sorted(seen, key=lambda p: str(p))


def _extract_name_from_lockfile_key(key, fallback_name):
    """Extract package name from a lockfile v2 key like 'node_modules/@scope/pkg'."""
    if key:
        parts = key.rsplit("node_modules/", 1)
        return parts[-1].strip("/") if len(parts) > 1 else key
    return fallback_name


def load_json(path):
    try:
        with open(path) as f:
            return json.load(f)
    except Exception:
        return None


def scan_package_json(path, results, source_label="package.json"):
    data = load_json(path)
    if not isinstance(data, dict):
        return

    name = data.get("name")
    version = data.get("version")
    if name and version and is_bad(name, version):
        add_result(results, "affected package metadata", path, f"{name}@{version}")

    for sec in DEPENDENCY_SECTIONS:
        deps = data.get(sec, {})
        if not isinstance(deps, dict):
            continue
        for name, version in deps.items():
            if is_bad(name, version):
                add_result(
                    results,
                    f"affected {source_label} dependency",
                    path,
                    f"{sec}: {name}@{version}",
                )


def scan_package_lock(path, results):
    data = load_json(path)
    if not isinstance(data, dict):
        return

    if "packages" in data:
        for key, meta in data["packages"].items():
            if not isinstance(meta, dict):
                continue
            version = meta.get("version")
            if not version:
                continue
            name = meta.get("name") or _extract_name_from_lockfile_key(key, data.get("name"))
            if name and is_bad(name, version):
                add_result(
                    results,
                    "affected package-lock package",
                    path,
                    f"{name}@{version} ({key or '<root>'})",
                )
        return

    if "dependencies" in data:
        stack = list(data["dependencies"].items())
        while stack:
            name, meta = stack.pop()
            if not isinstance(meta, dict):
                continue
            version = meta.get("version")
            if version and is_bad(name, version):
                add_result(results, "affected package-lock dependency", path, f"{name}@{version}")
            nested = meta.get("dependencies")
            if isinstance(nested, dict):
                stack.extend(nested.items())


def scan_text_lockfile(path, results):
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return

    for name, versions in BAD.items():
        escaped_name = re.escape(name)
        for version in versions:
            escaped_version = re.escape(version)
            patterns = (
                rf"{escaped_name}@{escaped_version}",
                rf"{escaped_name}[\s\S]{{0,160}}version:\s*[\"']?{escaped_version}[\"']?",
                rf"{escaped_name}[\s\S]{{0,160}}version\s+[\"']{escaped_version}[\"']",
            )
            if any(re.search(pattern, text) for pattern in patterns):
                add_result(results, "affected lockfile entry", path, f"{name}@{version}")


def should_scan_text(path):
    return path.name in LOCKFILE_NAMES or path.name == "package.json" or path.suffix in TEXT_SUFFIXES


def scan_ioc_path(path, results):
    posix = path.as_posix()
    for rule in IOC_RULES:
        if rule["kind"] == "file" and path.name == rule["value"]:
            add_result(
                results,
                "ioc file",
                path,
                describe_ioc(rule),
                severity=rule["severity"],
            )
        elif rule["kind"] == "path" and posix.endswith(rule["value"]):
            add_result(
                results,
                "ioc path",
                path,
                describe_ioc(rule),
                severity=rule["severity"],
            )


def scan_ioc_text(path, results, max_bytes):
    string_rules = [rule for rule in IOC_RULES if rule["kind"] == "string"]
    if not string_rules or not should_scan_text(path):
        return
    try:
        raw = path.read_bytes()
    except OSError:
        return
    if len(raw) > max_bytes:
        return

    for rule in string_rules:
        if rule["value"].encode("utf-8") in raw:
            add_result(
                results,
                "ioc string",
                path,
                describe_ioc(rule),
                severity=rule["severity"],
            )


def describe_ioc(rule):
    if rule["description"]:
        return f"{rule['value']} ({rule['description']})"
    return rule["value"]


def inventory_all_packages(root):
    found = set()

    for path in iter_files(root):
        if path.name != "package.json":
            continue
        data = load_json(path)
        if not isinstance(data, dict):
            continue
        if data.get("name"):
            found.add(data["name"])
        for sec in DEPENDENCY_SECTIONS:
            deps = data.get(sec, {})
            if isinstance(deps, dict):
                found.update(deps.keys())

    for path in iter_files(root):
        if path.name not in {"package-lock.json", "npm-shrinkwrap.json"}:
            continue
        data = load_json(path)
        if not isinstance(data, dict):
            continue
        if "packages" in data:
            for key, meta in data["packages"].items():
                name = meta.get("name") if isinstance(meta, dict) else None
                name = name or _extract_name_from_lockfile_key(key, data.get("name"))
                if name:
                    found.add(name)
        if "dependencies" in data:
            stack = list(data["dependencies"].items())
            while stack:
                name, meta = stack.pop()
                found.add(name)
                nested = meta.get("dependencies") if isinstance(meta, dict) else None
                if isinstance(nested, dict):
                    stack.extend(nested.items())

    return sorted(found)


def scan_root(root, max_file_mb=10):
    results = []
    max_bytes = max_file_mb * 1024 * 1024

    for path in iter_files(root):
        scan_ioc_path(path, results)

        if path.name == "package.json":
            source_label = "installed package" if "node_modules" in path.parts else "package.json"
            scan_package_json(path, results, source_label=source_label)
        elif path.name in {"package-lock.json", "npm-shrinkwrap.json"}:
            scan_package_lock(path, results)
        elif path.name in {"pnpm-lock.yaml", "yarn.lock"}:
            scan_text_lockfile(path, results)

        scan_ioc_text(path, results, max_bytes)

    return dedupe_results(results)


def print_results(results):
    if not results:
        print("\nNo compromised packages or IOCs found.")
        return

    print("\nFINDINGS:\n")
    for result in results:
        print(
            f"{result['severity'].upper()} | {result['kind']} | "
            f"{result['path']} | {result['detail']}"
        )


def main():
    parser = argparse.ArgumentParser(description="Scan npm projects for compromised dependencies and IOCs")
    parser.add_argument("--root", default=".", help="Root directory to scan (default: current directory)")
    parser.add_argument(
        "--bad-file",
        action="append",
        default=[],
        help="Path to bad-packages list (repeatable; default: bad-packages.txt)",
    )
    parser.add_argument(
        "--ioc-file",
        action="append",
        default=[],
        help="Path to tab-separated IOC rules (repeatable): kind, value, severity, description",
    )
    parser.add_argument(
        "--max-file-mb",
        type=int,
        default=10,
        help="Maximum size per file for IOC text scanning. Default: 10.",
    )
    parser.add_argument("--inventory", action="store_true", help="List all found packages instead of scanning")
    args = parser.parse_args()

    global BAD, IOC_RULES, EXCLUDED_FILES
    if not args.bad_file and not args.ioc_file and not args.inventory:
        print("Error: at least one --bad-file or --ioc-file is required.")
        sys.exit(2)

    BAD = {}
    for f in args.bad_file:
        resolved = Path(f).resolve()
        EXCLUDED_FILES.add(resolved)
        for name, versions in load_bad_packages(resolved).items():
            BAD.setdefault(name, []).extend(v for v in versions if v not in BAD.get(name, []))

    IOC_RULES = []
    for f in args.ioc_file:
        resolved = Path(f).resolve()
        EXCLUDED_FILES.add(resolved)
        try:
            IOC_RULES.extend(load_ioc_file(resolved))
        except ValueError as exc:
            print(f"Error: {exc}")
            sys.exit(2)

    root = Path(args.root)

    if args.inventory:
        for pkg in inventory_all_packages(root):
            print(pkg)
        return

    repos = list_repos(root)
    for repo in repos:
        print(f"Checking: {repo}")

    results = scan_root(root, max_file_mb=args.max_file_mb)
    print_results(results)

    if results:
        sys.exit(1)


if __name__ == "__main__":
    main()

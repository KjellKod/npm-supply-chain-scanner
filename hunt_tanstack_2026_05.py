#!/usr/bin/env python3
"""
One-off local hunt for GHSA-g7cv-rxg3-hmpx / CVE-2026-45321.

This script is read-only. It never runs package-manager lifecycle scripts.
"""

import argparse
import json
import re
import sys
from pathlib import Path


AFFECTED = {
    "@tanstack/arktype-adapter": {"1.166.12", "1.166.15"},
    "@tanstack/eslint-plugin-router": {"1.161.9", "1.161.12"},
    "@tanstack/eslint-plugin-start": {"0.0.4", "0.0.7"},
    "@tanstack/history": {"1.161.9", "1.161.12"},
    "@tanstack/nitro-v2-vite-plugin": {"1.154.12", "1.154.15"},
    "@tanstack/react-router": {"1.169.5", "1.169.8"},
    "@tanstack/react-router-devtools": {"1.166.16", "1.166.19"},
    "@tanstack/react-router-ssr-query": {"1.166.15", "1.166.18"},
    "@tanstack/react-start": {"1.167.68", "1.167.71"},
    "@tanstack/react-start-client": {"1.166.51", "1.166.54"},
    "@tanstack/react-start-rsc": {"0.0.47", "0.0.50"},
    "@tanstack/react-start-server": {"1.166.55", "1.166.58"},
    "@tanstack/router-cli": {"1.166.46", "1.166.49"},
    "@tanstack/router-core": {"1.169.5", "1.169.8"},
    "@tanstack/router-devtools": {"1.166.16", "1.166.19"},
    "@tanstack/router-devtools-core": {"1.167.6", "1.167.9"},
    "@tanstack/router-generator": {"1.166.45", "1.166.48"},
    "@tanstack/router-plugin": {"1.167.38", "1.167.41"},
    "@tanstack/router-ssr-query-core": {"1.168.3", "1.168.6"},
    "@tanstack/router-utils": {"1.161.11", "1.161.14"},
    "@tanstack/router-vite-plugin": {"1.166.53", "1.166.56"},
    "@tanstack/solid-router": {"1.169.5", "1.169.8"},
    "@tanstack/solid-router-devtools": {"1.166.16", "1.166.19"},
    "@tanstack/solid-router-ssr-query": {"1.166.15", "1.166.18"},
    "@tanstack/solid-start": {"1.167.65", "1.167.68"},
    "@tanstack/solid-start-client": {"1.166.50", "1.166.53"},
    "@tanstack/solid-start-server": {"1.166.54", "1.166.57"},
    "@tanstack/start-client-core": {"1.168.5", "1.168.8"},
    "@tanstack/start-fn-stubs": {"1.161.9", "1.161.12"},
    "@tanstack/start-plugin-core": {"1.169.23", "1.169.26"},
    "@tanstack/start-server-core": {"1.167.33", "1.167.36"},
    "@tanstack/start-static-server-functions": {"1.166.44", "1.166.47"},
    "@tanstack/start-storage-context": {"1.166.38", "1.166.41"},
    "@tanstack/valibot-adapter": {"1.166.12", "1.166.15"},
    "@tanstack/virtual-file-routes": {"1.161.10", "1.161.13"},
    "@tanstack/vue-router": {"1.169.5", "1.169.8"},
    "@tanstack/vue-router-devtools": {"1.166.16", "1.166.19"},
    "@tanstack/vue-router-ssr-query": {"1.166.15", "1.166.18"},
    "@tanstack/vue-start": {"1.167.61", "1.167.64"},
    "@tanstack/vue-start-client": {"1.166.46", "1.166.49"},
    "@tanstack/vue-start-server": {"1.166.50", "1.166.53"},
    "@tanstack/zod-adapter": {"1.166.12", "1.166.15"},
}

CONFIRMED_IOCS = {
    "@tanstack/setup": "malicious optional dependency package name",
    "github:tanstack/router#79ac49eedf774dd4b0cfa308722bc463cfe5885c": "malicious optional dependency git ref",
    "79ac49eedf774dd4b0cfa308722bc463cfe5885c": "orphan payload commit",
    "router_init.js": "malicious payload filename",
    "tanstack_runner.js": "malicious helper filename",
    "filev2.getsession.org": "exfiltration domain",
    "seed1.getsession.org": "exfiltration domain",
    "seed2.getsession.org": "exfiltration domain",
    "seed3.getsession.org": "exfiltration domain",
    "https://litter.catbox.moe/h8nc9u.js": "second-stage payload URL",
    "https://litter.catbox.moe/7rrc6l.mjs": "second-stage payload URL",
    "Linux-pnpm-store-6f9233a50def742c09fde54f56553d6b449a535adf87d4083690539f49ae4da11": "poisoned GitHub Actions cache key",
    "github.com/zblgg/configuration": "attacker fork",
    "65bf499d16a5e8d25ba95d69ec9790a6dd4a1f14": "malicious fork commit",
}

SUSPICIOUS_PATH_SUFFIXES = {
    ".claude/router_runtime.js": "reported persistence artifact",
    ".claude/setup.mjs": "reported persistence artifact",
    ".vscode/setup.mjs": "reported persistence artifact",
    ".local/bin/gh-token-monitor.sh": "reported persistence artifact",
    ".config/systemd/user/gh-token-monitor.service": "reported persistence artifact",
    ".github/workflows/codeql_analysis.yml": "reported suspicious workflow name",
    ".github/workflows/codeql_analysis.yaml": "reported suspicious workflow name",
}

SUSPICIOUS_TEXT = {
    "node .vscode/setup.mjs": "reported Claude Code hook command",
    "node .claude/setup.mjs": "reported VS Code folder-open task command",
    "toJSON(secrets)": "workflow serializes all GitHub Actions secrets",
    "gh-token-monitor": "reported persistence service name",
    "api.masscan.cloud": "reported C2 endpoint in broader campaign writeups",
}

DEPENDENCY_SECTIONS = (
    "dependencies",
    "devDependencies",
    "peerDependencies",
    "optionalDependencies",
    "bundledDependencies",
    "bundleDependencies",
)

LOCKFILE_NAMES = {
    "package-lock.json",
    "npm-shrinkwrap.json",
    "pnpm-lock.yaml",
    "yarn.lock",
    "bun.lock",
    "bun.lockb",
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
SELF_PATH = Path(__file__).resolve()


def normalize_version(version):
    if not isinstance(version, str):
        return ""
    return version.strip().lstrip("^~=").strip()


def is_affected(name, version):
    return name in AFFECTED and normalize_version(version) in AFFECTED[name]


def add_finding(findings, kind, path, detail, severity="critical"):
    findings.append(
        {
            "severity": severity,
            "kind": kind,
            "path": str(path),
            "detail": detail,
        }
    )


def load_json(path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def extract_name_from_lock_key(key, fallback_name=None):
    if key:
        parts = key.rsplit("node_modules/", 1)
        candidate = parts[-1] if len(parts) > 1 else key
        return candidate.strip("/") or fallback_name
    return fallback_name


def scan_package_json(path, findings):
    data = load_json(path)
    if not isinstance(data, dict):
        return

    name = data.get("name")
    version = data.get("version")
    if name and version and is_affected(name, version):
        add_finding(findings, "affected package metadata", path, f"{name}@{version}")

    for section in DEPENDENCY_SECTIONS:
        deps = data.get(section)
        if not isinstance(deps, dict):
            continue
        for dep_name, dep_version in deps.items():
            if is_affected(dep_name, dep_version):
                add_finding(
                    findings,
                    "affected manifest dependency",
                    path,
                    f"{section}: {dep_name}@{dep_version}",
                )
            if dep_name == "@tanstack/setup" and isinstance(dep_version, str):
                add_finding(
                    findings,
                    "confirmed IOC",
                    path,
                    f"{section}: @tanstack/setup -> {dep_version}",
                )


def walk_lock_v1_dependencies(path, deps, findings):
    stack = list(deps.items()) if isinstance(deps, dict) else []
    while stack:
        name, meta = stack.pop()
        if not isinstance(meta, dict):
            continue
        if name == "@tanstack/setup":
            add_finding(findings, "confirmed IOC", path, "package-lock dependency: @tanstack/setup")
        version = meta.get("version")
        if version and is_affected(name, version):
            add_finding(findings, "affected package-lock dependency", path, f"{name}@{version}")
        nested = meta.get("dependencies")
        if isinstance(nested, dict):
            stack.extend(nested.items())


def scan_package_lock(path, findings):
    data = load_json(path)
    if not isinstance(data, dict):
        return

    packages = data.get("packages")
    if isinstance(packages, dict):
        for key, meta in packages.items():
            if not isinstance(meta, dict):
                continue
            name = meta.get("name") or extract_name_from_lock_key(key, data.get("name"))
            version = meta.get("version")
            if name == "@tanstack/setup":
                add_finding(findings, "confirmed IOC", path, f"package-lock package: {name} ({key or '<root>'})")
            if name and version and is_affected(name, version):
                add_finding(findings, "affected package-lock package", path, f"{name}@{version} ({key or '<root>'})")
            for field in ("resolved", "version"):
                value = meta.get(field)
                if isinstance(value, str):
                    scan_text_value(path, value, findings, context=f"package-lock packages[{key!r}].{field}")

    walk_lock_v1_dependencies(path, data.get("dependencies"), findings)


def scan_text_value(path, value, findings, context="text"):
    for ioc, reason in CONFIRMED_IOCS.items():
        if ioc in value:
            add_finding(findings, "confirmed IOC", path, f"{context}: {ioc} ({reason})")
    for ioc, reason in SUSPICIOUS_TEXT.items():
        if ioc in value:
            add_finding(findings, "suspicious broader-campaign IOC", path, f"{context}: {ioc} ({reason})", severity="warning")


def scan_text_file(path, findings, max_bytes):
    try:
        size = path.stat().st_size
    except OSError:
        return
    if size > max_bytes:
        return

    try:
        raw = path.read_bytes()
    except OSError:
        return

    for ioc, reason in CONFIRMED_IOCS.items():
        if ioc.encode("utf-8") in raw:
            add_finding(findings, "confirmed IOC", path, f"{ioc} ({reason})")
    for ioc, reason in SUSPICIOUS_TEXT.items():
        if ioc.encode("utf-8") in raw:
            add_finding(findings, "suspicious broader-campaign IOC", path, f"{ioc} ({reason})", severity="warning")

    if path.name in {"pnpm-lock.yaml", "yarn.lock", "bun.lock", "bun.lockb"}:
        try:
            text = raw.decode("utf-8", errors="ignore")
        except Exception:
            return
        scan_lock_text_for_versions(path, text, findings)


def scan_lock_text_for_versions(path, text, findings):
    for name, versions in AFFECTED.items():
        escaped = re.escape(name)
        for version in versions:
            version_escaped = re.escape(version)
            patterns = (
                rf"{escaped}@{version_escaped}",
                rf"{escaped}@npm:{version_escaped}",
                rf"{escaped}@[^\n\r]{{0,160}}[\"']?:\s*[\n\r]+(?:[^\n\r]*[\n\r]+){{0,3}}[ \t]*version:?\s*[\"']?{version_escaped}[\"']?",
            )
            if any(re.search(pattern, text) for pattern in patterns):
                add_finding(findings, "affected lockfile entry", path, f"{name}@{version}")


def should_scan_text(path):
    return path.name in LOCKFILE_NAMES or path.name == "package.json" or path.suffix in TEXT_SUFFIXES


def iter_files(root):
    for path in root.rglob("*"):
        if path.is_dir():
            continue
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        if path.resolve() == SELF_PATH:
            continue
        yield path


def scan_path(root, max_bytes):
    findings = []

    for path in iter_files(root):
        posix = path.as_posix()
        for suffix, reason in SUSPICIOUS_PATH_SUFFIXES.items():
            if posix.endswith(suffix):
                add_finding(findings, "suspicious persistence path", path, reason, severity="warning")

        if path.name in {"router_init.js", "tanstack_runner.js"}:
            add_finding(findings, "confirmed IOC file", path, path.name)

        if path.name == "package.json":
            scan_package_json(path, findings)
        elif path.name in {"package-lock.json", "npm-shrinkwrap.json"}:
            scan_package_lock(path, findings)

        if should_scan_text(path):
            scan_text_file(path, findings, max_bytes)

    return dedupe_findings(findings)


def dedupe_findings(findings):
    seen = set()
    unique = []
    for finding in findings:
        key = (finding["severity"], finding["kind"], finding["path"], finding["detail"])
        if key in seen:
            continue
        seen.add(key)
        unique.append(finding)
    return unique


def print_findings(findings):
    critical = [f for f in findings if f["severity"] == "critical"]
    warnings = [f for f in findings if f["severity"] != "critical"]

    if not findings:
        print("No TanStack GHSA-g7cv-rxg3-hmpx package/version hits or configured IOCs found.")
        return

    if critical:
        print("CRITICAL FINDINGS")
        for finding in critical:
            print(f"- {finding['kind']} | {finding['path']} | {finding['detail']}")

    if warnings:
        if critical:
            print()
        print("WARNINGS / BROADER-CAMPAIGN HUNTS")
        for finding in warnings:
            print(f"- {finding['kind']} | {finding['path']} | {finding['detail']}")


def main():
    parser = argparse.ArgumentParser(
        description="Read-only one-off hunt for the May 2026 TanStack npm supply-chain compromise."
    )
    parser.add_argument("--root", default=".", help="Root directory to scan.")
    parser.add_argument(
        "--max-file-mb",
        type=int,
        default=10,
        help="Maximum size for text IOC scanning per file. Default: 10.",
    )
    parser.add_argument("--json", action="store_true", help="Emit findings as JSON.")
    args = parser.parse_args()

    root = Path(args.root).expanduser().resolve()
    max_bytes = args.max_file_mb * 1024 * 1024
    findings = scan_path(root, max_bytes)

    if args.json:
        print(json.dumps(findings, indent=2, sort_keys=True))
    else:
        print_findings(findings)

    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())

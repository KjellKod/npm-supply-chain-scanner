# npm-supply-chain-scanner

Version 0.0.1

Scan npm projects for known compromised packages. Checks `package.json` and `package-lock.json` files against a curated list of bad packages and versions (`bad-packages.txt`).

## Requirements

- Python 3.6+
- `gh` CLI (for org-wide scanning)
- `git` (for cloning repos)

## Usage

### Scan a local directory

```bash
python3 scan_npm.py --root /path/to/project --bad-file bad-packages.txt
```

Without `--root`, scans the current directory.

### Scan all repos in a GitHub org

```bash
bash scan_org.sh --bad-file bad-packages.txt onfleet
```

### Scan specific repos in an org

```bash
bash scan_org.sh --bad-file bad-packages.txt onfleet repo1 repo2
```

### Keep cloned repos after scanning

```bash
bash scan_org.sh --bad-file bad-packages.txt --keep onfleet
```

### Inventory mode (list all packages found)

```bash
python3 scan_npm.py --inventory --root /path/to/project
```

### Test

```bash
python3 -m unittest discover -s tests
```

### May 2026 TanStack incident hunt

For GHSA-g7cv-rxg3-hmpx / CVE-2026-45321, use the read-only one-off hunter. It checks exact affected package/version pairs plus confirmed local IOCs like `@tanstack/setup`, the malicious git ref, `router_init.js`, `tanstack_runner.js`, getsession domains, and broader persistence artifacts reported in the campaign.

```bash
python3 hunt_tanstack_2026_05.py --root /path/to/project
```

You can also use the official GHSA package/version table with the standard scanner:

```bash
python3 scan_npm.py --root /path/to/project --bad-file 2026-05-tanstack-ghsa-g7cv-rxg3-hmpx.txt
```

## Default incident response approach

For new supply-chain incidents, add three things together:

1. A dated bad-file sourced from the official advisory package/version table.
2. A dated read-only hunt script for incident-specific IOCs that do not fit package/version matching.
3. Fixture tests proving the scanner sees manifests, lockfiles, installed package metadata, confirmed IOCs, and broader campaign warnings.

Keep incident hunters read-only: parse local files, inspect lockfiles and installed metadata, and do not run package-manager install scripts.

## Exit codes

- `0` -- no compromised packages found
- `1` -- compromised packages detected
- `2` -- usage error or missing dependencies

## Adding new compromised packages

Append entries to `bad-packages.txt` using tab-separated format:

```
package-name\t= version
package-name\t= version1 || = version2
```

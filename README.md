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
python3 scan_npm.py --root /path/to/project
```

Without `--root`, scans the current directory.

### Scan all repos in a GitHub org

```bash
bash scan_org.sh onfleet
```

### Scan specific repos in an org

```bash
bash scan_org.sh onfleet repo1 repo2
```

### Keep cloned repos after scanning

```bash
bash scan_org.sh --keep onfleet
```

### Inventory mode (list all packages found)

```bash
python3 scan_npm.py --inventory --root /path/to/project
```

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

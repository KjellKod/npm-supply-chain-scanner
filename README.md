# npm-supply-chain-scanner

Version 0.0.1

Scan npm projects for known compromised packages. Checks `package.json` and `package-lock.json` files against a known-compromised package/version list.

## Requirements

- Python 3.6+
- `gh` CLI (for org-wide scanning)
- `git` (for cloning repos)

## Usage

`--bad-file` points to a tab-separated package/version list that the scanner should treat as compromised. The default example list is `bad-packages.txt`; incident-specific lists can be added as separate dated files, such as `2026-05-tanstack-ghsa-g7cv-rxg3-hmpx.txt`.

### Scan a local directory

```bash
python3 scan_npm.py --root /path/to/project --bad-file bad-packages.txt
```

This scans `/path/to/project` using the known-compromised package/version entries in `bad-packages.txt`. Without `--root`, it scans the current directory.

### Scan up to 500 repos in a GitHub org

```bash
bash scan_org.sh --bad-file bad-packages.txt <github-org-name>
```

This clones up to 500 repos in `<github-org-name>` to a temporary directory and scans them using `bad-packages.txt`.

### Scan specific repos in an org

```bash
bash scan_org.sh --bad-file bad-packages.txt <github-org-name> repo1 repo2
```

This scans only `repo1` and `repo2` from `<github-org-name>`.

### Keep cloned repos after scanning

```bash
bash scan_org.sh --bad-file bad-packages.txt --keep <github-org-name>
```

By default, `scan_org.sh` deletes temporary clones when it finishes. `--keep` leaves those cloned repos on disk so you can inspect them after the run.

### Run the TanStack hunter against a GitHub org

`scan_org.sh` clones up to 500 matching repos to a temporary directory and runs the local hunter against each checkout.

```bash
bash scan_org.sh --tanstack-hunt <github-org-name>
```

Scan specific repos with the TanStack hunter:

```bash
bash scan_org.sh --tanstack-hunt <github-org-name> repo1 repo2
```

Run both package/version matching and the TanStack IOC hunter:

```bash
bash scan_org.sh --bad-file 2026-05-tanstack-ghsa-g7cv-rxg3-hmpx.txt --tanstack-hunt <github-org-name>
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

For GHSA-g7cv-rxg3-hmpx / CVE-2026-45321, use the read-only one-off hunter from the repo root. It checks exact affected package/version pairs plus confirmed local IOCs like `@tanstack/setup`, the malicious git ref, `router_init.js`, `tanstack_runner.js`, getsession domains, and broader persistence artifacts reported in the campaign.

```bash
python3 hunt_tanstack_2026_05.py --root /path/to/project
```

Use `--json` when you want machine-readable findings:

```bash
python3 hunt_tanstack_2026_05.py --root /path/to/project --json
```

Scan all locally cloned repos that are accessible under one or more local directories:

```bash
cd npm-supply-chain-scanner
python3 scan_local_repos.py /path/to/directory-with-repos
```

Scan multiple local directories:

```bash
python3 scan_local_repos.py /path/to/team-repos /path/to/personal-repos
```

The local repo scanner recursively discovers Git repos under the input directories, runs the TanStack hunter once per repo, writes per-repo logs to `hunt-logs/`, and prints one final summary with all findings. It exits `1` if any repo has findings, `2` if a scan error occurs, and `0` when all discovered repos are clean.

Use a custom log directory when you want to keep outputs separate:

```bash
python3 scan_local_repos.py --logs-dir tanstack-hunt-logs /path/to/directory-with-repos
```

Clean output:

```text
No TanStack GHSA-g7cv-rxg3-hmpx package/version hits or configured IOCs found.
```

Example finding output:

```text
CRITICAL FINDINGS
- affected manifest dependency | /path/to/project/package.json | dependencies: @tanstack/react-router@1.169.5
- confirmed IOC | /path/to/project/package-lock.json | package-lock packages['node_modules/@tanstack/setup'].resolved: github:tanstack/router#79ac49eedf774dd4b0cfa308722bc463cfe5885c (malicious optional dependency git ref)

WARNINGS / BROADER-CAMPAIGN HUNTS
- suspicious persistence path | /path/to/project/.vscode/setup.mjs | reported persistence artifact
```

Local repo summary:

```text
TANSTACK LOCAL REPO SCAN SUMMARY
================================
Input directories:
- /path/to/directory-with-repos
Repos discovered:  2
Repos with hits:   1
Scan errors:       0
Per-repo logs:     /path/to/output/hunt-logs

FINDINGS
- /path/to/directory-with-repos/example-repo
  log: /path/to/output/hunt-logs/example-repo-abc123def456.log
    CRITICAL FINDINGS
    - affected manifest dependency | /path/to/directory-with-repos/example-repo/package.json | dependencies: @tanstack/react-router@1.169.5
```

The hunter exits `1` when it finds any critical or warning evidence, and `0` when the tree is clean. `scan_local_repos.py` reports one final summary across local disk repos.

Use the official GHSA package/version table and IOC rules with the standard scanner:

```bash
python3 scan_npm.py \
  --root /path/to/project \
  --bad-file 2026-05-tanstack-ghsa-g7cv-rxg3-hmpx.txt \
  --ioc-file 2026-05-tanstack-iocs.tsv
```

Scan a GitHub org or owner with the same package/version and IOC rules:

```bash
bash scan_org.sh \
  --bad-file 2026-05-tanstack-ghsa-g7cv-rxg3-hmpx.txt \
  --ioc-file 2026-05-tanstack-iocs.tsv \
  <github-org-name>
```

To run the full TanStack hunter against GitHub repos without cloning them manually, use `scan_org.sh --tanstack-hunt`.

Concrete examples:

```bash
cd /Users/kjell/ws/extra/npm-supply-chain-scanner
bash scan_org.sh \
  --bad-file 2026-05-tanstack-ghsa-g7cv-rxg3-hmpx.txt \
  --ioc-file 2026-05-tanstack-iocs.tsv \
  KjellKod

bash scan_org.sh \
  --bad-file 2026-05-tanstack-ghsa-g7cv-rxg3-hmpx.txt \
  --ioc-file 2026-05-tanstack-iocs.tsv \
  onfleet
```

Verification completed on the durable scanner branch:

```bash
python3 -m unittest discover -s tests
python3 -m py_compile scan_npm.py hunt_tanstack_2026_05.py tests/test_scan_npm.py tests/test_tanstack_hunt.py
python3 scan_npm.py --help && bash -n scan_org.sh
python3 scan_npm.py --root . --bad-file 2026-05-tanstack-ghsa-g7cv-rxg3-hmpx.txt --ioc-file 2026-05-tanstack-iocs.tsv
```

## Default incident response approach

For new supply-chain incidents, add three things together:

1. A dated bad-file sourced from the official advisory package/version table.
2. A dated IOC file for strings, filenames, and path suffixes that do not fit package/version matching.
3. Fixture tests proving the scanner sees manifests, lockfiles, installed package metadata, confirmed IOCs, and broader campaign warnings.

Keep incident scans read-only: parse local files, inspect lockfiles and installed metadata, and do not run package-manager install scripts.

IOC files are tab-separated:

```text
Kind    Value   Severity    Description
string  example.com critical    example network IOC
file    payload.js  critical    payload filename
path    .vscode/setup.mjs   warning reported persistence path
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

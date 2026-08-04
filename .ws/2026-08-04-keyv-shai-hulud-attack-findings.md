# Keyv / Shai-Hulud npm supply chain attack (Aug 4, 2026)

Source: https://www.aikido.dev/blog/keyv-and-friends-compromised-in-npm-supply-chain-attack

Note: IoC values in this document are defanged (`[.]`, `[0]`, colon dropped from the campaign marker) so this file does not trip the scanner's own string rules. Canonical machine-readable values live in `2026-08-shai-hulud-iocs.tsv`.

## Summary

On August 4, 2026, an attacker compromised the GitHub account of the keyv maintainer and published poisoned versions of keyv and related caching packages, signed with valid GitHub Actions signatures. The campaign is a new wave of the "Shai-Hulud" worm ("Shai-Hulud "Here We Go Again""). Installation triggers a `preinstall` script that runs an obfuscated dropper, downloads the Bun runtime, executes a credential-harvesting payload, and self-propagates by publishing infected versions of other packages using stolen npm tokens.

## Compromised packages (primary wave)

| Package | Compromised version | Monthly downloads |
|---|---|---|
| keyv | 6.0.0 | 604M |
| flat-cache | 6.1.24 | 580M |
| file-entry-cache | 11.1.6 | 571M |
| cacheable-request | 13.0.20 | 137M |
| @cacheable/utils | 2.5.1 | 34M |
| cacheable | 2.5.1 | 30M |
| @cacheable/memory | 2.2.1 | 28M |
| cache-manager | 7.2.10 | 16M |
| @cacheable/node-cache | 3.1.2 | 6M |
| ecto | 5.0.1 | 4.5K |
| @cacheable/net | 2.1.1 | 3.7K |

Secondary wave: 434+ packages across 1,381 versions infected via worm propagation, including @deliveroo/reevent, @picsart/ai-sdk, @qlik/embed-runtime.

## Attack mechanism

- Two files injected into the package: `setup.mjs` (obfuscated dropper) and `Math_Symbol.js` (728 KB payload, also seen as `math_init.js`).
- `package.json` gains `"preinstall": "node setup[.]mjs"`.
- Dropper downloads the Bun runtime and executes the main payload.
- Payload harvests: npm tokens (~/.npmrc), GitHub tokens (classic PATs, OAuth, App, OIDC), AWS credentials, Kubernetes secrets, HashiCorp Vault tokens, Stripe and Slack tokens. Scans filesystem for .env files, SSH keys, config files.

## Indicators of compromise

File hashes (SHA-256):
- `setup.mjs`: `54dc7ea54a1317cca0e890a2770630cf7fa6c97813e0cb9d2caa93012b350668`
- `setup.mjs` (community spread variant): `fd3ca4007b225fdf8de7af4345a19179d5efa8c4bb9205f88cda806e5684b1eb`
- `Math_Symbol.js` / `math_init.js`: `9fc2570b7cef51c1b8df116d144d11ff4096357be7d2c4c6367cfc2509cf1bcc`

Files and manifest:
- `setup.mjs`, `Math_Symbol.js`, `math_init.js` in package root
- `"preinstall": "node setup[.]mjs"` in package.json

Network / repo:
- `npm-cache[.]com:443/router` (fallback exfiltration)
- GitHub repos with description "Shai-Hulud "Here We Go Again""
- Ethereum smart contract `0xE1f2395ee43e45A1556EC6438a88c31B834931[0]3`
- Git commits authored as "claude" with message "chore: update config"

## Remediation (per article)

1. Audit and revoke npm tokens used on affected systems.
2. Rotate GitHub tokens, AWS credentials, and other cloud credentials.
3. Remove affected package versions from environments.
4. Scan for `setup.mjs` and `Math_Symbol.js` files.
5. Review GitHub commits authored as "claude" with message "chore: update config".
6. Upgrade to patched versions once available.
7. Use package-scanning tooling in CI.

## Scanner gap analysis (this repo)

### How the scanner works today

- `scan_npm.py`: durable data-driven engine. Repeatable `--bad-file` (TSV package/version) and `--ioc-file` (TSV `Kind\tValue\tSeverity\tDescription`, kinds limited to `string`, `file`, `path`). Scans package.json dep sections, npm lockfiles (v1/v2/v3), pnpm-lock.yaml, yarn.lock, plus IoC file/path/string rules. Exit 1 on hits.
- `scan_org.sh`: org driver. `gh repo list <org> --limit 500`, shallow-clones each repo, runs `scan_npm.py` and/or the TanStack hunter.
- `hunt_tanstack_2026_05.py` and `scan_local_repos.py`: one-off May 2026 TanStack tooling, hardcoded to that campaign.
- Per-incident pattern already established: dated bad-file + dated IoC TSV + fixture tests (see `2026-05-tanstack-*`).

### What already works with only new data files

- All 11 primary packages at exact versions, plus the 434+ secondary-wave packages: covered by a new dated bad-file (manifests, npm/pnpm/yarn lockfiles, installed node_modules).
- `setup.mjs` / `Math_Symbol.js` / `math_init.js` presence: IoC `file` rules (basename match, any depth).
- `npm-cache[.]com`, "Shai-Hulud "Here We Go Again"", Ethereum address, literal `"preinstall": "node setup[.]mjs"`: IoC `string` rules (text files under 10 MB only).

### What the scanner misses today

1. SHA-256 file hashes (the highest-confidence IoC). No hashing anywhere; `load_ioc_file` rejects a `sha256` kind with exit 2. Renamed payloads undetectable.
2. Structured lifecycle-script detection. `scan_package_json` never reads `scripts`; only exact-substring luck catches preinstall variants like `node ./setup.mjs`.
3. Git commit IoCs (author "claude", message "chore: update config"). No git inspection exists, and `scan_org.sh` clones `--depth 1` so history isn't even present.
4. GitHub repo descriptions containing "Shai-Hulud "Here We Go Again"" (the worm's exfil-repo tell). `scan_org.sh` fetches `--json name` only.
5. Bun lockfiles. `LOCKFILE_NAMES` in `scan_npm.py` lacks `bun.lock`/`bun.lockb` (the TanStack hunter has them). Relevant since the payload runs via Bun.
6. Root-anchoring. `file`/`path` rules match at any depth, so `setup.mjs` rules will be noisy against legitimate `scripts/setup.mjs`, and existing TanStack `.vscode/setup.mjs` rules will double-fire.
7. Reusability: `scan_local_repos.py` hardwires the TanStack hunter; `scan_org.sh` has a campaign-specific `--tanstack-hunt` flag and a hardcoded 500-repo limit.

### Plan

New data files (immediate detection value):
- `2026-08-shai-hulud-here-we-go-again.txt`: bad-file with the 11 primary packages, extended with the secondary-wave list as it firms up.
- `2026-08-shai-hulud-iocs.tsv`: `file` rules (setup.mjs, Math_Symbol.js, math_init.js), `string` rules (npm-cache[.]com, campaign name, Ethereum address, preinstall strings), and `sha256` rows once supported.

Code changes to `scan_npm.py` (~60 lines, keeps the engine durable):
- Add `sha256` IoC kind: validate 64-hex value, hash candidate files in chunks, not gated by text-suffix filter (optimization: only hash files matching a `file` rule basename or with `.mjs`/`.js`/`.cjs`/`.ts` suffix).
- Parse `package.json` `scripts`: new IoC kind for lifecycle hooks, plus a generic warning for any preinstall/install/postinstall/prepare hook invoking a root-level `.mjs`/`.js`.
- Add `bun.lock`/`bun.lockb` to `LOCKFILE_NAMES`.

Code changes to `scan_org.sh`:
- Fetch `--json name,description` and flag descriptions containing "Shai-Hulud" as a cheap pre-pass.
- Replace `--depth 1` with `--filter=blob:none` and add a `git log` check for commits authored as "claude" with message "chore: update config".
- Generalize `--tanstack-hunt` to `--hunt <script>`, make `--limit` configurable.

Also: parameterize `scan_local_repos.py` (`--hunter PATH`), update README with a "run this now" block for the Aug 2026 campaign, add fixtures/tests mirroring the TanStack ones (hash hit, preinstall hit, bun lockfile hit, combined bad-file + IoC test).

Recommendation: extend the durable engine plus two dated data files. Do not clone a third one-off hunter. The only genuinely new capabilities (git history, gh repo descriptions) belong in `scan_org.sh`.

### Implementation status (2026-08-04)

Implemented, all 23 tests passing plus end-to-end smoke test on a synthetic infected fixture:

- `2026-08-shai-hulud-here-we-go-again.txt`: 11 primary packages.
- `2026-08-shai-hulud-iocs.tsv`: 3 file rules, 3 sha256 rules, 5 string rules.
- `scan_npm.py`: `sha256` IoC kind (chunked hashing, all files under size cap, catches renamed payloads), lifecycle-script warning for preinstall/install invoking a bare `node`/`bun` script (postinstall excluded to avoid node_modules noise), bun.lock/bun.lockb lockfile scanning.
- `scan_org.sh`: automatic repo-description sweep for "shai-hulud" (exit 1 on match), `--git-history` (blobless full-history clone plus check for commits authored "claude" with subject "chore: update config"), `--hunt <script>` generalization (`--tanstack-hunt` kept as alias), configurable `--limit` with cap warning.
- `scan_local_repos.py`: `--hunter` / `--hunter-arg` parameterization, generic summary header.
- README: new "Run this now" block for this campaign, sha256 kind and new flags documented.

Run it:

```bash
bash scan_org.sh \
  --git-history \
  --bad-file 2026-08-shai-hulud-here-we-go-again.txt \
  --ioc-file 2026-08-shai-hulud-iocs.tsv \
  <github-org-name>
```

Caveat: secondary-wave packages (434+) not yet in the bad-file; append when a public list firms up.

### Review round (Codex + Claude sub-agent, 2026-08-04)

Both reviews confirmed the six intents functionally met and the data files correct. Fixes applied from their findings, all verified empirically on macOS /bin/bash 3.2:

- Severity-aware exit codes: `scan_npm.py` now exits 1 only on critical findings, 3 on warnings-only. Prevents legit repos (test `setup.mjs`, benign preinstall scripts) from reading as compromised in org sweeps.
- `scan_org.sh` repo-list hardening: `gh repo list` failure or an empty/typo'd org now exits 2 with a clear error instead of crashing on bash 3.2 or silently reporting a clean scan.
- Scanner and hunter exit statuses classified (1 hit, 3 warning, other = scan error); crashes no longer count as compromised repos. Summary lists hits, warning-only repos, and scan errors separately; script exits 0/1/2/3 accordingly.
- Arg validation: `--limit` must be numeric, trailing flags without values fail cleanly.
- IoC strings defanged in README and this writeup so the scanner's own repo scans clean (verified: self-scan exit 0, infected fixture still exit 1).
- Known limitation documented: binary `bun.lockb` matching is best-effort; prefer text `bun.lock` or convert first. Text `bun.lock` works.

Remaining accepted risks: no automated tests for scan_org.sh shell paths (manually verified with a stubbed `gh`), minified `"preinstall":"node setup[.]mjs"` matches at warning severity via the heuristic rather than the exact critical string, secondary-wave package list pending.

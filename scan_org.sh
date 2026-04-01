#!/usr/bin/env bash
#
# scan_org.sh -- Clone all repos in a GitHub org and scan for compromised npm packages.
#
# Usage:
#   bash scan_org.sh <org>                    # scan ALL repos in the org
#   bash scan_org.sh <org> repo1 repo2        # scan only specific repos
#   bash scan_org.sh --keep <org> [repos...]  # keep cloned repos after scan
#
# Version: 0.0.1

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
KEEP=false

# Parse --keep flag
if [[ "${1:-}" == "--keep" ]]; then
    KEEP=true
    shift
fi

# Require org name
if [[ $# -lt 1 ]]; then
    echo "Usage: $0 [--keep] <org> [repo1 repo2 ...]"
    exit 2
fi

ORG="$1"
shift
SPECIFIC_REPOS=("$@")

# Check dependencies
for cmd in gh python3 git; do
    if ! command -v "$cmd" &>/dev/null; then
        echo "Error: '$cmd' is required but not found. Please install it first."
        exit 2
    fi
done

# Verify gh auth
if ! gh auth status &>/dev/null; then
    echo "Error: 'gh' is not authenticated. Run 'gh auth login' first."
    exit 2
fi

# Get repo list
if [[ ${#SPECIFIC_REPOS[@]} -gt 0 ]]; then
    REPOS=("${SPECIFIC_REPOS[@]}")
    echo "Scanning ${#REPOS[@]} specified repo(s) in $ORG..."
else
    echo "Fetching repo list for org '$ORG'..."
    REPOS=()
    while IFS= read -r line; do
        REPOS+=("$line")
    done < <(gh repo list "$ORG" --limit 500 --json name --jq '.[].name')
    echo "Found ${#REPOS[@]} repos."
fi

# Create temp directory
TMPDIR="$(mktemp -d)"
if [[ "$KEEP" == false ]]; then
    trap 'rm -rf "$TMPDIR"' EXIT
else
    echo "Clones will be kept in: $TMPDIR"
fi

# Scan each repo
TOTAL=0
HITS=0
FAILED_CLONE=()
HIT_REPOS=()

for repo in "${REPOS[@]}"; do
    TOTAL=$((TOTAL + 1))
    echo ""
    echo "--- [$TOTAL/${#REPOS[@]}] $ORG/$repo ---"

    if ! git clone --depth 1 "https://github.com/$ORG/$repo.git" "$TMPDIR/$repo" 2>/dev/null; then
        echo "  SKIP: clone failed"
        FAILED_CLONE+=("$repo")
        continue
    fi

    if ! python3 "$SCRIPT_DIR/scan_npm.py" --root "$TMPDIR/$repo"; then
        HITS=$((HITS + 1))
        HIT_REPOS+=("$repo")
    fi
done

# Summary
echo ""
echo "========================================="
echo "SCAN SUMMARY for $ORG"
echo "========================================="
echo "Total repos scanned: $TOTAL"
echo "Repos with hits:     ${#HIT_REPOS[@]}"
if [[ ${#HIT_REPOS[@]} -gt 0 ]]; then
    for r in "${HIT_REPOS[@]}"; do
        echo "  - $r"
    done
fi
if [[ ${#FAILED_CLONE[@]} -gt 0 ]]; then
    echo "Failed to clone:     ${#FAILED_CLONE[@]}"
    for r in "${FAILED_CLONE[@]}"; do
        echo "  - $r"
    done
fi
echo "========================================="

if [[ ${#HIT_REPOS[@]} -gt 0 ]]; then
    exit 1
fi
exit 0

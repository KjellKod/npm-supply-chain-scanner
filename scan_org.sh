#!/usr/bin/env bash
#
# scan_org.sh -- Clone GitHub org repos and scan for compromised npm packages.
#
# Usage:
#   bash scan_org.sh --bad-file FILE <org>                    # scan up to 500 repos in the org
#   bash scan_org.sh --bad-file FILE <org> repo1 repo2        # scan only specific repos
#   bash scan_org.sh --tanstack-hunt <org> [repos...]         # run the TanStack IOC hunter
#   bash scan_org.sh --bad-file FILE --ioc-file FILE <org>    # scan package/version and IOC rules
#   bash scan_org.sh --keep --tanstack-hunt <org> [repos...]  # keep cloned repos after scan
#
# The org or owner name is positional. Use `... --tanstack-hunt <org>`, not
# `... --tanstack-hunt --org <org>`.
#
# Version: 0.0.1

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
KEEP=false
TANSTACK_HUNT=false
BAD_FILES=()
IOC_FILES=()
POSITIONAL=()

# Parse all args — flags can appear anywhere
ARGS=("$@")
i=0
while [[ $i -lt ${#ARGS[@]} ]]; do
    case "${ARGS[$i]}" in
        --keep) KEEP=true ;;
        --tanstack-hunt) TANSTACK_HUNT=true ;;
        --bad-file) i=$((i + 1)); BAD_FILES+=("${ARGS[$i]}") ;;
        --bad-file=*) BAD_FILES+=("${ARGS[$i]#--bad-file=}") ;;
        --ioc-file) i=$((i + 1)); IOC_FILES+=("${ARGS[$i]}") ;;
        --ioc-file=*) IOC_FILES+=("${ARGS[$i]#--ioc-file=}") ;;
        --org|--org=*)
            echo "Error: --org is not supported. Pass the GitHub org or owner as the final positional argument."
            echo "Usage: $0 [--bad-file FILE ...] [--ioc-file FILE ...] [--tanstack-hunt] [--keep] <org> [repo1 repo2 ...]"
            exit 2
            ;;
        *) POSITIONAL+=("${ARGS[$i]}") ;;
    esac
    i=$((i + 1))
done

# Require at least one scanner mode
if [[ ${#BAD_FILES[@]} -eq 0 && ${#IOC_FILES[@]} -eq 0 && "$TANSTACK_HUNT" == false ]]; then
    echo "Error: at least one --bad-file, --ioc-file, or --tanstack-hunt is required."
    echo "Usage: $0 [--bad-file FILE ...] [--ioc-file FILE ...] [--tanstack-hunt] [--keep] <org> [repo1 repo2 ...]"
    exit 2
fi

# Require org name
if [[ ${#POSITIONAL[@]} -lt 1 ]]; then
    echo "Usage: $0 [--bad-file FILE ...] [--ioc-file FILE ...] [--tanstack-hunt] [--keep] <org> [repo1 repo2 ...]"
    exit 2
fi

ORG="${POSITIONAL[0]}"
SPECIFIC_REPOS=()
if [[ ${#POSITIONAL[@]} -gt 1 ]]; then
    SPECIFIC_REPOS=("${POSITIONAL[@]:1}")
fi

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
if [[ "${#SPECIFIC_REPOS[@]}" -gt 0 ]]; then
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

    REPO_HIT=false

    if [[ ${#BAD_FILES[@]} -gt 0 || ${#IOC_FILES[@]} -gt 0 ]]; then
        SCAN_ARGS=(--root "$TMPDIR/$repo")
        for bf in "${BAD_FILES[@]+"${BAD_FILES[@]}"}"; do
            SCAN_ARGS+=(--bad-file "$bf")
        done
        for ioc in "${IOC_FILES[@]+"${IOC_FILES[@]}"}"; do
            SCAN_ARGS+=(--ioc-file "$ioc")
        done

        if ! python3 "$SCRIPT_DIR/scan_npm.py" "${SCAN_ARGS[@]}"; then
            REPO_HIT=true
        fi
    fi

    if [[ "$TANSTACK_HUNT" == true ]]; then
        if ! python3 "$SCRIPT_DIR/hunt_tanstack_2026_05.py" --root "$TMPDIR/$repo"; then
            REPO_HIT=true
        fi
    fi

    if [[ "$REPO_HIT" == true ]]; then
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

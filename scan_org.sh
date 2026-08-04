#!/usr/bin/env bash
#
# scan_org.sh -- Clone GitHub org repos and scan for compromised npm packages.
#
# Usage:
#   bash scan_org.sh --bad-file FILE <org>                    # scan repos in the org (default limit 500)
#   bash scan_org.sh --bad-file FILE <org> repo1 repo2        # scan only specific repos
#   bash scan_org.sh --hunt SCRIPT <org> [repos...]           # run a one-off hunter script per repo
#   bash scan_org.sh --tanstack-hunt <org> [repos...]         # alias for --hunt hunt_tanstack_2026_05.py
#   bash scan_org.sh --bad-file FILE --ioc-file FILE <org>    # scan package/version and IOC rules
#   bash scan_org.sh --git-history --bad-file FILE <org>      # also check commit-metadata IOCs (full-history clone)
#   bash scan_org.sh --limit 1000 --bad-file FILE <org>       # raise the repo-list cap
#   bash scan_org.sh --skip-archived --bad-file FILE <org>    # skip archived repos entirely
#   bash scan_org.sh --keep --bad-file FILE <org>             # keep cloned repos after scan
#
# The org or owner name is positional. Use `... --bad-file FILE <org>`, not
# `... --bad-file FILE --org <org>`.
#
# When fetching the org repo list (no specific repos given), repo descriptions
# are checked for the Shai-Hulud campaign marker (worm-created exfil repos).
#
# Archived repos are scanned by default and tagged "(archived)" in output.
# Archived code is read-only on GitHub but still clonable and installable, so a
# compromised lockfile there is still a live risk. Use --skip-archived to
# exclude them when you only care about actively developed code.
#
# Version: 0.0.3

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
KEEP=false
GIT_HISTORY=false
SKIP_ARCHIVED=false
HUNT_SCRIPT=""
LIMIT=500
BAD_FILES=()
IOC_FILES=()
POSITIONAL=()

USAGE="Usage: $0 [--bad-file FILE ...] [--ioc-file FILE ...] [--hunt SCRIPT] [--git-history] [--skip-archived] [--limit N] [--keep] <org> [repo1 repo2 ...]"

usage_error() {
    echo "Error: $1 requires a value."
    echo "$USAGE"
    exit 2
}

# Assert a value follows the flag at index $i. Bare "${ARGS[$i]:?msg}" would
# exit 1, which the exit-code contract reserves for confirmed findings.
require_next() {
    if [[ $((i + 1)) -ge ${#ARGS[@]} || -z "${ARGS[$((i + 1))]}" ]]; then
        usage_error "$1"
    fi
}

# Assert an inline --flag=value form is not empty.
require_value() {
    if [[ -z "$2" ]]; then
        usage_error "$1"
    fi
}

# Parse all args. Flags can appear anywhere.
ARGS=("$@")
i=0
while [[ $i -lt ${#ARGS[@]} ]]; do
    case "${ARGS[$i]}" in
        --keep) KEEP=true ;;
        --git-history) GIT_HISTORY=true ;;
        --skip-archived) SKIP_ARCHIVED=true ;;
        --tanstack-hunt) HUNT_SCRIPT="$SCRIPT_DIR/hunt_tanstack_2026_05.py" ;;
        --hunt) require_next --hunt; i=$((i + 1)); HUNT_SCRIPT="${ARGS[$i]}" ;;
        --hunt=*)
            HUNT_SCRIPT="${ARGS[$i]#--hunt=}"
            require_value --hunt "$HUNT_SCRIPT" ;;
        --limit) require_next --limit; i=$((i + 1)); LIMIT="${ARGS[$i]}" ;;
        --limit=*)
            LIMIT="${ARGS[$i]#--limit=}"
            require_value --limit "$LIMIT" ;;
        --bad-file) require_next --bad-file; i=$((i + 1)); BAD_FILES+=("${ARGS[$i]}") ;;
        --bad-file=*)
            require_value --bad-file "${ARGS[$i]#--bad-file=}"
            BAD_FILES+=("${ARGS[$i]#--bad-file=}") ;;
        --ioc-file) require_next --ioc-file; i=$((i + 1)); IOC_FILES+=("${ARGS[$i]}") ;;
        --ioc-file=*)
            require_value --ioc-file "${ARGS[$i]#--ioc-file=}"
            IOC_FILES+=("${ARGS[$i]#--ioc-file=}") ;;
        --org|--org=*)
            echo "Error: --org is not supported. Pass the GitHub org or owner as the final positional argument."
            echo "$USAGE"
            exit 2
            ;;
        *) POSITIONAL+=("${ARGS[$i]}") ;;
    esac
    i=$((i + 1))
done

# Require at least one scanner mode
if [[ ${#BAD_FILES[@]} -eq 0 && ${#IOC_FILES[@]} -eq 0 && -z "$HUNT_SCRIPT" ]]; then
    echo "Error: at least one --bad-file, --ioc-file, --hunt, or --tanstack-hunt is required."
    echo "$USAGE"
    exit 2
fi

# Require org name
if [[ ${#POSITIONAL[@]} -lt 1 ]]; then
    echo "$USAGE"
    exit 2
fi

ORG="${POSITIONAL[0]}"
SPECIFIC_REPOS=()
if [[ ${#POSITIONAL[@]} -gt 1 ]]; then
    SPECIFIC_REPOS=("${POSITIONAL[@]:1}")
fi

if [[ -n "$HUNT_SCRIPT" && ! -f "$HUNT_SCRIPT" ]]; then
    echo "Error: hunter script not found: $HUNT_SCRIPT"
    exit 2
fi

if ! [[ "$LIMIT" =~ ^[1-9][0-9]*$ ]]; then
    echo "Error: --limit must be a positive integer, got: $LIMIT"
    exit 2
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

# Commit-metadata IOCs: Shai-Hulud worm commits authored as "claude" with
# message "chore: update config". Requires history, so only useful with
# --git-history (shallow clones have a single commit).
# Prints matching commits. Returns 2 if `git log` itself failed, so a history
# that was never actually read is reported as a scan error, not as clean. A
# repo with no commits succeeds with empty output.
check_git_history() {
    local dir="$1" log_output=""
    if ! log_output="$(git -C "$dir" log --all --format='%h%x09%an%x09%s' 2>/dev/null)"; then
        return 2
    fi
    printf '%s' "$log_output" |
        awk -F'\t' 'tolower($2) == "claude" && $3 == "chore: update config" { print "  SUSPICIOUS COMMIT: " $1 " author=" $2 " subject=" $3 }'
}

# Get repo list. When listing the org, also sweep repo descriptions for the
# Shai-Hulud campaign marker (worm-created exfiltration repos).
SUSPICIOUS_DESC=()
SUSPICIOUS_NAMES=" "
# Archived repo names, space-delimited. bash 3.2 (macOS) has no associative
# arrays, so membership is tested with a padded substring match.
ARCHIVED_NAMES=" "
UNKNOWN_ARCHIVED=()
if [[ "${#SPECIFIC_REPOS[@]}" -gt 0 ]]; then
    REPOS=("${SPECIFIC_REPOS[@]}")
    echo "Scanning ${#REPOS[@]} specified repo(s) in $ORG..."
    for name in "${REPOS[@]}"; do
        # A failed lookup must not silently read as "not archived": that would
        # drop the (archived) tag and let --skip-archived skip nothing. Unknown
        # status always falls toward scanning, never toward skipping.
        if ! ARCHIVED_FLAG="$(gh repo view "$ORG/$name" --json isArchived --jq .isArchived 2>/dev/null)"; then
            echo "  WARNING: could not determine archive status for $name; scanning it and leaving it untagged."
            UNKNOWN_ARCHIVED+=("$name")
            continue
        fi
        if [[ "$ARCHIVED_FLAG" == "true" ]]; then
            ARCHIVED_NAMES="$ARCHIVED_NAMES$name "
        fi
    done
else
    echo "Fetching repo list for org '$ORG' (limit $LIMIT)..."
    # Fetch into a variable first: a gh failure inside process substitution is
    # invisible to `set -e` and would silently produce an empty, "clean" scan.
    if ! REPO_LIST="$(gh repo list "$ORG" --limit "$LIMIT" --json name,description,isArchived --jq '.[] | [.name, (.description // ""), (.isArchived | tostring)] | @tsv')"; then
        echo "Error: 'gh repo list $ORG' failed. Check the org name and your gh auth."
        exit 2
    fi
    REPOS=()
    while IFS=$'\t' read -r name description archived; do
        [[ -z "$name" ]] && continue
        REPOS+=("$name")
        if [[ "${archived:-}" == "true" ]]; then
            ARCHIVED_NAMES="$ARCHIVED_NAMES$name "
        fi
        if [[ -n "${description:-}" ]]; then
            desc_lower="$(printf '%s' "$description" | tr '[:upper:]' '[:lower:]')"
            if [[ "$desc_lower" == *"shai-hulud"* ]]; then
                SUSPICIOUS_DESC+=("$name: $description")
                SUSPICIOUS_NAMES="$SUSPICIOUS_NAMES$name "
                echo "  SUSPICIOUS REPO DESCRIPTION: $name: $description"
            fi
        fi
    done <<< "$REPO_LIST"
    echo "Found ${#REPOS[@]} repos."
    ARCHIVED_COUNT="$(printf '%s' "$ARCHIVED_NAMES" | wc -w | tr -d ' ')"
    if [[ "$ARCHIVED_COUNT" -gt 0 ]]; then
        if [[ "$SKIP_ARCHIVED" == true ]]; then
            echo "Archived repos: $ARCHIVED_COUNT (skipping, --skip-archived)"
        else
            echo "Archived repos: $ARCHIVED_COUNT (scanned and tagged; use --skip-archived to exclude)"
        fi
    fi
    if [[ ${#REPOS[@]} -eq 0 ]]; then
        echo "Error: no repos found for '$ORG'. Check the org or owner name."
        exit 2
    fi
    if [[ ${#REPOS[@]} -eq $LIMIT ]]; then
        echo "WARNING: repo list hit the --limit cap ($LIMIT); some repos may be missing. Re-run with a higher --limit."
    fi
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
FAILED_CLONE=()
HIT_REPOS=()
WARN_REPOS=()
ERROR_REPOS=()
SKIPPED_ARCHIVED=()

is_archived() {
    [[ "$ARCHIVED_NAMES" == *" $1 "* ]]
}

# Repo name tagged with archived status, for summary lines.
repo_label() {
    if is_archived "$1"; then
        printf '%s (archived)' "$1"
    else
        printf '%s' "$1"
    fi
}

# Exit-code contract for scanners/hunters: 0 clean, 1 critical findings,
# 3 warnings only. Anything else is a scan failure, not a compromise.
classify_exit() {
    case "$1" in
        0) ;;
        1) REPO_HIT=true ;;
        3) REPO_WARN=true ;;
        *) echo "  SCAN ERROR: exit status $1"; REPO_ERROR=true ;;
    esac
}

IDX=0
for repo in "${REPOS[@]}"; do
    IDX=$((IDX + 1))
    echo ""
    echo "--- [$IDX/${#REPOS[@]}] $ORG/$(repo_label "$repo") ---"

    if is_archived "$repo" && [[ "$SKIP_ARCHIVED" == true ]]; then
        echo "  SKIP: archived repo (--skip-archived)"
        if [[ "$SUSPICIOUS_NAMES" == *" $repo "* ]]; then
            # The description sweep is a separate signal from the code scan. A
            # worm-created exfil repo is an attacker artifact, so it is still
            # reported and still fails the run even when its code is skipped.
            echo "  NOTE: still reported for its repo description; that finding is not suppressed by --skip-archived"
        fi
        SKIPPED_ARCHIVED+=("$repo")
        continue
    fi

    TOTAL=$((TOTAL + 1))

    if [[ "$GIT_HISTORY" == true ]]; then
        CLONE_ARGS=(--filter=blob:none)
    else
        CLONE_ARGS=(--depth 1)
    fi
    if ! git clone "${CLONE_ARGS[@]}" "https://github.com/$ORG/$repo.git" "$TMPDIR/$repo" 2>/dev/null; then
        echo "  SKIP: clone failed"
        FAILED_CLONE+=("$repo")
        continue
    fi

    REPO_HIT=false
    REPO_WARN=false
    REPO_ERROR=false

    if [[ ${#BAD_FILES[@]} -gt 0 || ${#IOC_FILES[@]} -gt 0 ]]; then
        SCAN_ARGS=(--root "$TMPDIR/$repo")
        for bf in "${BAD_FILES[@]+"${BAD_FILES[@]}"}"; do
            SCAN_ARGS+=(--bad-file "$bf")
        done
        for ioc in "${IOC_FILES[@]+"${IOC_FILES[@]}"}"; do
            SCAN_ARGS+=(--ioc-file "$ioc")
        done

        STATUS=0
        python3 "$SCRIPT_DIR/scan_npm.py" "${SCAN_ARGS[@]}" || STATUS=$?
        classify_exit "$STATUS"
    fi

    if [[ -n "$HUNT_SCRIPT" ]]; then
        STATUS=0
        python3 "$HUNT_SCRIPT" --root "$TMPDIR/$repo" || STATUS=$?
        classify_exit "$STATUS"
    fi

    if [[ "$GIT_HISTORY" == true ]]; then
        GIT_STATUS=0
        COMMIT_HITS="$(check_git_history "$TMPDIR/$repo")" || GIT_STATUS=$?
        if [[ "$GIT_STATUS" -ne 0 ]]; then
            echo "  SCAN ERROR: git log failed, commit history was not checked"
            REPO_ERROR=true
        elif [[ -n "$COMMIT_HITS" ]]; then
            echo "$COMMIT_HITS"
            REPO_HIT=true
        fi
    fi

    if [[ "$REPO_HIT" == true ]]; then
        HIT_REPOS+=("$(repo_label "$repo")")
    elif [[ "$REPO_WARN" == true ]]; then
        WARN_REPOS+=("$(repo_label "$repo")")
    fi
    if [[ "$REPO_ERROR" == true ]]; then
        ERROR_REPOS+=("$(repo_label "$repo")")
    fi
done

# Summary
echo ""
echo "========================================="
echo "SCAN SUMMARY for $ORG"
echo "========================================="
echo "Total repos scanned: $TOTAL"
echo "Repos with critical hits: ${#HIT_REPOS[@]}"
if [[ ${#HIT_REPOS[@]} -gt 0 ]]; then
    for r in "${HIT_REPOS[@]}"; do
        echo "  - $r"
    done
fi
if [[ ${#WARN_REPOS[@]} -gt 0 ]]; then
    echo "Repos with warnings only: ${#WARN_REPOS[@]}"
    for r in "${WARN_REPOS[@]}"; do
        echo "  - $r"
    done
fi
if [[ ${#SUSPICIOUS_DESC[@]} -gt 0 ]]; then
    echo "Suspicious repo descriptions: ${#SUSPICIOUS_DESC[@]} (reported even if the repo was skipped)"
    for r in "${SUSPICIOUS_DESC[@]}"; do
        echo "  - $r"
    done
fi
if [[ ${#UNKNOWN_ARCHIVED[@]} -gt 0 ]]; then
    echo "Archive status unknown: ${#UNKNOWN_ARCHIVED[@]} (scanned, not tagged)"
    for r in "${UNKNOWN_ARCHIVED[@]}"; do
        echo "  - $r"
    done
fi
if [[ ${#ERROR_REPOS[@]} -gt 0 ]]; then
    echo "Repos with scan errors: ${#ERROR_REPOS[@]}"
    for r in "${ERROR_REPOS[@]}"; do
        echo "  - $r"
    done
fi
if [[ ${#SKIPPED_ARCHIVED[@]} -gt 0 ]]; then
    echo "Skipped (archived):  ${#SKIPPED_ARCHIVED[@]}"
fi
if [[ ${#FAILED_CLONE[@]} -gt 0 ]]; then
    echo "Failed to clone:     ${#FAILED_CLONE[@]}"
    for r in "${FAILED_CLONE[@]}"; do
        echo "  - $r"
    done
fi
echo "========================================="

if [[ ${#HIT_REPOS[@]} -gt 0 || ${#SUSPICIOUS_DESC[@]} -gt 0 ]]; then
    exit 1
fi
if [[ ${#ERROR_REPOS[@]} -gt 0 || ${#FAILED_CLONE[@]} -gt 0 ]]; then
    exit 2
fi
if [[ ${#WARN_REPOS[@]} -gt 0 ]]; then
    exit 3
fi
exit 0

#!/usr/bin/env bash
# Open, update or clear the single `qa-found` alert issue for the nightly
# `qa smoke` job (#625).
#
# Usage:
#   qa-alert.sh report [--log FILE] [--dry-run]
#   qa-alert.sh clear [--dry-run]
#
# `report` opens the alert issue, or comments on it (reopening it if a
# previous green run closed it), so repeated red nights update one issue
# instead of filing duplicates. `clear` closes it after a later green run.
#
# The workflow only calls this for `refs/heads/main` failures and guards
# against a cancelled run, so a manual dispatch on a feature branch neither
# opens nor closes the alert for main. `--dry-run` prints the issue body and
# the command it would run without calling the API; that is how the failure
# path is exercised locally.
#
# Reads the standard Actions environment: GITHUB_REPOSITORY, GITHUB_RUN_ID,
# GITHUB_SHA, GITHUB_EVENT_NAME and GITHUB_SERVER_URL.
# Requires GH_TOKEN with issues:write (the workflow grants it job-level).
set -euo pipefail

TITLE="qa smoke failed on main"
LABEL="qa-found"
MAX_LINES=25

LOG=""
DRY_RUN=false
COMMAND="${1:-}"
if [ $# -gt 0 ]; then
  shift
fi

usage() {
  cat <<'EOF'
usage: qa-alert.sh report [--log FILE] [--dry-run]
       qa-alert.sh clear [--dry-run]
EOF
}

while [ $# -gt 0 ]; do
  case "$1" in
    --log)
      LOG="${2:-}"
      if [ -z "$LOG" ]; then
        echo "qa-alert: --log needs a file" >&2
        exit 2
      fi
      shift 2
      ;;
    --dry-run)
      DRY_RUN=true
      shift
      ;;
    -h | --help)
      usage
      exit 0
      ;;
    *)
      echo "qa-alert: unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

case "$COMMAND" in
  report | clear) ;;
  -h | --help)
    usage
    exit 0
    ;;
  *)
    echo "qa-alert: expected 'report' or 'clear'" >&2
    usage >&2
    exit 2
    ;;
esac

: "${GH_REPO:=${GITHUB_REPOSITORY:-}}"
if [ -z "$GH_REPO" ]; then
  echo "qa-alert: GH_REPO or GITHUB_REPOSITORY is required" >&2
  exit 2
fi

# The newest issue carrying the exact alert title, as "<number> <state>".
existing_issue() {
  local state="$1"
  gh issue list --repo "$GH_REPO" --state "$state" --label "$LABEL" \
    --search "in:title \"$TITLE\"" --limit 100 --json number,title,state \
    --jq 'map(select(.title == "'"$TITLE"'")) | .[0] // empty | "\(.number) \(.state)"'
}

build_body() {
  local run_url failing excerpt
  run_url="${GITHUB_SERVER_URL:-https://github.com}/$GH_REPO/actions/runs/${GITHUB_RUN_ID:-unknown}"

  if [ -n "$LOG" ] && [ -f "$LOG" ]; then
    # The smoke names the failing step on its first failure line; the block
    # below it is the captured CLI output that explains it.
    failing="$(grep -m 1 '^qa smoke FAILED' "$LOG" || true)"
    excerpt="$(
      awk -v max="$MAX_LINES" \
        '/^qa smoke FAILED/{found=1} found && n < max {print; n++}' "$LOG"
    )"
  fi
  if [ -z "${failing:-}" ]; then
    failing="qa smoke did not reach a failing step (the job may have failed before the smoke ran)."
  fi
  if [ -z "${excerpt:-}" ]; then
    excerpt="(no smoke output captured; see the run link)"
  fi

  printf '%s\n' \
    "The \`qa smoke\` run failed on \`main\`." \
    "" \
    "- Run: $run_url" \
    "- Commit: \`${GITHUB_SHA:-unknown}\`" \
    "- Trigger: \`${GITHUB_EVENT_NAME:-unknown}\`" \
    "" \
    "### Failing step" \
    "" \
    '```' \
    "$failing" \
    '```' \
    "" \
    "<details><summary>Output from the failure onward (first $MAX_LINES lines)</summary>" \
    "" \
    '```' \
    "$excerpt" \
    '```' \
    "" \
    "</details>" \
    "" \
    "This issue is managed by the \`qa smoke\` job in \`.github/workflows/ci.yml\` (#625): a repeated failure updates this issue, and a later green run on \`main\` closes it."
}

report() {
  local body existing number state
  body="$(build_body)"

  if [ "$DRY_RUN" = true ]; then
    echo "[dry-run] would open, reopen or update '$TITLE' in $GH_REPO"
    echo "[dry-run] body:"
    printf '%s\n' "$body"
    return 0
  fi

  # `--force` is idempotent: it updates the label if a human already made it.
  gh label create "$LABEL" --repo "$GH_REPO" --force --color "d73a4a" \
    --description "Found by the QA sweep or the nightly qa smoke" >/dev/null

  existing="$(existing_issue all)"
  if [ -z "$existing" ]; then
    gh issue create --repo "$GH_REPO" --title "$TITLE" --label "$LABEL" --body "$body"
    return 0
  fi

  number="${existing%% *}"
  state="${existing##* }"
  if [ "$state" = "OPEN" ]; then
    gh issue comment "$number" --repo "$GH_REPO" --body "$body"
  else
    gh issue reopen "$number" --repo "$GH_REPO" --comment "$body"
  fi
}

clear() {
  local existing number
  existing="$(existing_issue open)"
  if [ -z "$existing" ]; then
    echo "qa-alert: no open '$TITLE' issue to clear"
    return 0
  fi
  number="${existing%% *}"

  if [ "$DRY_RUN" = true ]; then
    echo "[dry-run] would close #$number ('$TITLE') in $GH_REPO"
    return 0
  fi

  gh issue close "$number" --repo "$GH_REPO" \
    --comment "A later \`qa smoke\` run on \`main\` passed; closing the alert."
}

case "$COMMAND" in
  report) report ;;
  clear) clear ;;
esac

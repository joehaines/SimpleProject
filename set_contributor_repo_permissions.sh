#!/usr/bin/env bash
# set_contributor_repo_permissions.sh
# Reads a CSV of Azure DevOps projects (ProjectName, ProjectID) and sets
# DENY on "Delete or disable repository" for the Contributors group in each project.
#
# Usage:
#   ./set_contributor_repo_permissions.sh <CSV_FILE> [ORGANISATION]
#
# Authentication:
#   export AZURE_DEVOPS_PAT=<your-pat>   (needs "Security" read/write + "Graph" read)
#
# The permission applies at the project level, covering all repositories
# in that project.
#
# Dependencies: curl, jq (brew install curl jq)

set -euo pipefail

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
die()         { echo "ERROR: $*" >&2; exit 1; }
require_cmd() { command -v "$1" >/dev/null 2>&1 || die "'$1' not found. Install with: brew install $1"; }
log()         { echo "[$(date '+%H:%M:%S')] $*"; }

# ---------------------------------------------------------------------------
# Prerequisites
# ---------------------------------------------------------------------------
require_cmd curl
require_cmd jq

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
CSV_FILE="${1:-}"
ORGANISATION="${2:-${AZURE_DEVOPS_ORG:-}}"
PAT="${AZURE_DEVOPS_PAT:-}"

if [[ -z "$CSV_FILE" ]]; then
  echo "Usage: $0 <csv_file> [organisation]" >&2
  echo "       CSV must have columns: ProjectName,ProjectID" >&2
  exit 1
fi

[[ -f "$CSV_FILE" ]] || die "CSV file not found: $CSV_FILE"

if [[ -z "$ORGANISATION" ]]; then
  die "Organisation not specified. Pass it as the second argument or set AZURE_DEVOPS_ORG."
fi

if [[ -z "$PAT" ]]; then
  die "AZURE_DEVOPS_PAT is not set. Create a PAT with Security (read/write) and Graph (read) scopes."
fi

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
# Git Repositories security namespace ID (stable across all Azure DevOps orgs)
GIT_NAMESPACE_ID="2e9eb7ed-3c0a-47d4-87c1-0ffdd275fd87"

AUTH_HEADER="Authorization: Basic $(printf ":%s" "$PAT" | base64)"
API_VERSION="api-version=7.1"

# ---------------------------------------------------------------------------
# Resolve the "Delete repository" permission bit from the namespace definition
# ---------------------------------------------------------------------------
log "Resolving security namespace permissions..."
ns_response=$(curl --silent --fail --show-error \
  --header "$AUTH_HEADER" \
  "https://dev.azure.com/${ORGANISATION}/_apis/securitynamespaces/${GIT_NAMESPACE_ID}?${API_VERSION}") \
  || die "Failed to fetch security namespace. Check your PAT and organisation."

DELETE_BIT=$(echo "$ns_response" | \
  jq '.value[0].actions[] | select(.name == "DeleteRepository") | .bit')

[[ -n "$DELETE_BIT" && "$DELETE_BIT" != "null" ]] \
  || die "Could not find DeleteRepository permission bit in namespace response."

log "DeleteRepository permission bit: ${DELETE_BIT}"

# ---------------------------------------------------------------------------
# Helper: resolve the full ACE identity descriptor for the Contributors group.
# Returns the descriptor in "Microsoft.TeamFoundation.Identity;S-1-9-..." form.
# Args: project_name project_id
# Prints an error and returns 1 on failure (does not exit the script).
# ---------------------------------------------------------------------------
get_contributors_ace_descriptor() {
  local project_name="$1"
  local project_id="$2"

  # The identities API can look up the Contributors group directly using
  # the well-known display name "[ProjectName]\Contributors".
  # Using curl --get --data-urlencode handles special characters in names cleanly.
  local identity_resp ace_descriptor
  identity_resp=$(curl --silent --fail --show-error \
    --get \
    --header "$AUTH_HEADER" \
    --data-urlencode "searchFilter=General" \
    --data-urlencode "filterValue=[${project_name}]\Contributors" \
    --data-urlencode "queryMembership=None" \
    "https://vssps.dev.azure.com/${ORGANISATION}/_apis/identities?${API_VERSION}") \
    || { echo "  ERROR: identities API request failed for project '${project_name}'" >&2; return 1; }

  ace_descriptor=$(echo "$identity_resp" | jq -r '.value[0].descriptor // empty')
  [[ -n "$ace_descriptor" ]] \
    || { echo "  ERROR: Contributors group not found for project '${project_name}'" >&2; return 1; }

  echo "$ace_descriptor"
}

# ---------------------------------------------------------------------------
# Process each project from the CSV
# ---------------------------------------------------------------------------
success=0
failure=0

# Verify the CSV has data rows before entering the loop
data_rows=$(tail -n +2 "$CSV_FILE" | tr -d '\r' | grep -c '.' || true)
log "CSV file: ${CSV_FILE} (${data_rows} data rows)"
if [[ "$data_rows" -gt 0 ]]; then
  log "First data row: $(tail -n +2 "$CSV_FILE" | tr -d '\r' | head -1)"
fi

if [[ "$data_rows" -eq 0 ]]; then
  echo "No data rows found in CSV. Run enumerate_ado_projects.sh first."
  exit 1
fi

# Pre-process CSV to a temp file so the pipeline fully completes before read
# starts, avoiding process-substitution / pipefail timing issues.
tmp_csv=$(mktemp)
tail -n +2 "$CSV_FILE" | tr -d '\r' > "$tmp_csv"

# The '|| [[ -n "${raw_name:-}" ]]' handles files whose last line has no
# trailing newline: read populates the variables but returns 1 at EOF.
while IFS=',' read -r raw_name raw_id || [[ -n "${raw_name:-}" ]]; do
  # Strip surrounding quotes added by the enumerator script
  project_name="${raw_name//\"/}"
  project_id="${raw_id//\"/}"

  if [[ -z "$project_id" ]]; then continue; fi

  log "Processing: ${project_name} (${project_id})"

  # Resolve Contributors identity descriptor
  ace_descriptor=$(get_contributors_ace_descriptor "$project_name" "$project_id") || {
    log "  SKIP – could not resolve Contributors group"
    failure=$((failure + 1))
    continue
  }

  security_token="repoV2/${project_id}"

  # Build the ACE payload – merge=true preserves any existing allow bits
  ace_body=$(jq -n \
    --arg token "$security_token" \
    --arg desc  "$ace_descriptor" \
    --argjson deny "$DELETE_BIT" \
    '{
      token: $token,
      merge: true,
      accessControlEntries: [{
        descriptor: $desc,
        allow: 0,
        deny: $deny
      }]
    }')

  # Apply the ACE
  result=$(curl --silent --fail --show-error \
    --request POST \
    --header "$AUTH_HEADER" \
    --header "Content-Type: application/json" \
    --data "$ace_body" \
    "https://dev.azure.com/${ORGANISATION}/_apis/accesscontrolentries/${GIT_NAMESPACE_ID}?${API_VERSION}") \
    || { log "  FAIL – API call to set ACE failed"; failure=$((failure + 1)); continue; }

  applied=$(echo "$result" | jq '.value | length')
  if [[ "$applied" -gt 0 ]]; then
    log "  OK   – DENY DeleteRepository set for Contributors"
    success=$((success + 1))
  else
    log "  WARN – API responded but no ACE was returned"
    failure=$((failure + 1))
  fi

done < "$tmp_csv"

rm -f "$tmp_csv"

echo ""
echo "Done. Success: ${success}  Failed/skipped: ${failure}"

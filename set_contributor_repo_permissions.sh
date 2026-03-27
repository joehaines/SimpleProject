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
# Helper: get the Contributors group descriptor for a project
# ---------------------------------------------------------------------------
get_contributors_descriptor() {
  local project_id="$1"

  # Step 1 – project scope descriptor
  local scope_resp
  scope_resp=$(curl --silent --fail --show-error \
    --header "$AUTH_HEADER" \
    "https://vssps.dev.azure.com/${ORGANISATION}/_apis/graph/descriptors/${project_id}?${API_VERSION}") \
    || die "Failed to get scope descriptor for project ${project_id}"

  local scope_descriptor
  scope_descriptor=$(echo "$scope_resp" | jq -r '.value')
  [[ -n "$scope_descriptor" && "$scope_descriptor" != "null" ]] \
    || die "Empty scope descriptor for project ${project_id}"

  # Step 2 – list groups in project scope, find Contributors
  local groups_resp
  groups_resp=$(curl --silent --fail --show-error \
    --header "$AUTH_HEADER" \
    "https://vssps.dev.azure.com/${ORGANISATION}/_apis/graph/groups?scopeDescriptor=${scope_descriptor}&${API_VERSION}") \
    || die "Failed to list groups for project ${project_id}"

  local group_descriptor
  group_descriptor=$(echo "$groups_resp" | \
    jq -r '.value[] | select(.displayName == "Contributors") | .descriptor' | head -1)

  [[ -n "$group_descriptor" ]] \
    || die "Contributors group not found for project ${project_id}"

  # Step 3 – resolve the storage key (identity GUID) for the group
  local key_resp
  key_resp=$(curl --silent --fail --show-error \
    --header "$AUTH_HEADER" \
    "https://vssps.dev.azure.com/${ORGANISATION}/_apis/graph/storagekeys/${group_descriptor}?${API_VERSION}") \
    || die "Failed to get storage key for Contributors group in project ${project_id}"

  local storage_key
  storage_key=$(echo "$key_resp" | jq -r '.value')
  [[ -n "$storage_key" && "$storage_key" != "null" ]] \
    || die "Empty storage key for Contributors group in project ${project_id}"

  echo "$storage_key"
}

# ---------------------------------------------------------------------------
# Process each project from the CSV
# ---------------------------------------------------------------------------
success=0
failure=0

# Skip header row; handle both LF and CRLF line endings
tail -n +2 "$CSV_FILE" | tr -d '\r' | while IFS=',' read -r raw_name raw_id; do
  # Strip surrounding quotes added by the enumerator script
  project_name="${raw_name//\"/}"
  project_id="${raw_id//\"/}"

  [[ -z "$project_id" ]] && continue

  log "Processing: ${project_name} (${project_id})"

  # Resolve Contributors identity
  storage_key=$(get_contributors_descriptor "$project_id") || {
    log "  SKIP – could not resolve Contributors group"
    failure=$((failure + 1))
    continue
  }

  identity_descriptor="Microsoft.TeamFoundation.Identity;${storage_key}"
  security_token="repoV2/${project_id}"

  # Build the ACE payload – merge=true preserves existing allow bits
  ace_body=$(jq -n \
    --arg token  "$security_token" \
    --arg desc   "$identity_descriptor" \
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
done

echo ""
echo "Done. Success: ${success}  Failed/skipped: ${failure}"

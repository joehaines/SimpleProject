#!/usr/bin/env bash
# enumerate_ado_projects.sh
# Lists all projects in an Azure DevOps organisation using the REST API.
#
# Usage:
#   ./enumerate_ado_projects.sh [ORGANISATION]
#
# Authentication:
#   Set AZURE_DEVOPS_PAT to a Personal Access Token with "Read" access on
#   the "Project and Team" scope, or pass it via the environment:
#
#     export AZURE_DEVOPS_PAT=<your-pat>
#     ./enumerate_ado_projects.sh myorg
#
# Dependencies: curl, jq (both available via Homebrew: brew install curl jq)

set -euo pipefail

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
die() { echo "ERROR: $*" >&2; exit 1; }

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "'$1' is required but not installed. Install with: brew install $1"
}

# ---------------------------------------------------------------------------
# Prerequisites
# ---------------------------------------------------------------------------
require_cmd curl
require_cmd jq

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
ORGANISATION="${1:-${AZURE_DEVOPS_ORG:-}}"
PAT="${AZURE_DEVOPS_PAT:-}"

if [[ -z "$ORGANISATION" ]]; then
  echo "Usage: $0 <organisation>" >&2
  echo "       or set AZURE_DEVOPS_ORG in the environment" >&2
  exit 1
fi

if [[ -z "$PAT" ]]; then
  die "AZURE_DEVOPS_PAT environment variable is not set.\n" \
      "Create a PAT at: https://dev.azure.com/${ORGANISATION}/_usersSettings/tokens\n" \
      "Then run:  export AZURE_DEVOPS_PAT=<your-pat>"
fi

API_BASE="https://dev.azure.com/${ORGANISATION}/_apis"
API_VERSION="api-version=7.1"
AUTH_HEADER="Authorization: Basic $(printf ":%s" "$PAT" | base64)"

# ---------------------------------------------------------------------------
# Fetch projects (handles continuation tokens for large orgs)
# ---------------------------------------------------------------------------
echo "Fetching projects for organisation: ${ORGANISATION}"
echo "------------------------------------------------------"

all_projects=()
continuation_token=""

while true; do
  url="${API_BASE}/projects?${API_VERSION}&\$top=100"
  [[ -n "$continuation_token" ]] && url+="&continuationToken=${continuation_token}"

  response=$(curl --silent --fail --show-error \
    --header "$AUTH_HEADER" \
    --header "Content-Type: application/json" \
    "$url") || die "API request failed. Check your PAT and organisation name."

  # Extract projects from this page
  mapfile -t page_projects < <(echo "$response" | jq -r '.value[] | "\(.name)\t\(.state)\t\(.visibility)\t\(.id)"')
  all_projects+=("${page_projects[@]}")

  # Check for a continuation token in the response (may be absent)
  continuation_token=$(echo "$response" | jq -r '.continuationToken // empty')
  [[ -z "$continuation_token" ]] && break
done

total=${#all_projects[@]}

if [[ $total -eq 0 ]]; then
  echo "No projects found."
  exit 0
fi

# ---------------------------------------------------------------------------
# Display results
# ---------------------------------------------------------------------------
printf "%-40s %-12s %-12s %s\n" "NAME" "STATE" "VISIBILITY" "ID"
printf "%-40s %-12s %-12s %s\n" "----" "-----" "----------" "--"

for project in "${all_projects[@]}"; do
  IFS=$'\t' read -r name state visibility id <<< "$project"
  printf "%-40s %-12s %-12s %s\n" "$name" "$state" "$visibility" "$id"
done

echo ""
echo "Total projects: ${total}"

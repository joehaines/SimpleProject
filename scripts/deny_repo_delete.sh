#!/usr/bin/env bash
# deny_repo_delete.sh
#
# Enumerates all repositories in a GitHub org, lists all teams and outside
# collaborators that have access, and for each downgrades any "admin" permission
# to "maintain" (which removes the ability to delete/transfer the repo while
# keeping push + settings access).
#
# Also sets the org-wide flag that prevents members from deleting repos.
#
# Requirements (macOS):
#   brew install jq
#
# Usage:
#   export GITHUB_TOKEN=ghp_...
#   export GITHUB_ORG=my-org
#   ./deny_repo_delete.sh            # dry-run (shows what would change)
#   ./deny_repo_delete.sh --apply    # actually applies the changes

set -euo pipefail

# ── Colour helpers ────────────────────────────────────────────────────────────
RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

info()    { echo -e "${CYAN}[INFO]${RESET}  $*"; }
warn()    { echo -e "${YELLOW}[WARN]${RESET}  $*"; }
success() { echo -e "${GREEN}[OK]${RESET}    $*"; }
changed() { echo -e "${BOLD}[CHANGE]${RESET} $*"; }
err()     { echo -e "${RED}[ERROR]${RESET} $*" >&2; }

# ── CLI flags ─────────────────────────────────────────────────────────────────
APPLY=false
for arg in "$@"; do
  [[ "$arg" == "--apply" ]] && APPLY=true
done

if $APPLY; then
  warn "Running in APPLY mode – changes will be written to GitHub."
else
  info "Running in DRY-RUN mode. Pass --apply to make changes."
fi

# ── Prerequisites ─────────────────────────────────────────────────────────────
for cmd in curl jq; do
  if ! command -v "$cmd" &>/dev/null; then
    err "'$cmd' is required. Install with: brew install $cmd"
    exit 1
  fi
done

# ── Auth & org ────────────────────────────────────────────────────────────────
: "${GITHUB_TOKEN:?Set GITHUB_TOKEN to a Personal Access Token with admin:org + repo scopes}"
: "${GITHUB_ORG:?Set GITHUB_ORG to your GitHub organisation name}"

API="https://api.github.com"
AUTH_HEADER="Authorization: Bearer ${GITHUB_TOKEN}"
ACCEPT_HEADER="Accept: application/vnd.github+json"
API_VERSION_HEADER="X-GitHub-Api-Version: 2022-11-28"

# ── Generic paginated GET helper ──────────────────────────────────────────────
# Usage: gh_get_all <path>
# Returns: concatenated JSON array across all pages
gh_get_all() {
  local path="$1"
  local page=1
  local per_page=100
  local result="[]"

  while true; do
    local url="${API}${path}?per_page=${per_page}&page=${page}"
    local response
    response=$(curl -sf -H "$AUTH_HEADER" -H "$ACCEPT_HEADER" -H "$API_VERSION_HEADER" "$url" || true)

    if [[ -z "$response" || "$response" == "null" || "$response" == "[]" ]]; then
      break
    fi

    local count
    count=$(echo "$response" | jq 'length')
    result=$(echo "$result $response" | jq -s 'add')

    [[ "$count" -lt "$per_page" ]] && break
    (( page++ ))
  done

  echo "$result"
}

# ── Generic PATCH / PUT helper ────────────────────────────────────────────────
gh_patch() {
  local url="$1"
  local body="$2"
  curl -sf -X PATCH \
    -H "$AUTH_HEADER" -H "$ACCEPT_HEADER" -H "$API_VERSION_HEADER" \
    -H "Content-Type: application/json" \
    -d "$body" "$url" > /dev/null
}

gh_put() {
  local url="$1"
  local body="$2"
  curl -sf -X PUT \
    -H "$AUTH_HEADER" -H "$ACCEPT_HEADER" -H "$API_VERSION_HEADER" \
    -H "Content-Type: application/json" \
    -d "$body" "$url" > /dev/null
}

# ── 1. Org-wide: disable member-initiated repo deletion ───────────────────────
echo ""
echo -e "${BOLD}══ Step 1: Org-wide repository deletion setting ══${RESET}"

ORG_DATA=$(curl -sf -H "$AUTH_HEADER" -H "$ACCEPT_HEADER" -H "$API_VERSION_HEADER" \
  "${API}/orgs/${GITHUB_ORG}")

MEMBERS_CAN_DELETE=$(echo "$ORG_DATA" | jq -r '.members_can_delete_repositories // "unknown"')
info "members_can_delete_repositories = ${MEMBERS_CAN_DELETE}"

if [[ "$MEMBERS_CAN_DELETE" == "false" ]]; then
  success "Org already blocks member-initiated repository deletion."
else
  changed "Will set members_can_delete_repositories = false for org '${GITHUB_ORG}'"
  if $APPLY; then
    gh_patch "${API}/orgs/${GITHUB_ORG}" '{"members_can_delete_repositories":false}'
    success "Applied org-wide deletion restriction."
  fi
fi

# ── 2. Enumerate all repositories ────────────────────────────────────────────
echo ""
echo -e "${BOLD}══ Step 2: Enumerating repositories ══${RESET}"

REPOS=$(gh_get_all "/orgs/${GITHUB_ORG}/repos")
REPO_COUNT=$(echo "$REPOS" | jq 'length')
info "Found ${REPO_COUNT} repositories in '${GITHUB_ORG}'."

if [[ "$REPO_COUNT" -eq 0 ]]; then
  warn "No repositories found. Check your GITHUB_ORG and token scopes."
  exit 0
fi

# ── 3. Enumerate all teams ────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}══ Step 3: Enumerating teams (security groups) ══${RESET}"

TEAMS=$(gh_get_all "/orgs/${GITHUB_ORG}/teams")
TEAM_COUNT=$(echo "$TEAMS" | jq 'length')
info "Found ${TEAM_COUNT} teams in '${GITHUB_ORG}'."

# Print teams table
echo ""
printf "  %-40s %-20s\n" "Team Name" "Slug"
printf "  %-40s %-20s\n" "─────────────────────────────────────" "────────────────────"
echo "$TEAMS" | jq -r '.[] | "  \(.name | .[0:38] | . + (if (. | length) < 38 then "" else "…" end))\t\(.slug)"' \
  | awk -F'\t' '{ printf "  %-40s %-20s\n", $1, $2 }'

# ── 4. Per-repo: downgrade admin teams → maintain ─────────────────────────────
echo ""
echo -e "${BOLD}══ Step 4: Applying deny-delete to each repo ══${RESET}"

TOTAL_CHANGES=0
TOTAL_ALREADY_OK=0

while IFS= read -r repo_json; do
  REPO_NAME=$(echo "$repo_json" | jq -r '.name')
  REPO_FULL=$(echo "$repo_json" | jq -r '.full_name')

  echo ""
  echo -e "  ${BOLD}── Repo: ${REPO_FULL}${RESET}"

  # ── 4a. Teams with access to this repo ───────────────────────────────────
  REPO_TEAMS=$(gh_get_all "/repos/${REPO_FULL}/teams")

  if [[ "$(echo "$REPO_TEAMS" | jq 'length')" -eq 0 ]]; then
    info "    No teams directly assigned."
  else
    while IFS= read -r team_json; do
      TEAM_SLUG=$(echo "$team_json" | jq -r '.slug')
      TEAM_NAME=$(echo "$team_json" | jq -r '.name')
      PERMISSION=$(echo "$team_json" | jq -r '.permission')   # pull/push/maintain/admin
      # newer API returns a permissions object too
      HAS_ADMIN=$(echo "$team_json" | jq -r '.permissions.admin // false')

      if [[ "$PERMISSION" == "admin" || "$HAS_ADMIN" == "true" ]]; then
        changed "  Team '${TEAM_NAME}' (${TEAM_SLUG}) has ADMIN on ${REPO_NAME} → downgrade to 'maintain'"
        if $APPLY; then
          gh_put "${API}/orgs/${GITHUB_ORG}/teams/${TEAM_SLUG}/repos/${REPO_FULL}" \
            '{"permission":"maintain"}'
          success "    Downgraded."
        fi
        (( TOTAL_CHANGES++ )) || true
      else
        info "    Team '${TEAM_NAME}' permission='${PERMISSION}' – no change needed."
        (( TOTAL_ALREADY_OK++ )) || true
      fi
    done < <(echo "$REPO_TEAMS" | jq -c '.[]')
  fi

  # ── 4b. Outside collaborators with admin on this repo ────────────────────
  COLLABS=$(gh_get_all "/repos/${REPO_FULL}/collaborators?affiliation=outside")

  if [[ "$(echo "$COLLABS" | jq 'length')" -gt 0 ]]; then
    while IFS= read -r collab_json; do
      LOGIN=$(echo "$collab_json" | jq -r '.login')
      HAS_ADMIN=$(echo "$collab_json" | jq -r '.permissions.admin // false')

      if [[ "$HAS_ADMIN" == "true" ]]; then
        changed "  Outside collaborator '${LOGIN}' has ADMIN on ${REPO_NAME} → downgrade to 'maintain'"
        if $APPLY; then
          curl -sf -X PUT \
            -H "$AUTH_HEADER" -H "$ACCEPT_HEADER" -H "$API_VERSION_HEADER" \
            -H "Content-Type: application/json" \
            -d '{"permission":"maintain"}' \
            "${API}/repos/${REPO_FULL}/collaborators/${LOGIN}" > /dev/null
          success "    Downgraded."
        fi
        (( TOTAL_CHANGES++ )) || true
      fi
    done < <(echo "$COLLABS" | jq -c '.[]')
  fi

done < <(echo "$REPOS" | jq -c '.[]')

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}══ Summary ══${RESET}"
if $APPLY; then
  success "Applied ${TOTAL_CHANGES} permission downgrade(s). ${TOTAL_ALREADY_OK} were already safe."
else
  if [[ "$TOTAL_CHANGES" -gt 0 ]]; then
    warn "${TOTAL_CHANGES} permission(s) need downgrading. Re-run with --apply to fix."
  else
    success "No changes needed – all teams/collaborators are already below admin level."
  fi
  info "${TOTAL_ALREADY_OK} team/collaborator assignments already at safe permission levels."
fi
echo ""

<#
.SYNOPSIS
    Denies the "Delete repository" permission for the Contributors group in every Azure DevOps project.

.DESCRIPTION
    For each project in the organisation this script:
      1. Resolves the project-scoped Contributors security group.
      2. Converts that group to an identity descriptor usable in ACEs.
      3. Posts a Deny ACE for the Delete-repository bit (512) on the project-level
         Git Repositories security token  repoV2/<projectId>.

    Run with -WhatIf first to preview changes without applying them.

.PARAMETER Organization
    Your Azure DevOps organisation name (the part after dev.azure.com/).

.PARAMETER PAT
    A Personal Access Token with at minimum:
      - Project and Team: Read
      - Identity: Read
      - Security: Manage

.PARAMETER WhatIf
    Preview what would be changed without applying any ACE modifications.

.EXAMPLE
    .\Set-DenyRepoDelete.ps1 -Organization "myorg" -PAT $env:AZDO_PAT

.EXAMPLE
    .\Set-DenyRepoDelete.ps1 -Organization "myorg" -PAT $env:AZDO_PAT -WhatIf
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)]
    [string] $Organization,

    [Parameter(Mandatory)]
    [string] $PAT,

    [switch] $WhatIf
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
# Security namespace for Git Repositories
$GIT_NAMESPACE_ID = '2e9eb7ed-3c0a-47d4-87c1-0ffdd275fd87'

# Permission bit for "Delete repository"
# See: https://learn.microsoft.com/en-us/azure/devops/organizations/security/namespace-reference#git-repositories-namespace
$DELETE_REPO_BIT = 512

# ---------------------------------------------------------------------------
# Auth header
# ---------------------------------------------------------------------------
$encodedPAT = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes(":$PAT"))
$authHeaders = @{
    Authorization  = "Basic $encodedPAT"
    'Content-Type' = 'application/json'
    Accept         = 'application/json'
}

# ---------------------------------------------------------------------------
# Helper: GET wrapper with basic error surfacing
# ---------------------------------------------------------------------------
function Invoke-AzDoGet {
    param([string] $Url)
    try {
        Invoke-RestMethod -Uri $Url -Headers $authHeaders -Method Get
    } catch {
        Write-Error "GET $Url failed: $_"
    }
}

# ---------------------------------------------------------------------------
# Step 1 – enumerate all projects (handles pagination)
# ---------------------------------------------------------------------------
Write-Host "`n==> Fetching projects from organisation '$Organization'..." -ForegroundColor Cyan

$allProjects = [System.Collections.Generic.List[object]]::new()
$projectsUrl = "https://dev.azure.com/$Organization/_apis/projects?api-version=7.1&`$top=500"

do {
    $page = Invoke-AzDoGet -Url $projectsUrl
    $allProjects.AddRange([object[]]$page.value)
    $projectsUrl = $page.nextLink  # null when no further pages
} while ($projectsUrl)

Write-Host "    Found $($allProjects.Count) project(s).`n" -ForegroundColor Green

# ---------------------------------------------------------------------------
# Process each project
# ---------------------------------------------------------------------------
$successCount = 0
$skipCount    = 0
$errorCount   = 0

foreach ($project in $allProjects) {
    $projectName = $project.name
    $projectId   = $project.id

    Write-Host "--- Project: $projectName ($projectId)" -ForegroundColor Yellow

    try {
        # ------------------------------------------------------------------
        # Step 2 – resolve the project-level scope descriptor
        # ------------------------------------------------------------------
        $descriptorResp = Invoke-AzDoGet `
            -Url "https://vssps.dev.azure.com/$Organization/_apis/graph/descriptors/$projectId?api-version=7.1"
        $scopeDescriptor = $descriptorResp.value

        # ------------------------------------------------------------------
        # Step 3 – list all groups scoped to this project, find Contributors
        # ------------------------------------------------------------------
        $groupsResp = Invoke-AzDoGet `
            -Url "https://vssps.dev.azure.com/$Organization/_apis/graph/groups?scopeDescriptor=$scopeDescriptor&api-version=7.1"

        $contributorsGroup = $groupsResp.value |
            Where-Object { $_.displayName -eq 'Contributors' } |
            Select-Object -First 1

        if (-not $contributorsGroup) {
            Write-Warning "    No 'Contributors' group found – skipping."
            $skipCount++
            continue
        }

        Write-Host "    Contributors group: $($contributorsGroup.principalName)" -ForegroundColor Gray

        # ------------------------------------------------------------------
        # Step 4 – resolve the graph subject descriptor to an identity
        #          descriptor (format: Microsoft.TeamFoundation.Identity;SID)
        #          which is what the ACE API requires
        # ------------------------------------------------------------------
        $identityResp = Invoke-AzDoGet `
            -Url "https://vssps.dev.azure.com/$Organization/_apis/identities?subjectDescriptors=$($contributorsGroup.descriptor)&api-version=7.1"

        $identity = $identityResp.value | Select-Object -First 1
        if (-not $identity) {
            Write-Warning "    Could not resolve identity for Contributors – skipping."
            $skipCount++
            continue
        }

        $identityDescriptor = $identity.descriptor   # e.g. Microsoft.TeamFoundation.Identity;S-1-9-…

        # ------------------------------------------------------------------
        # Step 5 – apply Deny ACE on the project-level Git token
        #
        #   Token format: repoV2/<projectId>
        #   This covers ALL repositories inside the project.
        #   To target a single repo use: repoV2/<projectId>/<repoId>
        # ------------------------------------------------------------------
        $token = "repoV2/$projectId"

        $acePayload = @{
            token                = $token
            merge                = $true
            accessControlEntries = @(
                @{
                    descriptor = $identityDescriptor
                    allow      = 0
                    deny       = $DELETE_REPO_BIT
                }
            )
        } | ConvertTo-Json -Depth 10

        if ($WhatIf) {
            Write-Host "    [WhatIf] Would DENY Delete Repository on token '$token'" `
                       "for '$($contributorsGroup.principalName)'" -ForegroundColor DarkYellow
            $successCount++
        } else {
            $aceUrl = "https://dev.azure.com/$Organization/_apis/accesscontrolentries/$GIT_NAMESPACE_ID`?api-version=7.1"
            Invoke-RestMethod -Uri $aceUrl -Headers $authHeaders -Method Post -Body $acePayload | Out-Null
            Write-Host "    [OK] Deny Delete Repository applied." -ForegroundColor Green
            $successCount++
        }

    } catch {
        Write-Warning "    ERROR processing project '$projectName': $_"
        $errorCount++
    }
}

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
Write-Host "`n========================================" -ForegroundColor Cyan
if ($WhatIf) {
    Write-Host "WhatIf run complete (no changes made)." -ForegroundColor DarkYellow
} else {
    Write-Host "Run complete." -ForegroundColor Cyan
}
Write-Host "  Applied/previewed : $successCount"
Write-Host "  Skipped           : $skipCount"
Write-Host "  Errors            : $errorCount"
Write-Host "========================================`n" -ForegroundColor Cyan

<#
.SYNOPSIS
    Enumerate (and optionally revoke) a compromised user's Azure DevOps PATs and SSH keys.

.DESCRIPTION
    Uses the Azure DevOps Token Administration REST API to list all personal
    access tokens (isPublic=false) and SSH public keys (isPublic=true) for a
    target user, org-wide. Report-only by default; revocation is gated behind
    -Revoke with per-token confirmation (ConfirmImpact High).

    REQUIREMENTS
      - Caller must be an Azure DevOps organization administrator (PCA) or hold
        the Entra 'Azure DevOps Administrator' role.
      - Auth: either Azure CLI signed in (default; token acquired via
        `az account get-access-token`) or an admin PAT via -AdminPat.
        Run from a CLEAN machine - never from the compromised endpoint.

.PARAMETER Organization
    Azure DevOps organization name (the {org} in https://dev.azure.com/{org}).

.PARAMETER UserPrincipalName
    UPN / email of the compromised user.

.PARAMETER AdminPat
    Optional admin PAT (scope: Token Administration). If omitted, Azure CLI is used.

.PARAMETER Revoke
    Revoke every valid token found. Prompts for confirmation. Omit for report-only.

.PARAMETER IncludeExpired
    Also list tokens that are already expired/invalid (for the incident timeline).

.PARAMETER OutputPath
    JSON report path. Default: .\DevOpsTokenSweep_<user>_<timestamp>.json

.EXAMPLE
    # Report only
    .\Invoke-DevOpsTokenSweep.ps1 -Organization contoso -UserPrincipalName dev@contoso.com

.EXAMPLE
    # Revoke everything valid, with confirmation
    .\Invoke-DevOpsTokenSweep.ps1 -Organization contoso -UserPrincipalName dev@contoso.com -Revoke

.NOTES
    Exit 0 = ran clean, no valid tokens found
    Exit 1 = valid tokens found (and/or revoked - see report)
    Exit 2 = error (auth, permissions, user not found)

    API reference: Token Administration REST API (vssps.dev.azure.com,
    tokenadmin/personalaccesstokens + tokenadmin/revocations, api-version 7.1-preview.1).
#>
[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory)][string]$Organization,
    [Parameter(Mandatory)][string]$UserPrincipalName,
    [string]$AdminPat,
    [switch]$Revoke,
    [switch]$IncludeExpired,
    [string]$OutputPath = ".\DevOpsTokenSweep_$($UserPrincipalName -replace '[@.]','_')_$(Get-Date -Format 'yyyyMMdd-HHmmss').json"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Organization must be the org slug from https://dev.azure.com/{org} — not a URL, path, or script name.
$Organization = $Organization.Trim().TrimEnd('/')
if ($Organization -match '^https?://') {
    if ($Organization -match 'dev\.azure\.com/([^/]+)') {
        $Organization = $Matches[1]
        Write-Warning "Stripped URL to organization slug: '$Organization'"
    } elseif ($Organization -match 'visualstudio\.com') {
        throw "Pass the organization name only (the {org} in https://dev.azure.com/{org}), not a full URL."
    } else {
        throw "-Organization looks like a URL. Pass only the org slug, e.g. -Organization contoso"
    }
}
if ($Organization -match '[\\/]|\.ps1$|^\.' ) {
    throw "-Organization '$Organization' looks like a file path. Pass the Azure DevOps org slug only, e.g. -Organization contoso"
}
if ($Organization -notmatch '^[A-Za-z0-9]([A-Za-z0-9\-]*[A-Za-z0-9])?$') {
    throw "-Organization '$Organization' is not a valid Azure DevOps organization name."
}

$BaseUri    = "https://vssps.dev.azure.com/$Organization"
$ApiVersion = '7.1-preview.1'
$AdoResourceId = '499b84ac-1321-427f-aa17-267ca6975798'   # Azure DevOps AAD resource ID (constant)

# ---------------------------------------------------------------------------
# Auth header
# ---------------------------------------------------------------------------
try {
    if ($AdminPat) {
        $b64 = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes(":$AdminPat"))
        $Headers = @{ Authorization = "Basic $b64" }
        Write-Verbose 'Authenticating with supplied admin PAT.'
    } else {
        $token = az account get-access-token --resource $AdoResourceId --query accessToken -o tsv 2>$null
        if (-not $token) { throw "Azure CLI token acquisition failed. Run 'az login' first, or supply -AdminPat." }
        $Headers = @{ Authorization = "Bearer $token" }
        Write-Verbose 'Authenticating with Azure CLI bearer token.'
    }
} catch {
    Write-Error "Authentication setup failed: $_"
    exit 2
}

# ---------------------------------------------------------------------------
# Resolve the user's subjectDescriptor
# ---------------------------------------------------------------------------
try {
    $idUri = "$BaseUri/_apis/identities?searchFilter=General&filterValue=$([uri]::EscapeDataString($UserPrincipalName))&queryMembership=None&api-version=7.1"
    $idResp = Invoke-RestMethod -Uri $idUri -Headers $Headers -Method Get
    $identity = @($idResp.value) | Where-Object {
        $_.properties.PSObject.Properties['Account'] -and
        $_.properties.Account.'$value' -eq $UserPrincipalName
    } | Select-Object -First 1
    if (-not $identity) { $identity = @($idResp.value) | Select-Object -First 1 }
    if (-not $identity) { throw "No identity found for '$UserPrincipalName' in org '$Organization'." }
    $descriptor = $identity.subjectDescriptor
    Write-Host "Resolved: $($identity.providerDisplayName) -> $descriptor" -ForegroundColor Cyan
} catch {
    Write-Error @"
Identity resolution failed for org '$Organization'.
  Request: $idUri
  Error:   $_
Hint: -Organization must be the org slug only (https://dev.azure.com/{org}), e.g. -Organization contoso
"@
    exit 2
}

# ---------------------------------------------------------------------------
# Enumerate session tokens (PATs and SSH public keys)
# ---------------------------------------------------------------------------
function Get-UserSessionTokens {
    param([bool]$IsPublic)   # $false = PATs, $true = SSH keys
    $tokens = @()
    $continuation = $null
    do {
        $uri = "$BaseUri/_apis/tokenadmin/personalaccesstokens/${descriptor}?isPublic=$($IsPublic.ToString().ToLower())&`$top=100&api-version=$ApiVersion"
        if ($continuation) { $uri += "&continuationToken=$([uri]::EscapeDataString($continuation))" }
        $resp = Invoke-RestMethod -Uri $uri -Headers $Headers -Method Get
        if ($resp.PSObject.Properties['value']) { $tokens += @($resp.value) }
        $continuation = if ($resp.PSObject.Properties['continuationToken']) { $resp.continuationToken } else { $null }
    } while ($continuation)
    # Caller wraps with @() so 0/1/N results are always a flat Object[].
    # Do NOT use "return ,$tokens" here — with N>1 that nests the array and
    # ForEach-Object then treats the whole list as a single $_ (breaks .validTo).
    return $tokens
}

try {
    # @() so .Count is safe under Set-StrictMode when the API returns 0 or 1 item.
    $pats    = @(Get-UserSessionTokens -IsPublic:$false)
    $sshKeys = @(Get-UserSessionTokens -IsPublic:$true)
} catch {
    Write-Error "Token enumeration failed (are you an org admin / Azure DevOps Administrator?): $_"
    exit 2
}

$now = (Get-Date).ToUniversalTime()
function Format-Token {
    param($Token, [string]$Kind)
    $validTo = [datetime]$Token.validTo
    [pscustomobject]@{
        Kind            = $Kind
        DisplayName     = $Token.displayName
        Scope           = $Token.scope
        ValidFrom       = $Token.validFrom
        ValidTo         = $Token.validTo
        IsValid         = ($Token.isValid -and $validTo -gt $now)
        AuthorizationId = $Token.authorizationId
        TargetAccounts  = ($Token.targetAccounts -join ';')
    }
}

$all = @(
    @($pats | ForEach-Object { Format-Token $_ 'PAT' }) +
    @($sshKeys | ForEach-Object { Format-Token $_ 'SSH' })
)
$valid = @($all | Where-Object IsValid)
$display = @(if ($IncludeExpired) { $all } else { $valid })

Write-Host "`n=== $UserPrincipalName @ $Organization : $($pats.Count) PAT(s), $($sshKeys.Count) SSH key(s) total; $($valid.Count) currently VALID ===" -ForegroundColor Cyan
if ($display.Count -gt 0) {
    $display | Format-Table Kind, DisplayName, Scope, ValidTo, IsValid, AuthorizationId -AutoSize
} else {
    Write-Host 'No tokens to display.' -ForegroundColor Green
}

# ---------------------------------------------------------------------------
# Revocation (opt-in, HITL)
# ---------------------------------------------------------------------------
$revoked = @()
if ($Revoke -and $valid.Count -gt 0) {
    foreach ($kind in @('PAT', 'SSH')) {
        $targets = @($valid | Where-Object Kind -eq $kind)
        if ($targets.Count -eq 0) { continue }
        $label = "$($targets.Count) valid $kind token(s) for $UserPrincipalName"
        if ($PSCmdlet.ShouldProcess($label, 'Revoke')) {
            $isPublic = ($kind -eq 'SSH').ToString().ToLower()
            $body = ConvertTo-Json @($targets | ForEach-Object { @{ authorizationId = $_.AuthorizationId } })
            $revUri = "$BaseUri/_apis/tokenadmin/revocations?isPublic=$isPublic&api-version=$ApiVersion"
            Invoke-RestMethod -Uri $revUri -Headers $Headers -Method Post -Body $body -ContentType 'application/json' | Out-Null
            $revoked += $targets
            Write-Host "Revoked $($targets.Count) $kind token(s)." -ForegroundColor Green
        }
    }
} elseif ($Revoke) {
    Write-Host 'Nothing valid to revoke.' -ForegroundColor Green
}

# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------
[pscustomobject]@{
    Organization      = $Organization
    UserPrincipalName = $UserPrincipalName
    SubjectDescriptor = $descriptor
    SweepTimeUtc      = $now.ToString('o')
    TotalPats         = $pats.Count
    TotalSshKeys      = $sshKeys.Count
    ValidCount        = $valid.Count
    RevokedCount      = $revoked.Count
    Tokens            = $all
    Revoked           = $revoked
} | ConvertTo-Json -Depth 5 | Out-File -FilePath $OutputPath -Encoding utf8
Write-Host "`nReport written: $OutputPath" -ForegroundColor Cyan

Write-Host @'

FOLLOW-UPS (not covered by this API):
  - OAuth app authorizations: user must review at https://dev.azure.com/{org}/_usersSettings/authorizations
    (or disable the Entra account, which invalidates everything at the IdP).
  - Service connection secrets / pipeline variable groups the user could read: rotate separately.
  - Multi-org: re-run per organization; PATs can be scoped to "All accessible organizations".
'@ -ForegroundColor Yellow

if ($valid.Count -gt 0) { exit 1 } else { exit 0 }

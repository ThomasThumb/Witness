<#
.SYNOPSIS
  BUILD_PLAN.md phase 2, step 3, the four cases that need Exploit Protection
  opt-in: ACG (`trigger rwx`), Block remote images (`trigger remote`),
  child-process block (`trigger child`), Block low-integrity images (`trigger lowil`).

.DESCRIPTION
  MUST run elevated: Set-ProcessMitigation and `net share` need it. Everything
  it changes is undone in a `finally` block: the two mitigations on trigger.exe
  and the read-only loopback share of tests\triggers. Witness itself runs as
  you, unelevated-equivalent (same profile, same DPAPI seed, same evidence dir).

  Results go to phase2-results\admin-summary.txt and admin-events-*.xml.
  Run scripts\phase2.ps1 first so trigger.exe and witness.exe exist.

  Run:  powershell -ExecutionPolicy Bypass -File scripts\phase2-admin.ps1   (as Administrator)
#>
param([switch]$CleanupOnly)
$ErrorActionPreference = 'Continue'
$root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$out = Join-Path $root 'phase2-results'
New-Item -ItemType Directory -Force -Path $out | Out-Null
$summary = Join-Path $out 'admin-summary.txt'
"phase2-admin run $(Get-Date -Format o) on $env:COMPUTERNAME" | Set-Content $summary

function Step($name, [scriptblock]$body) {
    try { $r = & $body; if ($r -is [string]) { "PASS  $name  $r" | Add-Content $summary } else { "PASS  $name" | Add-Content $summary } }
    catch { "FAIL  $name  $($_.Exception.Message)" | Add-Content $summary }
}

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) { "STOP  not elevated; right-click PowerShell > Run as administrator" | Add-Content $summary; Get-Content $summary; exit 1 }

$exe = Join-Path $root 'target\release\witness.exe'
$trigDir = Join-Path $root 'tests\triggers'
$trig = Join-Path $trigDir 'trigger.exe'
foreach ($f in $exe, $trig) { if (-not (Test-Path $f)) { "STOP  $f missing; run scripts\phase2.ps1 first" | Add-Content $summary; Get-Content $summary; exit 1 } }
$base = Join-Path $env:LOCALAPPDATA 'Witness'
$share = 'witnesstest'

function KernelEvents($since, $id) {
    Get-WinEvent -LogName 'Microsoft-Windows-Security-Mitigations/KernelMode' -ErrorAction SilentlyContinue |
        Where-Object { $_.TimeCreated -gt $since -and $_.Id -eq $id -and $_.ToXml() -match 'trigger\.exe' }
}
function FreshLog($epoch) {
    Get-Content (Join-Path $base 'witness.log') -ErrorAction SilentlyContinue | Where-Object { [int64]($_ -split ' ')[0] -ge $epoch }
}

# Set-ProcessMitigation writes to Image File Execution Options\trigger.exe. `-Remove`
# is fussy about its arguments across Windows builds; deleting the IFEO key for
# our own test binary is unambiguous and leaves nothing behind.
function Cleanup {
    & net share $share /delete 2>$null | Out-Null
    Set-ProcessMitigation -Name trigger.exe -Disable BlockDynamicCode, BlockRemoteImageLoads, BlockLowLabelImageLoads, DisallowChildProcessCreation -ErrorAction SilentlyContinue 3>$null
    Remove-Item (Join-Path $trigDir 'lowil-copy.exe') -Force -ErrorAction SilentlyContinue
    Remove-Item "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\trigger.exe" -Recurse -ErrorAction SilentlyContinue
    $left = Get-ProcessMitigation -Name trigger.exe -ErrorAction SilentlyContinue 3>$null
    $state = if ($left) { "DynamicCode=$($left.DynamicCode.BlockDynamicCode) RemoteImages=$($left.ImageLoad.BlockRemoteImageLoads) (NOTSET = clean)" } else { "no Exploit Protection entry for trigger.exe (clean)" }
    "INFO  cleanup: share removed; low-IL copy deleted; $state" | Add-Content $summary
}
if ($CleanupOnly) { Cleanup; Get-Content $summary; exit 0 }

$w = $null
try {
    Step 'opt-in' {
        Set-ProcessMitigation -Name trigger.exe -Enable BlockDynamicCode, BlockRemoteImageLoads, BlockLowLabelImageLoads, DisallowChildProcessCreation
        $m = Get-ProcessMitigation -Name trigger.exe
        "DynamicCode=$($m.DynamicCode.BlockDynamicCode) RemoteImages=$($m.ImageLoad.BlockRemoteImageLoads) LowIL=$($m.ImageLoad.BlockLowLabelImageLoads) Child=$($m.ChildProcess.DisallowChildProcessCreation)"
    }
    $lowil = Join-Path $trigDir 'lowil-copy.exe'
    Step 'low-integrity-copy' {
        Copy-Item $trig $lowil -Force
        $r = & icacls $lowil /setintegritylevel Low 2>&1
        if ($LASTEXITCODE -ne 0) { throw ($r -join ' ') }
        $lab = (& icacls $lowil) -join ' '
        if ($lab -notmatch 'Low Mandatory Level') { throw "label not applied: $lab" }
        'Low Mandatory Level'
    }
    Step 'share' {
        & net share $share /delete 2>$null | Out-Null
        $r = & net share "$share=$trigDir" /GRANT:Everyone,READ 2>&1
        if ($LASTEXITCODE -ne 0) { throw ($r -join ' ') }
        if (-not (Test-Path "\\localhost\$share\trigger.exe")) { throw "\\localhost\$share\trigger.exe not reachable (Server service running?)" }
        "\\localhost\$share"
    }

    $before = Get-Date
    $epoch = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds() - 1
    $w = Start-Process -FilePath $exe -ArgumentList 'run' -PassThru -WindowStyle Hidden
    Start-Sleep 3

    Step 'trigger-rwx-acg' {
        $p = Start-Process -FilePath $trig -ArgumentList 'rwx' -PassThru -Wait -WindowStyle Hidden
        Start-Sleep 5
        $ev = KernelEvents $before 2 | Select-Object -First 1
        if (-not $ev) { throw "trigger exit $($p.ExitCode); no KernelMode event 2 for trigger.exe (ACG opt-in not effective?)" }
        $ev.ToXml() | Set-Content (Join-Path $out 'admin-events-acg.xml')
        $m = FreshLog $epoch | Where-Object { $_ -match 'match acg-block-kernel' }
        if (-not $m) { throw "event 2 written but witness.log shows no acg-block-kernel match; log: $((FreshLog $epoch) -join ' || ')" }
        "exit $($p.ExitCode); KernelMode event 2; Witness matched acg-block-kernel"
    }
    Step 'trigger-child' {
        $p = Start-Process -FilePath $trig -ArgumentList 'child' -PassThru -Wait -WindowStyle Hidden
        Start-Sleep 5
        $ev = KernelEvents $before 4 | Select-Object -First 1
        if (-not $ev) { throw "trigger exit $($p.ExitCode) (0 = child ran, block not effective); no KernelMode event 4" }
        $ev.ToXml() | Set-Content (Join-Path $out 'admin-events-child.xml')
        $m = FreshLog $epoch | Where-Object { $_ -match 'match child-process-block' }
        if (-not $m) { throw "event 4 written but witness.log shows no child-process-block match; log: $((FreshLog $epoch) -join ' || ')" }
        "exit $($p.ExitCode); KernelMode event 4; Witness matched child-process-block"
    }
    Step 'trigger-lowil' {
        $p = Start-Process -FilePath $trig -ArgumentList @('lowil', $lowil) -PassThru -Wait -WindowStyle Hidden
        Start-Sleep 5
        $ev = KernelEvents $before 6 | Select-Object -First 1
        if (-not $ev) { throw "trigger exit $($p.ExitCode) (0 = load ALLOWED; 2 = refused but no event 6); no KernelMode event 6" }
        $ev.ToXml() | Set-Content (Join-Path $out 'admin-events-lowil.xml')
        $m = FreshLog $epoch | Where-Object { $_ -match 'match low-integrity-image-block' }
        if (-not $m) { throw "event 6 written but witness.log shows no low-integrity-image-block match; log: $((FreshLog $epoch) -join ' || ')" }
        "exit $($p.ExitCode); KernelMode event 6; Witness matched low-integrity-image-block"
    }
    Step 'trigger-remote-image' {
        $p = Start-Process -FilePath $trig -ArgumentList @('remote', "\\localhost\$share\trigger.exe") -PassThru -Wait -WindowStyle Hidden
        Start-Sleep 5
        $ev = KernelEvents $before 8 | Select-Object -First 1
        if (-not $ev) { throw "trigger exit $($p.ExitCode) (0 = load ALLOWED, mitigation not effective; 2 = refused but no event 8); check admin-summary" }
        $ev.ToXml() | Set-Content (Join-Path $out 'admin-events-remote.xml')
        $m = FreshLog $epoch | Where-Object { $_ -match 'match remote-image-block' }
        if (-not $m) { throw "event 8 written but witness.log shows no remote-image-block match; log: $((FreshLog $epoch) -join ' || ')" }
        "exit $($p.ExitCode); KernelMode event 8; Witness matched remote-image-block (urgent)"
    }
} finally {
    Start-Sleep 2
    if ($w -and -not $w.HasExited) { Stop-Process -Id $w.Id -Force }
    Cleanup
    Copy-Item (Join-Path $base 'witness.log') (Join-Path $out 'witness.log') -ErrorAction SilentlyContinue
    Get-Content $summary
}

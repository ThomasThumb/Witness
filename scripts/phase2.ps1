<#
.SYNOPSIS
  BUILD_PLAN.md phase 2, steps 1-2, as one reproducible run. No admin needed.

.DESCRIPTION
  Builds witness-win, runs `check`, `fingerprint`, `selftest`, verifies the
  selftest bundle, proves an edited bundle fails verification, compiles
  tests/triggers/trigger.c when MSVC is available, fires the two fast-fail
  triggers, and captures what the Event Log actually wrote for each.

  Everything is written to phase2-results\ next to this script's repo root:
    summary.txt       one line per step: PASS / FAIL / SKIP and why
    build.log         cargo output
    check.txt, fingerprint.txt, selftest.txt, verify*.txt
    witness.log       copy of %LOCALAPPDATA%\Witness\witness.log
    events-*.xml      raw EvtRender XML of the events the triggers produced
    evidence-list.txt bundles that appeared under %LOCALAPPDATA%\Witness\evidence

  Run from anywhere:  powershell -ExecutionPolicy Bypass -File scripts\phase2.ps1
#>
$ErrorActionPreference = 'Continue'
$root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$out = Join-Path $root 'phase2-results'
New-Item -ItemType Directory -Force -Path $out | Out-Null
$summary = Join-Path $out 'summary.txt'
"phase2 run $(Get-Date -Format o) on $env:COMPUTERNAME" | Set-Content $summary
"os: $((Get-CimInstance Win32_OperatingSystem).Caption) build $((Get-CimInstance Win32_OperatingSystem).BuildNumber)" | Add-Content $summary

function Step($name, [scriptblock]$body) {
    try {
        $r = & $body
        if ($r -is [string]) { "PASS  $name  $r" | Add-Content $summary } else { "PASS  $name" | Add-Content $summary }
    } catch {
        "FAIL  $name  $($_.Exception.Message)" | Add-Content $summary
    }
}
function Skip($name, $why) { "SKIP  $name  $why" | Add-Content $summary }
function Need($cmd) { if (-not (Get-Command $cmd -ErrorAction SilentlyContinue)) { throw "$cmd not on PATH" } }

# ---- toolchain -------------------------------------------------------------
Step 'toolchain' {
    Need cargo; Need rustc
    $v = (& rustc -V 2>&1) -join ' '
    $t = (& rustup show active-toolchain 2>&1) -join ' '
    "$v / $t"
}

# ---- build -----------------------------------------------------------------
$exe = Join-Path $root 'target\release\witness.exe'
Step 'build' {
    Push-Location $root
    try {
        & cargo build --release --locked -p witness-win *> (Join-Path $out 'build.log')
        if ($LASTEXITCODE -ne 0) { throw "cargo build exit $LASTEXITCODE; see build.log" }
        if (-not (Test-Path $exe)) { throw "witness.exe not produced" }
        "$([math]::Round((Get-Item $exe).Length / 1KB)) KB"
    } finally { Pop-Location }
}
if (-not (Test-Path $exe)) { "STOP  no binary; nothing else can run" | Add-Content $summary; Get-Content $summary; exit 1 }

# ---- self-hardening flags actually present in the PE? ----------------------
Step 'pe-flags' {
    $bytes = [IO.File]::ReadAllBytes($exe)
    $peOff = [BitConverter]::ToInt32($bytes, 0x3C)
    # DllCharacteristics sits at +70 in the optional header for both PE32 and PE32+.
    $dc = [BitConverter]::ToUInt16($bytes, $peOff + 24 + 70)
    $flags = @()
    if ($dc -band 0x0020) { $flags += 'HIGH_ENTROPY_VA' }
    if ($dc -band 0x0040) { $flags += 'DYNAMIC_BASE' }
    if ($dc -band 0x0100) { $flags += 'NX_COMPAT' }
    if ($dc -band 0x4000) { $flags += 'GUARD_CF' }
    if ($flags.Count -lt 4) { throw "DllCharacteristics=0x$($dc.ToString('X4')) missing: expected HIGH_ENTROPY_VA DYNAMIC_BASE NX_COMPAT GUARD_CF, got $($flags -join ',')" }
    ($flags -join ',') + " (CETCOMPAT lives in the load-config table; check with dumpbin /loadconfig)"
}

# ---- witness check / fingerprint / selftest --------------------------------
function RunW($name, [string[]]$argv) {
    # Run through cmd.exe so stdout+stderr land in the file byte-for-byte,
    # whatever the exit code; PowerShell 5.1 otherwise rewrites stderr as
    # error records (and drops them entirely when errors are silenced).
    $f = Join-Path $out "$name.txt"
    $quoted = ($argv | ForEach-Object { '"' + $_ + '"' }) -join ' '
    cmd /c "`"$exe`" $quoted > `"$f`" 2>&1"
    $code = $LASTEXITCODE
    $text = if (Test-Path $f) { [string](Get-Content $f -Raw) } else { '' }
    return @{ code = $code; text = $text }
}
Step 'check' {
    $r = RunW 'check' @('check')
    if ($r.code -ne 0) { throw "exit $($r.code): $($r.text)" }
    $unavailable = ($r.text -split "`n" | Where-Object { $_ -match 'UNAVAILABLE' })
    if ($unavailable) { throw "channel(s) unavailable: $($unavailable -join ' | ')" }
    ($r.text -split "`n" | Where-Object { $_ -match '^self:' }) -join ''
}
Step 'fingerprint' {
    $r = RunW 'fingerprint' @('fingerprint')
    if ($r.code -ne 0) { throw "exit $($r.code)" }
    ($r.text -split "`n")[0].Trim()
}
$base = Join-Path $env:LOCALAPPDATA 'Witness'
Step 'selftest' {
    $r = RunW 'selftest' @('selftest')
    if ($r.code -ne 0) { throw "exit $($r.code): $($r.text)" }
    $dir = Join-Path $base 'evidence\selftest\20000101-000000-fastfail-any'
    if (-not (Test-Path (Join-Path $dir 'manifest.sig'))) { throw "bundle not written at $dir" }
    $r2 = RunW 'selftest-again' @('selftest')
    if ($r2.code -ne 0) { throw "second selftest exit $($r2.code)" }
    if (-not (Test-Path "$dir-2")) { throw "second selftest must write $dir-2, not overwrite" }
    "sig $((Get-Item (Join-Path $dir 'manifest.sig')).Length) B, pubkey $((Get-Item (Join-Path $dir 'pubkey.bin')).Length) B"
}
$selfDir = Join-Path $base 'evidence\selftest\20000101-000000-fastfail-any'
Step 'verify-selftest' {
    $r = RunW 'verify-selftest' @('verify', $selfDir)
    if ($r.code -ne 0) { throw "exit $($r.code): $($r.text)" }
    $r.text.Trim()
}
Step 'verify-rejects-edit' {
    if (-not (Test-Path $selfDir)) { throw "no selftest bundle to tamper with" }
    $copy = Join-Path $out 'tampered-bundle'
    if (Test-Path $copy) { Remove-Item -Recurse -Force $copy }
    Copy-Item -Recurse $selfDir $copy
    Add-Content -Path (Join-Path $copy 'report.html') -Value '<!-- edited -->'
    $r = RunW 'verify-tampered' @('verify', $copy)
    if ($r.code -eq 0) { throw "edited bundle verified OK; that is a bug" }
    "rejected: $($r.text.Trim())"
}

# ---- triggers --------------------------------------------------------------
$cl = Get-Command cl.exe -ErrorAction SilentlyContinue
$trig = Join-Path $root 'tests\triggers\trigger.exe'
if (-not $cl) {
    # Try the VS developer environment the usual way.
    $vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
    if (Test-Path $vswhere) {
        $vs = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
        $vcvars = Join-Path $vs 'VC\Auxiliary\Build\vcvars64.bat'
        if (Test-Path $vcvars) {
            Step 'compile-trigger' {
                Push-Location (Join-Path $root 'tests\triggers')
                try {
                    cmd /c "`"$vcvars`" >nul && cl /nologo /W4 /GS trigger.c" *> (Join-Path $out 'cl.log')
                    if (-not (Test-Path $trig)) { throw "cl failed; see cl.log" }
                    'via vcvars64'
                } finally { Pop-Location }
            }
        }
    }
} else {
    Step 'compile-trigger' {
        Push-Location (Join-Path $root 'tests\triggers')
        try {
            & cl /nologo /W4 /GS trigger.c *> (Join-Path $out 'cl.log')
            if (-not (Test-Path $trig)) { throw "cl failed; see cl.log" }
            'cl on PATH'
        } finally { Pop-Location }
    }
}

if (-not (Test-Path $trig)) {
    Skip 'triggers' 'no MSVC cl.exe found (install "Desktop development with C++" in VS Build Tools), or compile tests\triggers\trigger.c by hand and re-run'
} else {
    # Start the watcher, fire triggers, stop the watcher, then read the log.
    $before = Get-Date
    $epoch = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds() - 1
    $w = Start-Process -FilePath $exe -ArgumentList 'run' -PassThru -WindowStyle Hidden
    Start-Sleep 3
    foreach ($case in 'fastfail', 'gs') {
        Step "trigger-$case" {
            $p = Start-Process -FilePath $trig -ArgumentList $case -PassThru -Wait -WindowStyle Hidden
            Start-Sleep 4
            $ev = Get-WinEvent -FilterHashtable @{ LogName = 'Application'; ProviderName = 'Application Error'; Id = 1000; StartTime = $before } -ErrorAction SilentlyContinue |
                  Where-Object { $_.Message -match 'trigger\.exe' } | Select-Object -First 1
            if (-not $ev) { throw "trigger exited $($p.ExitCode) but no Application Error 1000 for trigger.exe appeared" }
            $ev.ToXml() | Set-Content (Join-Path $out "events-$case.xml")
            $x = [xml]$ev.ToXml()
            $d = $x.Event.EventData.Data
            $code = ($d | Where-Object { $_.Name -eq 'ExceptionCode' } | Select-Object -First 1).'#text'
            if (-not $code) { $code = $d[6].'#text' }   # positional form on older Windows
            $named = if ($d[0].Name) { 'named' } else { 'positional' }
            Start-Sleep 2
            $fresh = Get-Content (Join-Path $base 'witness.log') | Where-Object { [int64]($_ -split ' ')[0] -ge $epoch }
            $matched = $fresh | Where-Object { $_ -match 'match .* process=.*trigger\.exe' }
            if (-not $matched) { throw "event 1000 ($named fields, exception=$code) was written but witness.log shows no match; fresh log lines: $($fresh -join ' || ')" }
            "exit $($p.ExitCode); event 1000 $named fields, exception=$code; Witness matched"
        }
    }
    # ACG / remote-image need Exploit Protection opted in for trigger.exe; report but do not require.
    Step 'trigger-rwx' {
        $p = Start-Process -FilePath $trig -ArgumentList 'rwx' -PassThru -Wait -WindowStyle Hidden
        Start-Sleep 4
        $ev = Get-WinEvent -LogName 'Microsoft-Windows-Security-Mitigations/KernelMode' -ErrorAction SilentlyContinue |
              Where-Object { $_.TimeCreated -gt $before -and $_.Id -eq 2 } | Select-Object -First 1
        if ($ev) { $ev.ToXml() | Set-Content (Join-Path $out 'events-rwx.xml'); "ACG event 2 observed (exit $($p.ExitCode))" }
        elseif ($p.ExitCode -eq 0) { "RWX allowed: ACG not enabled for trigger.exe (enable it, see tests\triggers\README.md)" }
        else { throw "exit $($p.ExitCode) but no KernelMode event 2" }
    }
    Start-Sleep 2
    if (-not $w.HasExited) { Stop-Process -Id $w.Id -Force }
}

# ---- collect ---------------------------------------------------------------
Copy-Item (Join-Path $base 'witness.log') (Join-Path $out 'witness.log') -ErrorAction SilentlyContinue
# Every bundle's raw event XML: real captures are the fixtures rules are tested against.
$bx = Join-Path $out 'bundle-events'; New-Item -ItemType Directory -Force -Path $bx | Out-Null
Get-ChildItem (Join-Path $base 'evidence') -Recurse -Filter 'event.raw.xml' | ForEach-Object {
    Copy-Item $_.FullName (Join-Path $bx ($_.Directory.Name + '.xml'))
}
Get-ChildItem (Join-Path $base 'evidence') -Recurse -Directory | Select-Object -ExpandProperty FullName | Set-Content (Join-Path $out 'evidence-list.txt')
# Channel readability as a standard user, straight from the OS.
foreach ($ch in 'Microsoft-Windows-Security-Mitigations/KernelMode', 'Microsoft-Windows-Security-Mitigations/UserMode') {
    try { $c = Get-WinEvent -ListLog $ch -ErrorAction Stop; "INFO  channel $ch enabled=$($c.IsEnabled) records=$($c.RecordCount)" | Add-Content $summary }
    catch { "INFO  channel $ch not listable: $($_.Exception.Message)" | Add-Content $summary }
}
Get-Content $summary

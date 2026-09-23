<#
.SYNOPSIS
  BUILD_PLAN.md phase 4, step 1: prove two independent machines produce a
  byte-identical witness.exe. Machine A is this host; machine B is the
  Windows container from Dockerfile.windows.

.DESCRIPTION
  Both machines run scripts\build-release.ps1, which remaps every
  machine-specific path out of the binary, so they need not share a folder
  layout. They do share one thing on purpose: the crates, fetched once into
  .cargo-home (git-ignored) and mounted into the container, which builds
  offline. Anything that still differs is a real reproducibility bug. The two
  build-info.txt files say whether the toolchains matched; if the MSVC build
  numbers differ, fix that before looking anywhere else.

  Requires: Docker Desktop switched to Windows containers, and the image
  built once:  docker build -f Dockerfile.windows -t witness-build .

  Writes phase4-results\reproduce.txt with both build-info files and the verdict.
#>
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$out = Join-Path $root 'phase4-results'
New-Item -ItemType Directory -Force -Path $out | Out-Null
$report = Join-Path $out 'reproduce.txt'
"reproduce run $(Get-Date -Format o) on $env:COMPUTERNAME" | Set-Content $report

$os = (& docker info --format '{{.OSType}}' 2>$null)
if ($os -ne 'windows') { "STOP  Docker is in '$os' container mode; switch Docker Desktop to Windows containers" | Add-Content $report; Get-Content $report; exit 1 }
if (-not (& docker image inspect witness-build --format '{{.Id}}' 2>$null)) { "STOP  image 'witness-build' missing; run: docker build -f Dockerfile.windows -t witness-build ." | Add-Content $report; Get-Content $report; exit 1 }

$triple = 'x86_64-pc-windows-msvc'
$env:CARGO_HOME = Join-Path $root '.cargo-home'
Push-Location $root
try {
    $ErrorActionPreference = 'Continue'   # cargo reports progress on stderr
    & cargo fetch --locked
    $ErrorActionPreference = 'Stop'
    if ($LASTEXITCODE -ne 0) { throw "cargo fetch failed ($LASTEXITCODE)" }
} finally { Pop-Location }

& (Join-Path $root 'scripts\build-release.ps1') -Target $triple -TargetDir (Join-Path $root 'target-repro-host') | Out-Null
& docker run --rm -v "${root}:C:\src" witness-build
if ($LASTEXITCODE -ne 0) { throw "container build failed ($LASTEXITCODE)" }

$sides = @(('host', 'target-repro-host'), ('container', 'target-repro-container'))
foreach ($s in $sides) {
    "--- $($s[0])" | Add-Content $report
    Get-Content (Join-Path $root "$($s[1])\$triple\release\build-info.txt") | Add-Content $report
}
$a = Join-Path $root "target-repro-host\$triple\release\witness.exe"
$b = Join-Path $root "target-repro-container\$triple\release\witness.exe"
if ((Get-FileHash $a).Hash -eq (Get-FileHash $b).Hash) { "PASS  byte-identical" | Add-Content $report }
else {
    "FAIL  binaries differ; first differing offset below" | Add-Content $report
    $ba = [IO.File]::ReadAllBytes($a); $bb = [IO.File]::ReadAllBytes($b)
    $n = [Math]::Min($ba.Length, $bb.Length)
    for ($i = 0; $i -lt $n; $i++) { if ($ba[$i] -ne $bb[$i]) { "offset 0x$($i.ToString('X'))" | Add-Content $report; break } }
}
Get-Content $report

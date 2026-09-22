<#
.SYNOPSIS
  BUILD_PLAN.md phase 4, step 1: prove two independent machines produce a
  byte-identical witness.exe. Machine A is this host; machine B is the
  Windows container from Dockerfile.windows.

.DESCRIPTION
  Both builds run from the same absolute path (W:\, via `subst`), with the
  same CARGO_HOME (W:\.cargo-home, inside the repo and git-ignored) so the
  dependency sources sit at the same paths too, and `--locked --offline`
  after one `cargo fetch`. Anything that still differs is a real
  reproducibility bug, not a path artefact.

  Requires: Docker Desktop switched to Windows containers, and the image
  built once:  docker build -f Dockerfile.windows -t witness-build .

  Writes phase4-results\reproduce.txt with both hashes and the verdict.
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

$cargoHome = Join-Path $root '.cargo-home'
$env:CARGO_HOME = 'W:\.cargo-home'
& subst W: /D 2>$null | Out-Null
& subst W: $root
try {
    Push-Location 'W:\'
    # One fetch, shared by both machines through the mounted folder.
    & cargo fetch --locked | Out-Null
    "host: $((& rustc -V) -join ' ')" | Add-Content $report
    & cargo build --release --locked --offline -p witness-win --target-dir W:\target-repro-host | Out-Null
    Pop-Location

    # Machine B. The repo (with .cargo-home and Cargo.lock) is the only input.
    & docker run --rm -v "${root}:C:\src" -e CARGO_HOME=W:\.cargo-home witness-build
    if ($LASTEXITCODE -ne 0) { throw "container build failed ($LASTEXITCODE)" }

    $a = Get-FileHash (Join-Path $root 'target-repro-host\release\witness.exe') -Algorithm SHA256
    $b = Get-FileHash (Join-Path $root 'target-repro-container\release\witness.exe') -Algorithm SHA256
    "host      $($a.Hash)  $((Get-Item $a.Path).Length) B" | Add-Content $report
    "container $($b.Hash)  $((Get-Item $b.Path).Length) B" | Add-Content $report
    if ($a.Hash -eq $b.Hash) { "PASS  byte-identical" | Add-Content $report }
    else {
        "FAIL  binaries differ; first differing offset below" | Add-Content $report
        $ba = [IO.File]::ReadAllBytes($a.Path); $bb = [IO.File]::ReadAllBytes($b.Path)
        $n = [Math]::Min($ba.Length, $bb.Length)
        for ($i = 0; $i -lt $n; $i++) { if ($ba[$i] -ne $bb[$i]) { "offset 0x$($i.ToString('X'))" | Add-Content $report; break } }
    }
} finally {
    if ((Get-Location).Path -like 'W:*') { Pop-Location }
    & subst W: /D 2>$null | Out-Null
    Get-Content $report
}

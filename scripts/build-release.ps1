<#
.SYNOPSIS
  The one command that builds a release witness.exe (BUILD_PLAN.md phase 4).
  The release workflow, scripts\reproduce.ps1 and Dockerfile.windows all run it.

.DESCRIPTION
  Aim: the same bytes from any folder on any machine with the same toolchain.

  * /Brepro (in .cargo/config.toml) makes the link timestamp and the debug
    GUID hashes of the output instead of the clock and a random number.
  * --remap-path-prefix rewrites the three machine-specific paths rustc embeds
    in panic locations (CARGO_HOME, this checkout, the target directory) to
    fixed names. That also keeps the builder's user name out of the binary.
    It goes through `cargo --config`, which MERGES with the hardening flags in
    .cargo/config.toml. Never use RUSTFLAGS for this: it silently REPLACES
    them, and the result builds fine with CFG and CET switched off.

  "Same toolchain" means rustc (pinned in rust-toolchain.toml) and the MSVC
  linker and C runtime objects, which end up inside the binary. The script
  writes build-info.txt next to witness.exe with the hash, the rustc version
  and the MSVC build numbers read back out of the binary, so a rebuilder
  knows exactly what to match.

  Proven 2026-09-23 on Windows 11 26200, MSVC 14.44.35207: builds from two
  different source folders, CARGO_HOME paths and target directories were
  byte-identical, and neither contained a local path.

  Runs in Windows PowerShell 5.1 (the build container) and pwsh 7 (CI).
#>
param(
    [string]$Target = 'x86_64-pc-windows-msvc',
    [string]$TargetDir
)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
if (-not $TargetDir) { $TargetDir = Join-Path $root 'target' }
$cargoHome = if ($env:CARGO_HOME) { $env:CARGO_HOME } else { Join-Path $env:USERPROFILE '.cargo' }
foreach ($p in $cargoHome, $root, $TargetDir) {
    if ($p.Contains("'")) { throw "path contains a single quote, which the TOML below cannot carry: $p" }
}

# Literal TOML strings ('...'): backslashes pass through untouched.
$remap = "'--remap-path-prefix=$cargoHome=/cargo', '--remap-path-prefix=$root=/witness', '--remap-path-prefix=$TargetDir=/target'"
Push-Location $root
try {
    # PowerShell 5.1 turns cargo's progress (stderr) into errors whenever the
    # caller redirects output; judge cargo by its exit code alone.
    $ErrorActionPreference = 'Continue'
    & cargo build --release --locked -p witness-win --target $Target --target-dir $TargetDir --config "target.$Target.rustflags=[$remap]"
    $code = $LASTEXITCODE
    $ErrorActionPreference = 'Stop'
    if ($code -ne 0) { throw "cargo build failed (exit $code)" }
    $rustc = (& rustc -V) -join ' '
} finally {
    Pop-Location
}

$exe = Join-Path $TargetDir "$Target\release\witness.exe"
$b = [IO.File]::ReadAllBytes($exe)
$pe = [BitConverter]::ToInt32($b, 0x3C)
$linker = '{0}.{1}' -f $b[$pe + 26], $b[$pe + 27]

# The Rich header (between the DOS stub and the PE header) lists the build
# number of every MSVC tool and library object that went into the link.
# Rust objects carry none, so this is exactly the MSVC part to match.
$builds = @()
for ($i = 0x80; $i -lt $pe - 4; $i += 4) {
    if ([BitConverter]::ToUInt32($b, $i) -eq 0x68636952) {  # 'Rich'
        $key = [BitConverter]::ToUInt32($b, $i + 4)
        for ($j = $i - 8; $j -ge 0x80; $j -= 8) {
            $id = [BitConverter]::ToUInt32($b, $j) -bxor $key
            if ($id -eq 0x536E6144) { break }  # 'DanS'
            $build = $id -band 0xFFFF
            if ($build -ne 0) { $builds += $build }  # 0: unmarked objects, no toolset to match
        }
        break
    }
}
$msvc = ($builds | Sort-Object -Unique -Descending) -join ', '
$hash = (Get-FileHash $exe -Algorithm SHA256).Hash.ToLower()

$info = @(
    "witness.exe  sha256 $hash  $($b.Length) bytes",
    "target       $Target",
    "rustc        $rustc",
    "linker       MSVC $linker (PE header)",
    "msvc builds  $msvc (Rich header: every MSVC tool and CRT object linked in)"
)
$info | Set-Content -Path (Join-Path (Split-Path -Parent $exe) 'build-info.txt') -Encoding ascii
$info

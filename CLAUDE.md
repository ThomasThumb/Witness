# Witness — working notes for Claude Code

Read this first, then THREAT_MODEL.md, DESIGN.md, BUILD_PLAN.md. `docs/HANDOFF.md`
has the full history of how the code got to this state and why.

## What this is

A small Windows tool for journalists, lawyers and activists: watches the
Event Log channels where Windows' own exploit mitigations report that they
fired, matches against human-readable TOML rules, writes a tamper-evident
evidence bundle (BLAKE3 per file, ML-DSA-87 over the manifest), and explains
it in plain English with a list of helplines. No network, no telemetry, no
admin, no installer, no tray icon. Ever. See "Deliberate non-features" in
THREAT_MODEL.md before proposing a feature.

## Non-negotiables (the maintainer's rules)

- KISS. Two crates, one dependency direction. No god files. Every new
  dependency is justified in a comment and must not open a socket
  (`deny.toml` bans them; `cargo deny check` must stay green).
- `witness-core` is `#![forbid(unsafe_code)]`, clippy pedantic clean, and
  everything in it is tested on Linux. `unsafe` lives only in
  `crates/witness-win/src/{eventlog,keys,harden,notify}.rs`, one OS facility
  each, a SAFETY comment per call. CI greps for this.
- No `unwrap`/`expect`/`panic` outside tests. `panic = "abort"` in release.
- The strongest PQC available: ML-DSA-87 (FIPS 204 category 5), deterministic
  variant, seed-derived. `manifest.json` names the algorithm. Do not downgrade.
- Rules are the product. Never write "you have been hacked". Every rule
  carries what-happened / what-it-might-mean / what-to-do text a frightened
  non-technical person can act on. Prefer a structural predicate
  (`image_in_process_dir`) over a vendor allowlist.
- Every fix a live machine forced is recorded in `tests/triggers/README.md`
  with the raw XML checked in under `crates/witness-core/tests/fixtures/`.

## State as of 2026-09-23

Phase 0–2 of BUILD_PLAN.md are done except where marked. Proven on the
maintainer's Windows 11 Pro 26200 machine:
build, PE hardening flags, runtime self-hardening, `check`/`selftest`/
`verify`/tamper rejection, and live-fired events: Application Error 1000
(named fields on Win11!), KernelMode 2 (ACG), 8 (remote image), 12 (CIG —
Brave false positive, now the `cig-self-bundled` rule). Not yet fired: 4, 6
(triggers written, `scripts/phase2-admin.ps1` runs them, needs an elevated
run), and the UserMode family 14–24 (no triggers, on purpose: whether a
public repo should carry them is the maintainer's call).

Repository: `github.com/ThomasThumb/Witness`. First push pending; CI has never run.

## How to work here

```
cargo test                      # core only (workspace default-members); runs on any OS
cargo clippy --all-targets -- -D warnings
cargo deny check
cargo build --release -p witness-win        # Windows + MSVC only
powershell -ExecutionPolicy Bypass -File scripts\phase2.ps1          # full local proof, no admin
powershell -ExecutionPolicy Bypass -File scripts\phase2-admin.ps1    # elevated: the opt-in cases
powershell -ExecutionPolicy Bypass -File scripts\phase2-admin.ps1 -CleanupOnly
cargo +nightly fuzz run winevt_parse -- -max_total_time=3600         # in fuzz/
docker build -f Dockerfile.windows -t witness-build . ; scripts\reproduce.ps1   # Windows containers mode
```

Runtime data is in `%LOCALAPPDATA%\Witness\` (seed, log, evidence). The
evidence there from Phase 2 runs is real output; `evidence\selftest\` is not.

Known quirks: `rust-toolchain.toml` pins 1.95.0 (use `RUSTUP_TOOLCHAIN=stable`
if rustup cannot fetch that channel name). PowerShell 5.1: never name a
parameter `$args`; capture native stderr via `cmd /c ... 2>&1`, not `*>`.
`Set-ProcessMitigation` wants `BlockDynamicCode` (not `DynamicCode`) and its
`-Remove` is unreliable; the cleanup deletes the IFEO key instead.

## What is next (in order)

1. Elevated `phase2-admin.ps1` → record events 4 and 6 in
   `tests/triggers/README.md`, add their XML as fixtures + golden tests.
2. `git init`, commit, push; watch CI (fuzz, deny, audit, contacts, Windows smoke).
3. Phase 4 reproducibility: build the container image, run `reproduce.ps1`.
   Expect a mismatch first time (PDB path / link timestamp); likely fix is
   `/Brepro` and `/PDBALTPATH` in `.cargo/config.toml` link-args. Prove it.
4. Phase 3 words: outside reviewer sign-off on the triage text. Not optional.
5. `SUPPORT.md`, SignPath application, winget manifest (Phase 4/6).

## Style the maintainer expects

Casual, direct, sceptical. Say what was proven and what was not. Never
report a step as done that has not run on real hardware. Push back when a
change adds a dependency, a UI surface, or softens the "we cannot prevent
attacks" language.

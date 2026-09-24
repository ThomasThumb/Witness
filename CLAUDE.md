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
- Nothing public may identify the maintainer or any user: no names,
  emails, machine names, SIDs, key fingerprints or expanded user paths in
  files, fixtures, commit messages, commit authors or Witness's own output.
  Anything public can be read by the people this tool exists to catch.
  Fixtures get the fakes listed in `tests/triggers/README.md`; commits use
  the repo-local GitHub no-reply identity and UTC (`$env:TZ='UTC'` before
  `git commit`; otherwise the local timezone is stamped in); output shows
  `%LOCALAPPDATA%\Witness`.

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

Repository: `github.com/ThomasThumb/Witness`. Every commit's history was rewritten on 2026-09-24 to remove identifying data, so commit IDs from before then no longer exist. CI was green on all six jobs at `86c49e6` (rewritten ID).

Second session (Claude Code on the maintainer's machine, 2026-09-23; details in HANDOFF.md):
all four captured fixtures golden-tested; `verify` no longer follows
manifest file names out of the bundle (a crafted `\\host\share\x` would
have made it reach the network) and names unsigned extra files; selftest
reports say TEST via an explicit flag; `check` reports a *disabled*
channel instead of "ok"; release builds are byte-reproducible on one
machine via `scripts\build-release.ps1` (`/Brepro` + path remapping);
`release.yml` fixed before it ever ran (least-privilege jobs, exact cosign
identity, arm64 target on the pinned toolchain, flat artifacts, dry-run
trigger).

## How to work here

```
cargo test                      # core only (workspace default-members); runs on any OS
cargo clippy --all-targets -- -D warnings
cargo deny check
cargo build --release -p witness-win        # Windows + MSVC only; day-to-day
powershell -ExecutionPolicy Bypass -File scripts\build-release.ps1      # the release build: reproducible, writes build-info.txt
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

1. Elevated `phase2-admin.ps1`, run by the maintainer (it changes Exploit
   Protection settings and opens a share; Claude Code does not do that
   itself) → record events 4 and 6 in `tests/triggers/README.md`, add their
   XML as fixtures + golden tests.
2. Watch CI on the rewritten, pushed history; then run the release workflow by hand (Actions → release
   → Run workflow): a dry run that builds both targets and publishes nothing.
3. Phase 4, second machine: build the container image, run `reproduce.ps1`.
   The host half is proven. If it mismatches, compare the two
   `build-info.txt` first: the MSVC build numbers must match.
4. Phase 3 words: outside reviewer sign-off on the triage text. Not optional.
5. SignPath application, winget manifest (Phase 4/6). `SUPPORT.md` is
   drafted; it is user-facing text, so it goes through the Phase 3 review.

Open decisions for the maintainer (HANDOFF.md, "Things I would still argue
about"): the untested UserMode rules at `urgent`; `cig-self-bundled` for
programs installed in user-writable folders.

## Style the maintainer expects

Casual, direct, sceptical. Say what was proven and what was not. Never
report a step as done that has not run on real hardware. Push back when a
change adds a dependency, a UI surface, or softens the "we cannot prevent
attacks" language.

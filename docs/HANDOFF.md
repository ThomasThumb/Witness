# Hand-off: how the code got here (2026-09-22/23)

Written for whoever (or whatever) picks this up next. CLAUDE.md is the
short version; this is the reasoning trail. Everything below was verified
either by `cargo test`/clippy on Linux, by type-checking `witness-win`
against the real `windows` 0.61.3 bindings, or by a run on the maintainer's
Windows 11 Pro 26200 machine, and it says which.

## From scaffold to compiling

The scaffold was written without a Rust toolchain or a Windows machine.
First real compile found:

- `ml-dsa` 0.1.1 API: `SigningKey::from_seed(&Seed)`, `Signer::sign` is the
  deterministic variant, `zeroize` feature wipes the seed on drop. Pinned
  `=0.1.1`.
- `windows` 0.61.3: `LocalFree` is in `Win32::Foundation`, not
  `System::Memory`; the `PROCESS_MITIGATION_*_POLICY` structs are in
  `System::SystemServices` (the constants are in `System::Threading`).
  `&HSTRING` is a `Param<PCWSTR>`, so no raw pointer juggling.
- `tauri-winrt-notification` 0.7.3 uses the same `windows` 0.61, so no
  duplicate.
- The Windows crate was type-checked on Linux by copying `windows`,
  `windows-core`, `windows-strings`, `windows-result` into a scratch dir,
  stripping their `#![cfg(windows)]`, shimming three `OsStrExt` calls, and
  stubbing `windows-future`. Not shipped; it is a one-off trick.

## Bugs found by design review before any hardware

- Application Error 1000 positional path is `%11` (scaffold read `%10`).
- ROP/EAF/IAF rules were on the KernelMode channel; those mitigations are
  user-mode enforced, so they moved to UserMode. Still unconfirmed live.
- `run()` used `?` on bundle-write failure, exiting the watcher; DESIGN.md
  says log and continue. Fixed.
- `LICENSE-APACHE` was a URL; full text added. Toolchain pinned. `Cargo.lock`
  committed; CI `--locked`.

## Bugs found by hardware (the ones that matter)

1. **Windows 11 writes Application Error 1000 with named fields**
   (`AppName`, `ExceptionCode`, `AppPath`), not the positional `<Data>` the
   message template implies. Both live triggers silently matched nothing.
   Parser now tries named keys first, positional second. Fixture checked in.
2. **Brave's GPU process trips CIG (event 12) on its own `vulkan-1.dll`**,
   four times a second at browser start. Every Chromium user would have got
   a "worth a look" toast. Fix: `Event::image_in_process_dir()` and a
   `cig-self-bundled` rule at severity `bug` placed above `cig-block`.
   Kernel writes `\Device\HarddiskVolume3\...` for the process and a
   drive-less path for the image; `normalize_path` reconciles them.
3. **Same-second duplicate events overwrote the bundle folder.**
   `bundle_dir` now suffixes `-2`, `-3`; `EventRecordID` is captured.
4. **Four toasts and four browser tabs for one incident.** Notifications
   throttled to one per rule+process per 60 s; every event still gets a
   signed bundle.
5. Events 2 and 8 carry **no blocked-image path**, only the calling process.
   Rule text that promised "check the library path" was reworded.
6. `LoadLibraryW` of an `.exe` over a loopback SMB share is enough to fire
   Block-remote-images. Event 8 confirmed, urgent report rendered.

## Script lessons (PowerShell 5.1)

- `$args` is an automatic variable; a parameter named `$args` splats nothing.
- `*>` mangles native stderr into ErrorRecords and drops it when errors are
  silenced; use `cmd /c "... > file 2>&1"`.
- `Set-ProcessMitigation -Enable` wants `BlockDynamicCode`,
  `BlockRemoteImageLoads`, `BlockLowLabelImageLoads`,
  `DisallowChildProcessCreation`. `-Remove` returned `C000000D`; the cleanup
  now `-Disable`s and deletes `HKLM:\...\Image File Execution Options\trigger.exe`.
- Elevated PowerShell shares the same `%LOCALAPPDATA%` and DPAPI seed, so
  `witness run` under the admin script writes to the same evidence folder.

## Decisions taken with the maintainer

- ML-DSA-87 over 65 (his call, on my recommendation). Manifest names the
  algorithm so a verifier never guesses.
- No triggers for EAF/IAF/ROP in the public repo until he decides.
- Repository `github.com/thomasthumb/witness`.
- Docker is for Phase 4 (second machine for reproducibility), not for
  Phase 2; Windows containers cannot see the host's Event Log or toasts.

## Second session: Claude Code on the maintainer's machine (2026-09-23)

Picked up from the chat session with the tree clean and `aa4d418` unpushed.
Baseline first: fmt, clippy, 26 tests, `cargo deny`, release build,
`check`: all green, same key fingerprint as before, so nothing had
drifted. Then, each its own commit, each proven on this machine:

1. **Golden tests over every captured fixture.** Events 2, 8 and 12 were
   checked in but nothing read them, although README said the golden tests
   did. Added, plus the Brave event with the DLL moved out of Brave's
   folder. Mutation check: dropping `image_in_process_dir` fails the test.
2. **`verify` followed manifest names anywhere.** The manifest and
   `pubkey.bin` both come from whoever hands over the bundle, so a crafted
   one signs cleanly under its own key, and its file names went straight
   into `dir.join()`. `..\x` read outside the bundle; `\\host\share\x`
   would have made `witness verify` open SMB from a helpline's machine
   and offer its NTLM credentials. Now the manifest must list exactly the
   three bundle files, checked before anything is opened; signature files
   are size-capped; unsigned extra files are named (a warning: Windows
   drops `desktop.ini` by itself). All ten real bundles still verify.
3. **selftest says TEST.** Not keyed off record id 0 as suggested below:
   a real event without an `EventRecordID` also parses as 0, and a real
   alarm stamped "test" is the worst thing this tool could do. Explicit
   flag, set only by `selftest`; a test asserts a real render never has it.
4. **A disabled channel was "ok".** Called `EvtSubscribe` directly from
   PowerShell: a *disabled* channel subscribes cleanly (only a missing one
   fails, 15007), then nothing ever arrives. `.NET`'s `EventLogWatcher`
   even hides the missing-channel error. `check` now reads the channel's
   Enabled flag (`EvtOpenChannelConfig`, no admin, no new feature: the
   Security feature was already implied) and prints DISABLED with the
   `wevtutil` fix. The DISABLED branch is not proven end to end: that needs
   a Security-Mitigations channel switched off, which is the maintainer's
   machine to change, not mine.
5. **Reproducible builds, host half.** The binary carried the link time,
   a random PDB GUID, and `C:\Users\<builder>\.cargo\…` in 71 panic
   locations. `/Brepro` plus `--remap-path-prefix` fixes all three.
   Trap found on the way: RUSTFLAGS (and `trim-paths`, still unstable in
   1.95) are no good; RUSTFLAGS *replaces* the CFG/CET flags and the build
   still succeeds. `cargo --config` merges; checked by reading GUARD_CF and
   CETCOMPAT back out of the PE. Two builds sharing no path (other source
   folder, other CARGO_HOME via a junction, other target dir) were
   byte-identical, under Windows PowerShell 5.1 as the container will run it.
   What still has to match across machines is MSVC: its CRT objects are
   linked in. `build-info.txt` lists the builds from the Rich header.
6. **`release.yml`, before it ever ran.** Workflow-wide `contents: write`
   and `id-token: write` meant every dependency's build script and an
   unpinned `cargo install` could publish or sign as the repo; the cosign
   command in the release notes used an unanchored identity regexp that a
   branch named `github.com/ThomasThumb/Witness` in anyone's repository
   satisfies; the arm64 target went to `stable` while `rust-toolchain.toml`
   builds with 1.95.0 (CI logs show exactly that); `upload-artifact` with
   several paths keeps directories, so `publish` would not have found
   `witness.exe`; and the SBOM lands in `crates/witness-win/`, not the root
   (checked by running cargo-cyclonedx 0.5.9). All fixed; a manual trigger
   builds and uploads without publishing, so it can be proven before a tag.

Not done, deliberately: the elevated `phase2-admin.ps1` run (it changes
Exploit Protection settings and opens a share, so the maintainer runs it),
the Docker image (an ~8 GB download, the maintainer's call), and the push.

## Things I would still argue about

- The `Application` channel subscription sees every application event on
  the machine; only 1000/Application Error is acted on, but a helper
  reading `witness.log` sees `no rule:` lines for those. Fine for v0.1.
- `rop-*`/`eaf-*`/`iaf-*` rules ship untested. Either write the triggers
  behind an opt-in build flag, or mark those rules `severity = "look"`
  until confirmed, so an unverified rule cannot produce an "urgent".
- `cig-self-bundled` trusts "the DLL is in the program's own folder". For
  Program Files that folder needs admin to write, so the line holds. But
  Signal, Discord, Slack, new Teams and per-user Chrome install under
  `%LOCALAPPDATA%`, where anything running as the user can plant a DLL,
  and DLL side-loading is a real technique. A CIG block there is
  classified `bug` and never shown. Narrowing the predicate to non-user-
  writable folders brings back the per-user-Chrome false positive at every
  browser start. That trade-off is the maintainer's; flagged, not changed.
- The toast says "Tap to read what it means", but the report already opens
  by itself, and the toast is attributed to PowerShell's AppUserModelID,
  so tapping it may just open PowerShell. Untested; worth one look, and a
  Phase 3 wording question either way.

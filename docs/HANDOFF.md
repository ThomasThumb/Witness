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

## Things I would still argue about

- The `Application` channel subscription sees every application event on
  the machine; only 1000/Application Error is acted on, but a helper
  reading `witness.log` sees `no rule:` lines for those. Fine for v0.1.
- `rop-*`/`eaf-*`/`iaf-*` rules ship untested. Either write the triggers
  behind an opt-in build flag, or mark those rules `severity = "look"`
  until confirmed, so an unverified rule cannot produce an "urgent".
- `selftest` bundles live under `evidence\selftest\` but the toast and
  report look real. A "THIS WAS A TEST" banner in the report when the
  record id is 0 would cost five lines.

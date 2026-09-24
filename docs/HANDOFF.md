# Witness — hand-off to Claude Code

*As of 2026-09-24. Everything is pushed. Every commit was rewritten that day
to remove identifying data, so older commit IDs no longer exist. `CLAUDE.md` is the
short version Claude Code reads automatically; this is the complete one.
Three sessions have touched this code: the chat session that built it, a
Claude Code session on the maintainer's machine that hardened it, and the
chat session again to write this. Each section says which, and how it was
proven.*

---

## 1. What Witness is, in one paragraph

A small open-source Windows program for journalists, lawyers, activists and
the helplines that support them. It runs as the logged-in user with no
special rights and subscribes to the three Event Log channels where Windows'
own exploit mitigations report that they fired (`Application` for fast-fail
crashes, `Microsoft-Windows-Security-Mitigations/KernelMode` and
`/UserMode`). A matching event is run through a readable TOML rules file
(first match wins), written to a tamper-evident evidence bundle (BLAKE3 per
file, manifest signed with ML-DSA-87), and explained in a plain-English HTML
report with a helpline list. No network code exists in the binary; the
dependency policy bans socket crates and CI enforces it. No telemetry, no
update check, no installer, no admin, no driver, no tray icon. It never says
"you have been hacked". Read `THREAT_MODEL.md` before changing anything: if
a design decision contradicts it, the design is wrong.

## 2. Where everything lives

| What | Where |
|---|---|
| Repository | `github.com/ThomasThumb/Witness` (canonical casing matters: the cosign identity is case-sensitive) |
| Working copy | `C:\Witness\witness\` on the maintainer's Windows 11 Pro 26200 machine |
| Runtime data | `%LOCALAPPDATA%\Witness\` — `seed.dpapi`, `witness.log`, `evidence\` (ten real bundles from Phase 2 runs) and `evidence\selftest\` (not real) |
| Original scaffold inputs | `C:\Witness\files\` (historical; superseded by the repo) |
| Design docs | `THREAT_MODEL.md` → `DESIGN.md` → `BUILD_PLAN.md`, in that order |
| Live-test evidence | `tests/triggers/README.md` (verification log) and `crates/witness-core/tests/fixtures/*.xml` (raw captured events) |

## 3. Repository map

```
crates/witness-core/      all security-relevant logic; #![forbid(unsafe_code)]; clippy pedantic
  src/event.rs            Event struct, process_basename(), image_in_process_dir(), normalize_path()
  src/winevt.rs           Event Log XML → Event (named fields first, positional fallback; 8 MB cap)
  src/rules.rs            RuleSet/Rule/Match/Triage/Severity; first-match-wins; validation
  src/signing.rs          ML-DSA-87 deterministic, seed-derived; ALGORITHM const; fingerprint
  src/evidence.rs         bundle_dir() (collision-safe), write_bundle(), verify_bundle() (manifest names pinned to the bundle)
  src/report.rs           esc(), render(); CSP default-src 'none'; Contact struct; explicit TEST flag
  tests/shipped_files.rs  golden tests: shipped rules × realistic events × every captured fixture
  tests/fixtures/         6 raw XML captures from Windows 11 26200 (events 1000, 2, 4, 6, 8, 12), identifiers replaced
crates/witness-win/       the binary; unsafe ONLY in eventlog.rs, keys.rs, harden.rs, notify.rs
  src/main.rs             subcommands, App{rules,contacts,id,evidence_root,last_notified}, handle()
  src/eventlog.rs         EvtSubscribe push delivery → mpsc; EvtRender with size cap; EvtOpenChannelConfig for `check`
  src/keys.rs             DPAPI-wrapped 32-byte seed; Zeroizing; write-then-rename
  src/harden.rs           SetProcessMitigationPolicy: ExtensionPoints, ImageLoad, CIG, ACG
  src/notify.rs           toast (tauri-winrt-notification, PowerShell AppUserModelID) + ShellExecuteW
  src/paths.rs            %LOCALAPPDATA%\Witness
.cargo/config.toml        CFG + /CETCOMPAT /DYNAMICBASE /HIGHENTROPYVA /NXCOMPAT /DEPENDENTLOADFLAG /Brepro
rules/default.toml        14 rules, the product
rules/contacts.toml       5 helplines with checked = "YYYY-MM"
tests/triggers/           trigger.c (fastfail|gs|rwx|child|lowil|remote) + README verification log
scripts/phase2.ps1        no-admin proof: build → PE flags → check/fingerprint/selftest/verify/tamper → fastfail triggers
scripts/phase2-admin.ps1  elevated: opts trigger.exe into 4 mitigations, fires rwx/child/lowil/remote, cleans up; -CleanupOnly
scripts/build-release.ps1 THE release build: /Brepro + --remap-path-prefix via `cargo --config`; writes build-info.txt
scripts/reproduce.ps1     Phase 4: host + Windows container both run build-release.ps1, SHA-256 compare
scripts/check_contacts.py CI: fail if any helpline unchecked for 6 months
fuzz/                     cargo-fuzz targets winevt_parse, rules_parse; corpus seeded from fixtures
Dockerfile.windows        servercore + VS Build Tools + rustup 1.95.0, the "second machine"
.github/workflows/ci.yml  6 jobs, green; release.yml: least-privilege, Sigstore keyless + provenance + SBOM, dry-run trigger (never run)
deny.toml                 bans every socket crate; licence allowlist is exactly what is used
SUPPORT.md                routes people to helplines, not the maintainer (drafted; Phase 3 reviews it)
CLAUDE.md                 short standing orders for Claude Code
docs/HANDOFF.md           this file
docs/grapheneos-proposal.md  the Android half, as a proposal not code
```

Size: under 2,000 lines of Rust including tests. 13 direct dependencies, 61
in the tree, none with network capability. Tests: 26 unit/property in
`witness-core`, 5 golden test functions over the shipped files and captures, 1 in
`witness-win`.

## 4. Non-negotiables

- **KISS.** Two crates, one dependency direction. No god files. A new
  dependency needs a justifying comment and must pass `cargo deny check`.
- **`unsafe` stays in the four named files**, one OS facility each, a
  SAFETY comment per call. CI greps for this and fails otherwise.
- **No `unwrap`/`expect`/`panic`** outside tests. `panic = "abort"` in release.
- **ML-DSA-87, deterministic variant, seed-derived.** The maintainer chose
  87 over 65 deliberately (category 5, ~1.3 KB more per signature, audience
  faces state-level attackers). `manifest.json` names the algorithm and
  `verify_bundle` checks it before decoding. Do not downgrade.
- **Rules are the product.** Every rule ships with what-happened /
  what-it-might-mean / what-to-do text for a frightened non-technical
  person. Prefer a structural predicate over a vendor allowlist.
- **Every hardware-forced fix is recorded** in `tests/triggers/README.md`
  with the raw XML checked in as a fixture and a golden test.
- **Hardening flags go through `.cargo/config.toml` or `cargo --config`,
  never `RUSTFLAGS`**, which silently replaces them and still builds.
- **Nothing public identifies the maintainer or a user.** No names, emails,
  machine names, SIDs, key fingerprints or expanded user paths in files,
  fixtures, commit messages or authors, or Witness's own output. The people
  Witness exists to catch can read anything public. See `CLAUDE.md`.
- **Tone with the maintainer:** direct, sceptical, say what was proven and
  what was not. Never report a step done that has not run on real hardware.

## 5. What has been done, and how it was proven

### Phase 0 — hygiene: done
Full Apache-2.0 text; toolchain pinned to 1.95.0; `Cargo.lock` committed and
CI runs `--locked`; repository name set; `cargo deny` clean (advisories,
bans, licences, sources). Not done: branch protection, Dependabot,
`cargo vet` (all need repo settings or a first review pass).

### Phase 1 — core proven on Linux: done
`cargo test` green. proptest guarantees the parser never panics on
arbitrary input and `esc()` never emits `< > " '`. XXE rejected. FIPS 204
size checks (pk 2592 B, sig 4627 B). Every captured fixture has a golden
test against the shipped rules, including a mutation check (drop
`image_in_process_dir` and the Brave test fails). clippy pedantic clean.
Fuzz targets exist and CI runs each for 60 s on nightly; a one-hour local
run and committed corpus is still owed.

### Phase 2 — Windows binary proven on hardware: done except two rule families
Proven on the maintainer's machine (Windows 11 Pro 26200) via `scripts/phase2.ps1` and
`scripts/phase2-admin.ps1`, and independently on GitHub's `windows-latest`
runner via CI:

- Builds first time with 1.95.0 MSVC; ~817 KB; PE has HIGH_ENTROPY_VA,
  DYNAMIC_BASE, NX_COMPAT, GUARD_CF, CETCOMPAT; runtime self-hardening
  applies ExtensionPoints, ImageLoad, CIG, ACG.
- `check` reads all three channels as a standard user and now reports a
  *disabled* channel as DISABLED with the `wevtutil` fix (the DISABLED
  branch itself is not proven end to end; that needs a channel switched
  off on the maintainer's machine). `fingerprint`; `selftest` writes and
  signs a bundle (toast + browser confirmed on the maintainer's machine, headless on the runner)
  and says TEST in the toast and report; `verify` accepts it; an edited
  `report.html` is rejected. The key fingerprint is deliberately not recorded
  here: it would link that machine's evidence to this repository.
- Live-fired and matched, raw XML checked in:
  - Application Error 1000 via `trigger fastfail` and `trigger gs` →
    `fastfail-any`. **Finding:** Win11 writes this event with named fields
    (`AppName`, `ExceptionCode`, `AppPath`), not the positional `<Data>`
    Microsoft's template implies. Parser now tries named keys first.
  - KernelMode 2 (ACG) via `trigger rwx` under `BlockDynamicCode` →
    `acg-block-kernel`.
  - KernelMode 8 (remote image) via `trigger remote
    \\localhost\witnesstest\trigger.exe` under `BlockRemoteImageLoads` →
    `remote-image-block` (urgent). `LoadLibraryW` of an `.exe` over a
    loopback SMB share is enough. **Finding:** events 2 and 8 carry no
    blocked-image path, only the calling process.
  - KernelMode 12 (CIG), unprompted: Brave's GPU process refused its own
    `<install>\<ver>\vulkan-1.dll`, four times in one second. **Finding:**
    this would have toasted every Chromium user at every browser start.
    Fixed with `Event::image_in_process_dir()` and a `cig-self-bundled`
    rule at severity `bug` above `cig-block`. Kernel writes
    `\Device\HarddiskVolume3\…` for the process and a drive-less path for
    the image; `normalize_path` reconciles them.
- Consequences of the above, all implemented and tested: bundle folders
  never overwrite (`-2`, `-3` suffix, bounded); `EventRecordID` captured
  and shown; notifications throttled to one per rule+process per 60 s
  (every event still gets its own bundle); the watcher logs `no rule:`
  lines for Application Error and Security-Mitigations events that match
  nothing, so a helper can tune `rules.toml`; the `run` loop no longer
  exits on a bundle-write failure; report shows the process basename before
  the kernel path; rule text no longer promises a library path that events
  2 and 8 do not carry (event 6 does name it, in `ImageName`).
- **Fired on hardware 2026-09-24, elevated `phase2-admin.ps1`:** events 4
  (child process; names the refused child in `ChildImagePathName` /
  `ChildCommandLine`) and 6 (low-integrity image; names the refused file
  in `ImageName`), golden-tested from the captured XML. Getting there took
  two fixes: triggers now run in the script's own console (in a window of
  their own, "Do not allow child processes" refused `conhost.exe` and
  `trigger.exe` died at start with 0xC0000142), and the script refuses a
  `trigger.exe` older than `trigger.c`.
- **Not yet fired on hardware:** EAF/IAF/ROP (UserMode 14–24): **no
  triggers, by the maintainer's decision**; whether a public repo should
  carry them is the maintainer's call. Until then those five rules rest on
  Microsoft's documentation, and
  §9 suggests capping them at `look`.

### Phase 3 — words: not started
No outside reviewer has read the triage text. This gates any release.
`SUPPORT.md` is user-facing text and goes through the same review.

### Phase 4 — release engineering: host half proven, second machine not
`scripts/build-release.ps1` is the one release build; on the maintainer's machine two builds
sharing no path were byte-identical (see §6.5). `Dockerfile.windows` +
`scripts/reproduce.ps1` run the same script in a Windows container and
compare SHA-256; the container has never been built (~8 GB download, the
maintainer's call). `release.yml` has been fixed on paper (§6.6) but has
never run; it has a manual dry-run trigger that builds both targets and
publishes nothing. SignPath and winget not started.

### CI — live and green
Six jobs on every push: core (Linux tests + clippy), windows binary (clippy,
tests, build, then one step per smoke command: check, fingerprint, selftest,
verify, tamper-rejected, log dump), cargo-deny, unsafe-inventory, fuzz
smoke (nightly, 60 s per target), contacts freshness. First run needed two
fixes, both CI plumbing: `rustsec/audit-check` was dropped (needs
`checks: write`; cargo-deny covers the same DB), and the tamper step ends
with `exit 0` because GitHub's pwsh wrapper appends `exit $LASTEXITCODE`.
Green at `86c49e6` (rewritten ID). Everything since was pushed with the 2026-09-24 history rewrite.

## 6. Second session: Claude Code on the maintainer's machine (2026-09-23)

Picked up from the chat session with the tree clean and `257b934` (rewritten ID) unpushed.
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
3. **selftest says TEST.** Not keyed off record id 0 as first suggested:
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
   Proven with MSVC 14.44.35207; sha256 `3df053c6…`.
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

Also added `SUPPORT.md` and updated `BUILD_PLAN.md` status. Not done,
deliberately: the elevated `phase2-admin.ps1` run (it changes Exploit
Protection settings and opens a share, so the maintainer runs it), the
Docker image, and the push.

## 6a. Codex security scan (2026-09-24)

The maintainer ran OpenAI Codex's deep security scan over the working
folder. Ten findings, one medium, nine low; the medium and four of the lows
were about the superseded pre-repository copies (scaffold folder and two
ZIPs), which the maintainer deletes. The rest changed the live code: the
verifier opens nothing through a link, reads through size budgets, checks
every manifest field's grammar before printing it, escapes what it prints,
and takes an expected fingerprint; the event queue is bounded; bundles are
never overwritten; the CIG comparison keeps volumes apart; every action in
the workflows is pinned to a commit. Full record, with what was declined
and why: `docs/reviews/2026-09-24-codex-deep-scan.md`.

## 7. Decisions and why

| Decision | Reason |
|---|---|
| ML-DSA-87 | Maintainer's call on my recommendation; cost is trivial per bundle, audience justifies category 5 |
| Deterministic ML-DSA variant | No RNG at signing time; same manifest → same signature |
| `image_in_process_dir` over allowlists | Vendor-neutral, no list to maintain, proven on the Brave case |
| Notification throttle, evidence never throttled | Chromium trips mitigations several times per second; helplines still need every event |
| No EAF/IAF/ROP triggers | Ethics of shipping them in a public repo is the maintainer's decision, not a technical one |
| Windows containers for Phase 4 only | A container cannot see the host Event Log or toasts; it is a fine second build machine |
| `default-members = ["crates/witness-core"]` | `cargo test` on any OS runs the portable half; the binary is built explicitly |
| Repo `ThomasThumb/Witness` capitalised in all verification strings | Sigstore certificate identity is case-sensitive |
| Manifest may name only the three bundle files | Anything else is a path an attacker chose; `verify` runs on helpline machines |
| TEST is an explicit flag, not `record_id == 0` | A real event can parse with id 0; a real alarm labelled "test" is the worst failure mode |
| `/Brepro` + `--remap-path-prefix` via `cargo --config` | Only combination that is reproducible AND keeps CFG/CET; RUSTFLAGS silently drops them |

## 8. Tooling gotchas learned the hard way

- `rust-toolchain.toml` pins `1.95.0`; on a Linux box where rustup cannot
  fetch that channel name, `RUSTUP_TOOLCHAIN=stable` (same version).
- `ml-dsa` 0.1.1: `SigningKey::from_seed(&Seed)`; `Signer::sign` is the
  deterministic variant; `zeroize` feature wipes the seed on drop. Pinned
  `=0.1.1`.
- `windows` 0.61: `LocalFree` is in `Win32::Foundation`;
  `PROCESS_MITIGATION_*_POLICY` structs are in `Win32::System::SystemServices`
  (constants in `System::Threading`). `&HSTRING` is a `Param<PCWSTR>`.
  `tauri-winrt-notification` 0.7.3 uses the same `windows` 0.61.
- The Windows crate can be type-checked on Linux by copying `windows`,
  `windows-core`, `windows-strings`, `windows-result` to a scratch dir,
  removing `#![cfg(windows)]`, shimming three `OsStrExt` calls and stubbing
  `windows-future`. Useful; not shipped.
- A *disabled* Event Log channel subscribes cleanly with `EvtSubscribe`
  and delivers nothing; only a missing channel errors (15007). Check the
  Enabled flag via `EvtOpenChannelConfig`.
- PowerShell 5.1: a parameter named `$args` shadows the automatic variable
  and splats nothing; `*>` mangles native stderr — use `cmd /c "… > f 2>&1"`.
- `Set-ProcessMitigation -Enable` names: `BlockDynamicCode`,
  `BlockRemoteImageLoads`, `BlockLowLabelImageLoads`,
  `DisallowChildProcessCreation`. `-Remove` returned `C000000D`; cleanup
  now `-Disable`s and deletes `HKLM:\…\Image File Execution Options\trigger.exe`.
- Elevated PowerShell shares the same `%LOCALAPPDATA%` and DPAPI seed, so
  `witness run` under the admin script writes to the same evidence folder.
- GitHub `pwsh` (7.4) fails a step on any non-zero native exit AND appends
  `exit $LASTEXITCODE`; a step that expects a failure must end with `exit 0`.
- Run logs on GitHub need repo-admin rights to download via API; the job
  and step list does not. Split multi-command steps so failures are
  visible without logs.
- `upload-artifact` with several paths keeps directory structure;
  `cargo cyclonedx` writes the SBOM next to the crate's `Cargo.toml`.
- git on the Cowork Linux side-VM cannot delete files in the mounted folder
  unless permission is granted; a `git init` there left a broken `.git`
  until it was, and a later commit from that side clobbered newer
  `CLAUDE.md`/`HANDOFF.md` and rewrote `rules/default.toml` to CRLF (both
  reverted). Claude Code on the Windows box has no such limit, and should
  be the one making commits from now on.

## 9. Open questions for the maintainer

1. **EAF/IAF/ROP rules ship untested.** Options: write triggers behind an
   opt-in build flag, or cap those rules at `severity = "look"` until
   confirmed, so an unverified rule can never produce an "urgent".
2. **`cig-self-bundled` trusts "the DLL is in the program's own folder".**
   For Program Files that folder needs admin to write, so the line holds.
   But Signal, Discord, Slack, new Teams and per-user Chrome install under
   `%LOCALAPPDATA%`, where anything running as the user can plant a DLL,
   and DLL side-loading is a real technique. A CIG block there is
   classified `bug` and never shown. Narrowing the predicate to non-user-
   writable folders brings back the per-user-Chrome false positive at every
   browser start. That trade-off is the maintainer's; flagged, not changed.
   Since the Codex scan (2026-09-24, `docs/reviews/`): the comparison keeps
   volume identity, so the same folder on another drive no longer counts,
   and `witness.log` names the refused library on every match, so a quiet
   one can be judged from the log.
3. **The toast says "Tap to read what it means"**, but the report already
   opens by itself, and the toast is attributed to PowerShell's
   AppUserModelID, so tapping it may just open PowerShell. Untested; worth
   one look, and a Phase 3 wording question either way.
4. **The `Application` subscription** sees every application event on the
   machine; only 1000/Application Error is acted on. Fine for v0.1; a
   structured XPath filter in `EvtSubscribe` would cut the noise later.
   The queue behind it is bounded now (256 records, 64 MiB; drops are
   counted and logged), so the noise costs bounded memory.
5. **Repeat-offender escalation** (same process, same rule, N times in a
   window → bump severity) is wanted for v0.2 and needs a small state file.

## 10. Next steps, in order

1. Done 2026-09-24: pushed (after the history rewrite), CI green.
2. Done 2026-09-24: elevated `powershell -ExecutionPolicy Bypass -File scripts\phase2-admin.ps1`
   (maintainer runs it: it changes Exploit Protection settings and opens a
   share): all four PASS; events 4 and 6 recorded, captured and golden-tested.
   Re-run after every Windows feature update.
3. Actions → release → Run workflow: the dry run that builds both targets
   and publishes nothing. Fix whatever it finds.
4. Docker Desktop → Windows containers; `docker build -f Dockerfile.windows
   -t witness-build .`; `scripts\reproduce.ps1`. If it mismatches, compare
   the two `build-info.txt` first: the MSVC build numbers must match.
5. Decide §9.1 and apply it to `rules/default.toml`.
6. `cargo +nightly fuzz run winevt_parse -- -max_total_time=3600` (and
   `rules_parse`); commit the grown corpus under `fuzz/corpus/`.
7. Repo settings: branch protection on `main` with CI required; Dependabot
   security updates; `cargo vet init`.
8. Phase 3: find two reviewers who have done digital-security support for
   at-risk users; get written sign-off on every `triage` block and on
   `SUPPORT.md`; test the report on three non-technical people.
9. Phase 4: tag `v0.1.0` only after 8; SignPath application; winget
   manifest.

## 11. How to work here

```
cargo test                                  # core, any OS
cargo clippy --all-targets -- -D warnings
cargo deny check
cargo build --release -p witness-win        # Windows + MSVC; day-to-day
powershell -ExecutionPolicy Bypass -File scripts\build-release.ps1   # the release build; writes build-info.txt
powershell -ExecutionPolicy Bypass -File scripts\phase2.ps1
powershell -ExecutionPolicy Bypass -File scripts\phase2-admin.ps1          # elevated
powershell -ExecutionPolicy Bypass -File scripts\phase2-admin.ps1 -CleanupOnly
cd fuzz && cargo +nightly fuzz run winevt_parse -- -max_total_time=60
docker build -f Dockerfile.windows -t witness-build . && scripts\reproduce.ps1
```

Commit messages end with the session attribution lines the maintainer's
tooling adds; keep them.

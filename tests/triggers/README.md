# Triggers

Tiny programs that make Windows' own mitigations fire on purpose, so anyone
can confirm the rules in `rules/default.toml` match what the live OS writes.
This is BUILD_PLAN.md phase 2, steps 3 and 4. Nothing here is an exploit.

| Command | What fires | Expected rule |
|---|---|---|
| `trigger fastfail` | `__fastfail`, Application Error 1000, `0xC0000409` | `fastfail-any` (look) |
| `trigger gs` | `/GS` cookie check, same event | `fastfail-any` (look) |
| `trigger rwx` with ACG enabled for `trigger.exe` | Security-Mitigations/KernelMode event 2 | `acg-block-kernel` (look) |
| `trigger remote \\\\localhost\\witnesstest\\trigger.exe` with Block remote images on | Security-Mitigations/KernelMode event 8 | `remote-image-block` (urgent) |
| `trigger child` with Do not allow child processes on | Security-Mitigations/KernelMode event 4 | `child-process-block` (look) |
| `trigger lowil <Low-labelled copy>` with Block low integrity images on | Security-Mitigations/KernelMode event 6 | `low-integrity-image-block` (look) |
| Copy `trigger.exe` to `signal.exe` and run `fastfail` | as above, but the process name is on the high-risk list | `fastfail-messaging-browser` (urgent) |

Build with `cl /W4 /GS trigger.c` in a Developer PowerShell. Run `witness run`
in one window, fire a trigger in another, and expect a toast plus a folder
under `%LOCALAPPDATA%\Witness\evidence\`. `scripts\phase2.ps1` does the
build, the two fast-fail cases and the collection of results automatically.

## Opting trigger.exe into the mitigations that need it (admin, one-off)

Exploit Protection settings are per-executable and need an elevated shell:

```powershell
Set-ProcessMitigation -Name trigger.exe -Enable BlockDynamicCode       # ACG        -> `trigger rwx`
Set-ProcessMitigation -Name trigger.exe -Enable BlockRemoteImageLoads  # remote     -> `trigger remote`
Set-ProcessMitigation -Name trigger.exe -Enable DisallowChildProcessCreation  # -> `trigger child`
Set-ProcessMitigation -Name trigger.exe -Enable BlockLowLabelImageLoads       # -> `trigger lowil`
copy trigger.exe lowil-copy.exe; icacls lowil-copy.exe /setintegritylevel Low  # the file to load
Get-ProcessMitigation -Name trigger.exe                                # confirm
```

For the remote-image case the DLL must come from a UNC path. Loading an
`.exe` through `LoadLibraryW` is enough to exercise the loader, so share the
triggers folder read-only against loopback, test, then remove the share:

```powershell
net share witnesstest=C:\Witness\witness\tests\triggers /GRANT:Everyone,READ   # admin
.\trigger.exe remote \\localhost\witnesstest\trigger.exe
net share witnesstest /delete                                                # admin
```

Undo everything afterwards: `scripts\phase2-admin.ps1 -CleanupOnly` (elevated), which disables both and deletes the `Image File Execution Options\trigger.exe` key.

`scripts\phase2-admin.ps1` (elevated) runs all four opt-in cases and cleans up after itself.

## Not covered

The UserMode rules (EAF, IAF and the three ROP checks, events 14–24) have no
trigger here. A test program for them would have to imitate the behaviour those
mitigations exist to catch, and whether that belongs in a public repository is
a maintainer decision, not a technical one. Until it is made, those rules rest
on Microsoft's documentation plus the channel assignment reasoning in
`rules/default.toml`, and the table below says so.

## Verification log

Record here what each Windows build actually wrote, so the event IDs and
channels in `rules/default.toml` are backed by observation, not documentation.

| Date | Windows build | Trigger | Channel | Event ID | Rule matched | Notes |
|---|---|---|---|---|---|---|
| 2026-09-23 | Windows 11 Pro 26200 | `fastfail` | Application | 1000 | `fastfail-any` | Exit 0xC0000409. **Fields are named** (`AppName`, `ExceptionCode`, `AppPath`…), not positional as Microsoft's template suggests. Parser fixed; XML checked in as a fixture. |
| 2026-09-23 | Windows 11 Pro 26200 | `gs` | Application | 1000 | `fastfail-any` | Same shape as `fastfail`. |
| 2026-09-23 | Windows 11 Pro 26200 | (none: Brave started) | Security-Mitigations/KernelMode | 12 | `cig-block` → now `cig-self-bundled` | Brave's GPU process, CIG on, refused its own `<install>\153.1.95.104\vulkan-1.dll`; four identical events in one second. `ProcessPath` uses the `\Device\HarddiskVolume3\` form, `ImageName` has no drive at all. Led to the `image_in_process_dir` matcher, collision-safe bundle names and the 60 s notification throttle. XML checked in as a fixture. |
| 2026-09-23 | Windows 11 Pro 26200 | `rwx` (no opt-in) | — | — | — | RWX granted, as expected. Security-Mitigations/KernelMode enabled with 363 records; UserMode enabled with 0. |
| 2026-09-23 | Windows 11 Pro 26200 | `rwx` with `BlockDynamicCode` | Security-Mitigations/KernelMode | 2 | `acg-block-kernel` (look) | `VirtualProtect` refused, exit 2. Event has `ProcessPath`, `ProcessCommandLine` and `CallingProcess*` only: no address or size of the refused region. XML checked in. |
| 2026-09-23 | Windows 11 Pro 26200 | `remote \\localhost\witnesstest\trigger.exe` with `BlockRemoteImageLoads` | Security-Mitigations/KernelMode | 8 | `remote-image-block` (urgent) | `LoadLibraryW` of an `.exe` over a loopback SMB share is enough. Exit 2. Event carries **no image path**, only the calling process; the UNC path survives only inside `ProcessCommandLine` because the trigger put it there. XML checked in. |

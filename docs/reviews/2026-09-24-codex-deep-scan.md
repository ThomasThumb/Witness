# Review: Codex deep security scan, 2026-09-24

*Static, offline scan of the working folder by OpenAI Codex's security
plugin, run by the maintainer. It reviewed the live `witness/` tree and
three superseded copies from before the repository existed: the scaffold
folder and two ZIPs. Ten findings: one medium, nine low. This records what
each one was, what changed, and what remains. Part of BUILD_PLAN.md phase 5:
review outcomes are published here.*

## Findings against the live code, and the changes

| # | Finding | Severity | Change |
|---|---|---|---|
| 4 | `witness verify` read each payload whole, sized by the manifest, so a bundle could declare and ship a huge file. | low | Payloads are hashed as a stream through a 64 MiB budget; metadata through 1 MiB. Declared sizes above the limit are refused before any file is opened. A file that grows during reading is caught by the byte count. |
| 6 | `verify` followed symbolic links and reparse points, so a bundle unpacked with links kept could point a member at a file elsewhere on the helper's disk, or at a network share contacted on open. | low | Every member is opened without following links (Windows: `FILE_FLAG_OPEN_REPARSE_POINT`; Unix: identity of the open handle compared with the name) and the handle is judged: a link or a non-regular file is refused. Proven on Windows 11 with a real symlink. |
| 10 | Manifest text and extra file names were printed raw, so a crafted bundle could carry `\r`, `\n` or terminal escapes that forge or hide the key line a helper compares. | low | Every manifest text field is checked against a fixed grammar before it is printed (a rule id, a severity of ours, a version, a timestamp, a fingerprint of the exact shape Witness writes). Everything printed from a bundle or a caller's folder name goes through `visible()`, which keeps printable ASCII and escapes the rest. The key is printed alone on its own line. `witness verify <dir> <fingerprint>` takes the fingerprint the user wrote down and fails, before any payload is read, if the bundle's key differs. `selftest` now verifies against the install's own key. |
| 5 | The queue between the Event Log callback and the watcher was unbounded; any process can raise mitigation events at will, so a flood could grow the watcher's memory until Windows killed it. | low | The queue holds at most 256 records and 64 MiB. Records arriving while it is full are dropped and counted, never blocking the OS thread; the watcher logs the count. Windows keeps every record in the Event Log regardless. |
| 2 | `cig-self-bundled` judged a refused library harmless from its folder alone, and its path comparison dropped the volume, so the same folder on another drive counted as the same folder. | low | Volumes are kept: two named volumes must match, spelt the same way; a drive letter cannot be matched to a `\Device\HarddiskVolumeN` name, so that pair proves nothing. The kernel writes CIG's `ImageName` with no volume, and then, as before, the folders decide. The log now names the refused library for every match, so a helper can judge a quiet one. **Still open, the maintainer's call:** for programs installed in a folder the user can write to (Signal, Discord, Slack, per-user Chrome), a library planted there is still quieted; narrowing the rule brings back the per-user Chrome false positive at every browser start. See HANDOFF.md §9. |
| 3 | (Scaffold.) The live `bundle_dir` also fell back to an existing directory after 10 000 same-second collisions. | low | `write_bundle` creates the directory itself and fails if it exists. Evidence is never overwritten, whatever path it is given. |
| 7 | (Scaffold workflows.) The live workflows referenced actions by moving tags. | low | Every action is pinned to a commit with the release named in a comment; checkouts no longer keep their token; `cargo-fuzz` is pinned. |

Tests were added for each change; the earlier tests still pass.

## Findings against the superseded copies only

Findings 1 (medium), 3, 7, 8 and 9 concern the scaffold folder and the two
ZIPs from before the repository existed: an older verifier that followed
manifest names anywhere, an older parser that missed named fast-fail events,
an older workflow with write permissions on the build job, and captured
events with the capture machine's name and account SID. The live code fixed
each of these earlier (see HANDOFF.md). The archives are not part of the
repository and were never published; the fix is to delete them, which is
the maintainer's to do since it is their data. They must not be shared.

## Not changed, with reasons

- The scan asks for a per-event storage budget and cleanup. THREAT_MODEL.md
  and DESIGN.md leave evidence retention to the user on purpose; a tool
  that deletes evidence is a tool that can be made to delete evidence.
- The scan asks to narrow the `Application` channel subscription to the
  providers rules use. A user's `rules.toml` may match other providers
  there; the bounded queue answers the resource concern without changing
  what an override can see.
- The scan asks to refuse a bundle root on a network share. The root is the
  helper's own argument; opening what they named is not Witness reaching
  out. Members inside the bundle can no longer redirect anywhere.

## Limits of this review

Static and offline: no runtime reproduction of any finding. The scan did
not reverse-engineer binaries, audit dependencies' implementations, or
check live advisory databases. The findings' own severity and confidence
ratings are the scan's, not the maintainer's.

# Design

Working name **Witness**. Check crates.io and trademarks before the first
release; the name is the least important decision in this file.

## Requirements

Functional:
* F1. Notice when Windows' exploit mitigations fire, within seconds.
* F2. Explain it in plain English: what happened, what it might mean,
  what to do, who can help.
* F3. Preserve evidence in a form a helpline or analyst can trust.
* F4. Let anyone verify a bundle without installing Witness (public key
  + manifest + `witness verify`, or 30 lines of Python).
* F5. Be auditable end to end by a stranger with a weekend.

Non-functional:
* N1. Zero network. Zero telemetry. Enforced by dependency policy, not promises.
* N2. Runs as the logged-in user. No service, no driver, no admin.
* N3. Small: target under 4k lines of Rust excluding tests, under 15 direct
  dependencies. Every one justified in a comment.
* N4. Reproducible, signed, attested releases.
* N5. Never frightens without instructing.

Constraints: one maintainer at first; Windows-only for v0.1; the Android
counterpart is a GrapheneOS proposal, not code in this repo (see
BUILD_PLAN.md phase 6).

## Architecture

```
            Windows Event Log
   ┌──────────────┬───────────────────────────┬───────────────────────────┐
   │ Application  │ Security-Mitigations/     │ Security-Mitigations/     │
   │ (Event 1000) │ KernelMode                │ UserMode                  │
   └──────┬───────┴─────────────┬─────────────┴─────────────┬─────────────┘
          │ EvtSubscribe (push, future events only)         │
          ▼                     ▼                           ▼
   ┌──────────────────────────────────────────────────────────────────┐
   │ witness-win :: eventlog.rs   (unsafe FFI, OS thread → mpsc)      │
   └──────────────────────────────┬───────────────────────────────────┘
                                  │ raw XML string
                                  ▼
   ┌──────────────────────────────────────────────────────────────────┐
   │ witness-core :: winevt::parse  → Event (normalized, raw kept)    │
   │ witness-core :: RuleSet::first_match → Option<&Rule>             │
   └──────────────┬───────────────────────────────────────────────────┘
                  │ Bug → log only        Look / Urgent ↓
                  ▼
   ┌──────────────────────────────────────────────────────────────────┐
   │ witness-core :: report::render  → self-contained HTML (CSP none) │
   │ witness-core :: evidence::write_bundle → dir + manifest + sig    │
   │       (BLAKE3 per file, ML-DSA-87 over manifest)                 │
   └──────────────┬───────────────────────────────────────────────────┘
                  ▼
   ┌──────────────────────────────────────────────────────────────────┐
   │ witness-win :: notify (toast) + open report.html in browser      │
   └──────────────────────────────────────────────────────────────────┘
```

Two crates, one direction of dependency:

* **witness-core** — `#![forbid(unsafe_code)]`, no OS calls, builds and tests
  on Linux. Holds every security-relevant decision: parsing, matching,
  rendering, hashing, signing. This is what a reviewer reads first.
* **witness-win** — the binary. Five modules. Four contain `unsafe`, each
  wrapping one OS facility with a SAFETY comment per call site:
  `eventlog.rs` (read), `keys.rs` (DPAPI), `harden.rs` (self-mitigations),
  `notify.rs` (toast + ShellExecute). `main.rs` and `paths.rs` are safe glue.

## Data flow and trust boundaries

1. **OS → us.** Event XML is untrusted input in the sense that a compromised
   process can write *some* fields (process name, exception data). We parse
   with `roxmltree` (no external entities, no network, no DTD), cap the size
   at 8 MB, and copy everything through `esc()` before it touches HTML.
   Nothing from an event ever becomes a path, a command, or a URL.
2. **Rules → matcher.** Rules are TOML we ship (embedded) or the user
   overrides on disk. Validation rejects duplicate ids, empty text, and
   mixed-case process names so a typo cannot silently create a dead rule.
3. **Bundle → world.** `manifest.json` lists every file with BLAKE3 and size;
   `manifest.sig` is ML-DSA-87 over the manifest bytes; `pubkey.bin` travels
   with it. Verification needs nothing but those three files.
4. **Report → browser.** Local file, `Content-Security-Policy: default-src
   'none'; style-src 'unsafe-inline'`. No script, no images, no fonts, no
   links. Contacts are text the user types. Every `<Data>` field the OS
   recorded is shown in the "for a technical helper" table, escaped; a
   property test guarantees `esc()` output never contains `<`, `>`, `"`, `'`.

## Key decisions and trade-offs

| Decision | Alternative | Why this one |
|---|---|---|
| Read the Event Log via `EvtSubscribe` | ETW consumer; kernel driver | Event Log is what Microsoft's own mitigations write to, it is user-readable, and it needs no driver, no signing, no MVI. ETW-TI would see more but requires PPL/ELAM. Out of scope by THREAT_MODEL.md. |
| Report as static HTML opened in the default browser | Native window; Tauri/webview; TUI | Zero UI dependencies, printable, readable on a phone via cable, and a CSP of `none` makes it inert. Costs: it looks plain. That is a feature. |
| Toast via `tauri-winrt-notification` | Raw WinRT bindings; MessageBox | One small crate vs ~150 lines of COM; MessageBox is modal and blocks the watcher. Revisit if the crate goes stale. |
| ML-DSA-87 only, seed-derived, deterministic variant | Ed25519; hybrid; ML-DSA-65; randomized variant | Post-quantum by default is the point of this maintainer's work and the cost is one pure-Rust crate. 87 is the highest FIPS 204 security category (5); over 65 it costs ~1.3 KB per signature and ~0.6 KB per public key, which on a bundle written once per event is nothing, and the audience is people facing state-level attackers. Seed-derived keys mean the only secret is 32 bytes and DPAPI does the storage. The deterministic variant (FIPS 204 §3.4) needs no RNG at signing time, so the same manifest always gives the same signature. `manifest.json` names the algorithm so a verifier never guesses. Hybrid is a welcome PR. |
| BLAKE3 for file hashes | SHA-256; SHA-3 | Fast, simple API, one dependency already worth having. Any of the three is fine; changing is trivial. |
| DPAPI for the seed | Plaintext file with ACL; Windows Hello/TPM | DPAPI is zero-config and user-scoped. TPM-backed keys would resist a same-user attacker somewhat, at the cost of a lot of code and a worse first-run. Documented as a v0.3 option. |
| First-match-wins ordered rules | Scoring; ML | Explainable, diffable, testable. A helpline volunteer can read the rules file. |
| One structural predicate, `image_in_process_dir` | Per-browser allowlists; path globs in rules | Live testing showed Chromium browsers refuse their *own* DLLs under CIG at every start. "Loading from its own install folder" is the honest, vendor-neutral line between a bug and something to look at, and it needs no list to maintain. |
| Three severities | Five; numeric | People act on "look" vs "urgent". Anything finer is false precision. |
| Scheduled Task at logon, printed not created | Service; Run key; installer | The user (or their helper) runs one visible command. No hidden persistence; easy to remove. |
| `witness selftest` runs a canned event through the real path | Mock toast/report; nothing | The only way to know toasts and the browser hand-off work on *this* machine is to do them. Writes under `evidence\selftest\` so it cannot be mistaken for a finding. |
| No tray icon | Tray | Dependency + surface for something that should be silent. |
| Rules embedded, overridable on disk | Only on disk; only embedded | Works with zero setup; still lets a helper tune it. Override file wins entirely (no merging: merging is where surprises live). |

## Storage

`%LOCALAPPDATA%\Witness\`
```
seed.dpapi        32-byte seed, DPAPI-wrapped, written via tmp+rename
rules.toml        optional override
contacts.toml     optional override
witness.log       append-only plain text, epoch seconds + line
evidence\
  20260922-040000-fastfail-messaging-browser\
    event.json  event.raw.xml  report.html  manifest.json  manifest.sig  pubkey.bin
  selftest\
    20000101-000000-fastfail-any\        (only from `witness selftest`)
```
No database. No config format beyond TOML. No cleanup: the user decides when
evidence is no longer needed.

## Error handling

* FFI failures: logged, surfaced by `witness check`, never panic.
* Unparseable event: logged and skipped; the rules cannot match what we
  cannot parse, and we would rather miss than guess.
* Bundle write failure: fatal for that event, logged with the OS error;
  the watcher keeps running (`App::handle` returns a `String`, `run` logs it).
* Toast/open failure: ignored; the bundle exists and `witness.log` says so.
* `panic = "abort"` in release: a bug in Witness ends Witness rather than
  continuing in an unknown state. The scheduled task restarts it at next logon.

## What we would revisit as it grows

* Repeat-offender escalation (same process, same rule, N times in a window
  → bump severity). Wanted; needs a small state file; v0.2. (v0.1 already
  throttles *notifications* to one per rule+process per 60 s, in memory,
  because Chromium trips the same mitigation several times per second; every
  event still gets its own bundle.)
* Baseline snapshot of `Get-ProcessMitigation` at first run so "look" can say
  "and by the way, ACG is not enabled for your browser". v0.2.
* Windows Defender Exploit Guard operational events (channel
  `Microsoft-Windows-Windows Defender/Operational`) once we have confirmed
  IDs on a live machine.
* Localisation of triage text. The rules format already separates text from
  logic; a `rules/default.<lang>.toml` scheme is enough.
* TPM-backed signing identity. v0.3, if a reviewer thinks it earns its code.

# Witness

[![ci](https://github.com/thomasthumb/witness/actions/workflows/ci.yml/badge.svg)](https://github.com/thomasthumb/witness/actions/workflows/ci.yml)
![no network](https://img.shields.io/badge/network-none-2b2b2b)
![signatures](https://img.shields.io/badge/evidence%20signed-ML--DSA--87-2b2b2b)
![licence](https://img.shields.io/badge/licence-MIT%20or%20Apache--2.0-2b2b2b)

**Witness notices when Windows blocks an attack on your computer, tells you
in plain English, and keeps the evidence.**

*Working name. Pre-release: the code is built and proven on real hardware,
the words have not yet been reviewed by people who support at-risk users.
Read [BUILD_PLAN.md](BUILD_PLAN.md) before trusting anything here.*

---

## If Witness just showed you a message

Take a breath. Witness noticed that Windows stopped a program from doing
something dangerous with its memory. **The protection worked.** Most of the
time this is an ordinary bug in that program. Sometimes it is what a blocked
break-in attempt looks like from the outside. Witness cannot tell which. A
person can.

Open the report Witness showed you. It has three parts: what happened, what
it might mean, and what to do. Do the steps in order. If the report lists
organisations who can help, they are free and they will not think you are
paranoid. Type their address yourself rather than clicking anything.

Do not "clean" or reinstall the computer before talking to someone. That
destroys the evidence they would use to help you.

---

## What it does

Windows already ships strong exploit mitigations: hardware stack protection,
Arbitrary Code Guard, Code Integrity Guard, image-load restrictions and more.
When one of them fires, Windows writes a line to an event log almost nobody
reads, and the program that was attacked simply disappears. The person at the
keyboard learns nothing.

Witness is a small program that runs as you, with no special rights, and
watches those log channels. When a mitigation fires it:

1. **Matches** the event against a short, readable rules file, first match wins.
2. **Writes an evidence bundle**: the raw event, a normalised copy, and a
   report, each hashed with BLAKE3, the manifest signed with ML-DSA-87
   (FIPS 204). Anyone holding `pubkey.bin` can verify the bundle was not
   altered since Witness wrote it, without installing Witness.
3. **Shows a toast and opens a report** in your browser: what happened, what
   it might mean, what to do, and who can help. The report is a local HTML
   file with a `default-src 'none'` content-security policy. No scripts, no
   images, no links.

Everything is local. Witness has no network code at all: the dependency
policy bans every crate that can open a socket, and CI enforces it.

## What it is not

It does not prevent attacks; Windows does that. It does not detect spyware
that got past every mitigation, and silence from Witness is not safety. It
never says "you have been hacked": the strongest wording it will ever use is
"this pattern is sometimes seen when someone tries to break into a computer".
If your computer is already compromised, its reports may be wrong, and every
report says so. See [THREAT_MODEL.md](THREAT_MODEL.md).

## Who it is for

Journalists, lawyers, activists, human-rights defenders, and the helplines
and technical friends who support them. If you are one of the helpers, the
evidence bundle is designed for you: zip the folder, verify it with
`witness verify` or the public key alone, and read `event.raw.xml`.

## Install

There is no installer, on purpose. Download `witness.exe` from a release,
verify it (commands are on every release page), put it somewhere sensible, and:

```
witness check         # are the three log channels readable? what is my key fingerprint?
witness selftest      # push a built-in sample event through the whole pipeline
witness fingerprint   # print the signing-key fingerprint; write it on paper
witness install       # prints the one-line Scheduled Task command; you run it
```

`selftest` shows you what a real alert looks like: a toast and a report in
your browser. It writes under `evidence\selftest\` so it can never be mistaken
for a real finding. `install` does not install anything; it prints the
`schtasks` command that starts `witness run` at logon, and the one that
removes it. You run them. There is no hidden persistence.

Files live in `%LOCALAPPDATA%\Witness`:

```
seed.dpapi      32-byte signing seed, DPAPI-wrapped to your account
witness.log     plain text, one line per event
evidence\       one folder per finding
  20260922-150425-remote-image-block\
    event.json  event.raw.xml  report.html  manifest.json  manifest.sig  pubkey.bin
```

To change the rules or the helpline list, copy `rules/default.toml` or
`rules/contacts.toml` into that folder as `rules.toml` / `contacts.toml`.
An override replaces the built-in file entirely; there is no merging.

## Status

| | |
|---|---|
| Core logic (`witness-core`) | Built and tested on Linux: unit, property and golden tests; clippy pedantic; `cargo deny` clean |
| Windows binary | Built and run on Windows 11 Pro 26200. Self-hardens with ACG, CIG, image-load and extension-point policies; CFG, CET and high-entropy ASLR from the linker |
| Rules fired on real hardware | Fast-fail (0xC0000409), ACG, remote image, CIG. Recorded with raw XML in [`tests/triggers/README.md`](tests/triggers/README.md) |
| Rules not yet fired on hardware | Child-process, low-integrity image (triggers written); EAF/IAF/ROP (no triggers, by decision) |
| Plain-language review | Not yet. This is [Phase 3](BUILD_PLAN.md) and it gates any release |
| Signed, reproducible releases | Tooling in place (`Dockerfile.windows`, `scripts/reproduce.ps1`, Sigstore in `release.yml`); not yet exercised |

## For reviewers

Start with [THREAT_MODEL.md](THREAT_MODEL.md), then [DESIGN.md](DESIGN.md),
then [docs/HANDOFF.md](docs/HANDOFF.md) for how the code got here. The whole
thing is under 2,000 lines of Rust and meant to be read in an afternoon.

* `crates/witness-core` — every security-relevant decision: parsing,
  matching, rendering, hashing, signing. `#![forbid(unsafe_code)]`. Runs and
  tests on any OS: `cargo test`.
* `crates/witness-win` — the binary. `unsafe` only in `eventlog.rs`,
  `keys.rs`, `harden.rs`, `notify.rs`, one OS facility each, a SAFETY
  comment per call. CI fails if `unsafe` appears anywhere else.
* `rules/` — the product. TOML. Argue with it in a pull request.
* `tests/triggers/` — how to make the OS fire each rule, and the log of what
  was observed on which Windows build.
* `crates/witness-core/tests/fixtures/` — raw Event Log XML captured from a
  live machine; the golden tests run the shipped rules against them.
* `fuzz/` — cargo-fuzz targets for the two parsers of untrusted input.
* `deny.toml` — bans every crate that opens a socket.
* `scripts/` — `phase2.ps1` proves the binary on a Windows machine end to
  end; `phase2-admin.ps1` covers the cases that need Exploit Protection
  opt-in; `reproduce.ps1` builds on the host and in a bare container and
  compares hashes; `check_contacts.py` fails CI if a helpline has not been
  re-verified in six months.

Verify a release: commands are on each release page (Sigstore keyless
signature, GitHub provenance attestation, `SHA256SUMS`, SBOM). To rebuild it
yourself and compare, `Dockerfile.windows` + `scripts/reproduce.ps1` is the
recipe.

## Design in one paragraph

Two crates, one direction of dependency. The Event Log is read with
`EvtSubscribe`, never a driver or ETW. Rules are first-match-wins and carry
their own user-facing text, so a rule that cannot be explained cannot ship.
Severity has three levels, because people act on "look" versus "urgent" and
anything finer is false precision. The signing key is a 32-byte seed the OS
wraps with DPAPI; ML-DSA-87 is derived from it, deterministic variant, so
signing needs no randomness. A program refused one of its *own* bundled
libraries is a bug, not a finding, and that single structural rule is what
keeps Chromium browsers from crying wolf at every start. Notifications are
throttled; evidence never is.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). The most valuable contributions need
no Rust: rules that fire on something innocent, helplines that answer in a
country not yet listed, and plain-language review of the triage text by
people who have supported at-risk users. Security reports:
[SECURITY.md](SECURITY.md).

## Licence

MIT or Apache-2.0, at your option.

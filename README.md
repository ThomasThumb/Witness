# Witness

*Working name. Not yet released. Read BUILD_PLAN.md before trusting anything here.*

## If you were sent here because Witness showed you a message

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

## What Witness is

A small, open-source, Windows program that watches for the OS's own exploit
mitigations firing, explains it in plain language, and keeps tamper-evident
evidence. It has no network access, no telemetry, no update check, no
installer, and no admin rights. It is meant for journalists, lawyers,
activists, and anyone who might be targeted, and for the people who help them.

## What Witness is not

It does not prevent attacks; Windows does that. It does not detect spyware
that got past every mitigation. It never says "you have been hacked". See
[THREAT_MODEL.md](THREAT_MODEL.md).

## Use

```
witness check         # is everything reachable? what is my key fingerprint?
witness fingerprint   # print the fingerprint; write it on paper
witness install       # prints the one-line Scheduled Task command
witness selftest      # push a built-in sample event through the whole pipeline
witness run           # what the task runs; watches until closed
witness verify DIR    # verify an evidence bundle
```

`selftest` is the one to run first: it shows you what a real alert looks
like (toast, browser report) and writes its bundle under `evidence\selftest\`
so it can never be mistaken for a real finding.

Files live in `%LOCALAPPDATA%\Witness`. Evidence folders are under
`evidence\`. Each contains the raw event, a report, a manifest with BLAKE3
hashes, and an ML-DSA-87 signature. Anyone with `pubkey.bin` can verify it.

To override the rules or contacts, copy `rules/default.toml` or
`rules/contacts.toml` into that folder as `rules.toml` / `contacts.toml`.

## For reviewers

Start with [THREAT_MODEL.md](THREAT_MODEL.md), then [DESIGN.md](DESIGN.md).

* `crates/witness-core` — all logic. `#![forbid(unsafe_code)]`, clippy
  pedantic. Tests (unit, property and golden tests over the shipped rules)
  run on Linux: `cargo test`.
* `crates/witness-win` — the binary. `unsafe` only in `eventlog.rs`, `keys.rs`,
  `harden.rs`, `notify.rs`, each call with a SAFETY comment. CI fails if it
  appears anywhere else.
* `rules/` — the product. TOML. Argue with it in a pull request.
* `tests/triggers/` — how to make the real OS fire each rule, and the log of
  what was observed on which Windows build.
* `deny.toml` — bans every crate that opens a socket.
* `scripts/check_contacts.py` — CI fails if a helpline hasn't been re-verified
  in six months.

Verify a release: commands are on each release page (Sigstore keyless
signature, GitHub provenance attestation, SHA256SUMS, SBOM). To rebuild it
yourself and compare, `Dockerfile.windows` + `scripts\reproduce.ps1` is the
recipe.

## Contributing

[CONTRIBUTING.md](CONTRIBUTING.md). Rules, contacts and plain-language
review are as welcome as code and need no Rust.

## Licence

MIT or Apache-2.0, at your option.

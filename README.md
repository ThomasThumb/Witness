What Witness is

A small, open-source, Windows program that watches for the OS's own exploit
mitigations firing, explains it in plain language, and keeps tamper-evident
evidence. It has no network access, no telemetry, no update check, no
installer, and no admin rights. It is meant for journalists, lawyers,
activists, and anyone who might be targeted, and for the people who help them.

What Witness is not

It does not prevent attacks; Windows does that. It does not detect spyware
that got past every mitigation. It never says "you have been hacked". See
[THREAT_MODEL.md](THREAT_MODEL.md).

Use

```
witness check         # is everything reachable? what is my key fingerprint?
witness fingerprint   # print the fingerprint; write it on paper
witness install       # prints the one-line Scheduled Task command
witness run           # what the task runs; watches until closed
witness verify DIR    # verify an evidence bundle
```

Files live in `%LOCALAPPDATA%\Witness`. Evidence folders are under
`evidence\`. Each contains the raw event, a report, a manifest with BLAKE3
hashes, and an ML-DSA-65 signature. Anyone with `pubkey.bin` can verify it.

To override the rules or contacts, copy `rules/default.toml` or
`rules/contacts.toml` into that folder as `rules.toml` / `contacts.toml`.

For reviewers

Start with [THREAT_MODEL.md](THREAT_MODEL.md), then [DESIGN.md](DESIGN.md).

* `crates/witness-core` — all logic. `#![forbid(unsafe_code)]`. Tests run on Linux.
* `crates/witness-win` — the binary. `unsafe` only in `eventlog.rs`, `keys.rs`,
  `harden.rs`, `notify.rs`, each call with a SAFETY comment. CI fails if it
  appears anywhere else.
* `rules/` — the product. TOML. Argue with it in a pull request.
* `deny.toml` — bans every crate that opens a socket.

Verify a release: commands are on each release page (Sigstore keyless
signature, GitHub provenance attestation, SHA256SUMS, SBOM).

Contributing

[CONTRIBUTING.md](CONTRIBUTING.md). Rules, contacts and plain-language
review are as welcome as code and need no Rust.

Licence

Apache-2.0.

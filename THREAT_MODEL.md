# Threat model

Read this before DESIGN.md. If a design decision contradicts this file, the
design is wrong.

## What Witness is

A local observer. It subscribes to the Windows Event Log channels where the
OS's own exploit mitigations report that they fired, matches those records
against human-readable rules, writes a tamper-evident evidence bundle, and
explains the situation to a non-technical person in plain language with a
list of people who can help.

## What Witness is not

* **Not prevention.** Windows (CET, ACG, CFG, HVCI, Exploit Protection) does the
  preventing. Witness watches the scoreboard.
* **Not detection of spyware.** A successful exploit that defeats every
  mitigation produces no event. Silence from Witness is not safety.
* **Not attribution.** It never says who did it, or even that anyone did.
* **Not a substitute for a human.** Every serious path ends at "contact a
  helpline". That is deliberate.

## Assets

1. The user's safety and peace of mind. A false alarm that sends a journalist
   into a panic, or a missed explanation that leaves them ignoring a real
   signal, are both harms.
2. Evidence integrity: a bundle a helpline receives should be provably
   unaltered since Witness wrote it.
3. The user's privacy: Witness must never become a way to learn who runs it.
4. The integrity of the binary people install.

## Adversaries and what we do about them

| Adversary | Capability | Our posture |
|---|---|---|
| Commercial spyware operator (Paragon/NSO tier) | 0-days, kernel access once landed, motivated to hide | **Out of scope for prevention.** In scope: making the *blocked* attempts visible and keeping the evidence. Once they have the kernel they can blind or forge Witness; we say so on every report. |
| Opportunistic malware | Runs as the user, may tamper with files | Bundles are signed; DPAPI seed is user-scoped; tampering after the fact by anyone without the seed is detectable. Tampering *by code running as the user* is not, and is documented. |
| Supply-chain attacker | Compromise a dependency, the build, or the download | Minimal deps, `cargo deny`/`audit`/`vet` in CI, reproducible `--locked` builds, Sigstore keyless signatures, GitHub provenance attestation, SBOM per release, Authenticode via SignPath. Verification commands on every release page. |
| Malicious contributor | Sneak a "rule" that hides a real pattern or a "contact" that is a honeypot | Rules and contacts are TOML, diffed in every PR, reviewed by two people once we have two. Contacts are shown as text to type, not links to click. |
| Impostor fork | Ship a lookalike that phones home | We can't stop forks. We can make verification trivial and print the fingerprint of the *real* signing identity in every release note. |
| Nosy household member / employer | Reads files on disk | Evidence folders are under the user's own profile. That is all; local-privacy against someone with your password is not a promise we can keep. |
| Witness itself | Bugs in our own code become attack surface | No network. No parsers of untrusted input except the OS's own event XML (via `roxmltree`, bounded at 8 MB). `unsafe` confined to four files. Runs unprivileged. Runs with ACG/CIG/CET/CFG/no-remote-images on itself. `panic = "abort"`. |

## Trust assumptions

* We trust the Windows kernel and Event Log to report honestly **until the
  moment an attacker owns the kernel**, after which nothing on the machine
  is trustworthy, Witness included. The report tells the user this.
* We trust `getrandom` for the seed and DPAPI for wrapping it.
* We trust the RustCrypto `ml-dsa` implementation to be correct. It is
  pure Rust and pre-1.0; we pin the exact version and re-review on bump.
  If a reviewer prefers a hybrid (ML-DSA + Ed25519) that is a 40-line change
  in `signing.rs` and we are open to it.
* We do not trust ourselves to write user-facing text alone. It gets
  reviewed by people who have actually supported at-risk users.

## Deliberate non-features

Each of these was considered and rejected. Re-opening one needs a reason
that beats the one given here.

* **No network, no update check.** A tool for people under surveillance
  must not beacon. Users check releases themselves; the release page shows
  how to verify.
* **No tray icon in v0.1.** It is a dependency and a UI surface for a thing
  that should be silent until it matters. Revisit in v0.3 if users ask.
* **No kernel driver, no ETW-TI, no hooking.** That is an EDR. It needs
  Microsoft MVI membership and a team. Witness reads what the OS already
  writes.
* **No "you have been hacked".** Ever. The strongest wording is "this
  pattern is sometimes seen when someone tries to break in".
* **No admin rights.** If a channel needs elevation on some Windows SKU,
  `witness check` says so and we document the manual step. We never
  auto-elevate.
* **No configuration UI.** Rules and contacts are TOML files the user can
  read. A settings screen is a place to hide things.

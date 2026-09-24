# Build plan

Each phase has an exit test. Nothing moves to the next phase until it passes.
"Done" means merged, tested in CI, and documented; not "works on my machine".

Honest status (2026-09-24): CI green on all six jobs. `witness-win` is
built, run and proven on Windows 11 Pro 26200: fast-fail and every
kernel-enforced mitigation Witness has a rule for (ACG, child process,
low-integrity image, remote image, CIG) fired live and are golden-tested
from the captured XML. Not yet: the UserMode family (no triggers, by
decision), the hour-long fuzz run, the container half of the
reproducibility check, and all of Phase 3.

## Phase 0 — Repository hygiene (half a day)

- [x] Repository set to `github.com/thomasthumb/witness` in `Cargo.toml` and `release.yml`.
- [x] Full Apache-2.0 text in `LICENSE-APACHE`.
- [x] Pin `rust-toolchain.toml` to an exact version (1.95.0).
- [x] `Cargo.lock` committed; CI runs `--locked`.
- [ ] Enable branch protection: CI required, no force-push, signed commits.
- [ ] Enable GitHub Security Advisories and Dependabot (security updates only).
- [ ] `cargo vet init` and record the initial audit set; add `cargo vet` to CI.

Exit: CI green on an empty commit; `cargo deny check` and `cargo audit` pass.

## Phase 1 — Core compiles and is proven on Linux (1–2 days)

1. [x] `cargo test -p witness-core` on Linux. `ml-dsa` pinned to `=0.1.1`
   (`SigningKey::from_seed`, deterministic `Signer::sign`, `zeroize` on).
2. [x] Property tests (`proptest`) for `winevt::parse` and `report::esc`:
   arbitrary input never panics, escaped output never contains `<`, `>`, `"`, `'`.
3. [~] `fuzz/` has targets for `winevt::parse` and `RuleSet::parse`, corpus
   seeded from the captured fixtures; CI runs each for 60 s on nightly.
   [ ] Run each for an hour locally (`cargo +nightly fuzz run winevt_parse --
   -max_total_time=3600`) and commit the grown corpus.
4. [x] Golden tests over the shipped `rules/default.toml` and `contacts.toml`
   (`crates/witness-core/tests/shipped_files.rs`): synthetic XML plus every
   *captured* sample, events 1000, 2, 4, 6, 8 and 12 from build 26200,
   including the Brave CIG false positive and the same event with the DLL
   moved out of Brave's folder.
   Also fixed: Application Error 1000 field mapping (the path is `%11`, the
   scaffold read `%10`, the start time).

Exit: 100% of core public functions have a test; fuzz runs clean for 1 hour;
clippy pedantic has no new warnings.

## Phase 2 — Windows binary works end to end (2–3 days)

1. First build on Windows: `cargo build --release -p witness-win`, then
   `witness check`, `witness selftest`. The FFI already type-checks against
   the bindings, so this should be a link-and-run, not a fix-up. If anything
   does need changing, keep each fix a separate commit.
2. `witness check` reports all three channels reachable and self-hardening
   applied on Windows 10 22H2 and Windows 11 24H2, as a standard user.
   If a channel needs elevation on some SKU, document it; do not elevate.
3. Trigger real events and confirm a bundle + toast + report for each:
   * `0xC0000409`: a 20-line C program with a deliberate `/GS` cookie
     smash, and a CET fault via `__fastfail(FAST_FAIL_INCORRECT_STACK)`.
   * ACG: enable ACG for `notepad.exe` via Exploit Protection, then run a
     tiny program that `VirtualProtect`s a page to RWX inside it.
   * Remote image: attempt a `LoadLibrary` from a UNC path in a protected process.
   `tests/triggers/trigger.c` covers the first two and the ACG case; the
   remote-image case still needs writing. Record every observation in
   `tests/triggers/README.md`; that table is how anyone verifies the rules
   actually fire, and how CI on a self-hosted Windows runner can do it later.
4. Verify each Security-Mitigations event ID in `rules/default.toml` against
   what the live machine actually writes. Fix the file, not the machine.
5. Test on a machine with Exploit Protection entirely off: Witness should
   say so in `check` (baseline snapshot is v0.2, but a one-line warning is v0.1).
   [~] `check` now reports a channel that is subscribable but *disabled*
   (Windows writes nothing to it) as DISABLED with the `wevtutil` fix, and
   `run` logs it; before, it said "ok". Still to do: the per-program
   Exploit Protection side.

Exit: every rule has been fired on real hardware; `witness verify` passes on
every generated bundle; an edited bundle fails; a fresh install prints a
fingerprint and the same fingerprint appears in every report.

## Phase 3 — Words (2–3 days, not optional, not last)

1. Every `triage` block reviewed by at least one person who has done digital
   security support for at-risk users. Access Now's helpline and Freedom of
   the Press Foundation both have people who will do this if asked kindly.
2. Test the report with three non-technical people. Watch them read it. If
   any of them asks "so am I hacked?", the text is not done.
3. `contacts.toml` verified: every entry answers. [x] `checked = "YYYY-MM"`
   field on each entry and a CI job (`scripts/check_contacts.py`) that fails
   if any entry is older than 6 months. [ ] Actually phone/visit each one.
4. README written for two audiences, in that order: the frightened user
   (200 words, no jargon) and the helper/reviewer (everything else).

Exit: written sign-off from one outside reviewer on the triage text.

## Phase 4 — Release engineering (1–2 days)

1. `--locked` reproducible builds; document the exact command and confirm
   two independent machines produce byte-identical `witness.exe`.
   [x] The exact command is `scripts\build-release.ps1`, used by the
   release workflow, `reproduce.ps1` and the container alike. `/Brepro`
   replaces the link timestamp and debug GUID with hashes;
   `--remap-path-prefix` (through `cargo --config`, which merges with the
   hardening flags; RUSTFLAGS would replace them) takes CARGO_HOME, the
   checkout and the target dir out of the binary, and with them the
   builder's user name. It writes `build-info.txt`: hash, rustc, and the
   MSVC build numbers read from the binary's Rich header.
   [x] Proven on one machine: two builds from different source folders,
   CARGO_HOME paths and target dirs, byte-identical (x86_64 `3df053c6…`
   with rustc 1.95.0 and MSVC 14.44.35207), PE flags and CETCOMPAT intact.
   [ ] The second machine: build the container image, run `reproduce.ps1`.
   The MSVC toolset has to match too; compare the two `build-info.txt`.
2. SignPath Foundation application for free OSS Authenticode signing. Until
   approved, releases carry a SmartScreen warning; the README explains why
   and how to verify with cosign instead.
3. Release workflow produces: two `.exe`, two SBOMs, two `build-info`,
   `SHA256SUMS`, Sigstore bundles, GitHub provenance attestation. Release
   notes contain the verification commands (already in `release.yml`).
   [x] Fixed before it ever ran: the build job had `contents: write` and
   `id-token: write` while running every dependency's build script (now
   read-only; only `publish` can write or sign); the published cosign
   check used an unanchored identity regexp any repository could satisfy
   from a branch named `github.com/ThomasThumb/Witness` (now the exact
   workflow and tag); the arm64 target was added to `stable`, not the
   pinned toolchain; artifacts were uploaded nested, so `publish` could not
   find them. [ ] Dry run: Actions → release → Run workflow (builds and
   uploads, publishes nothing) before the first tag.
4. `winget` manifest submitted after the first signed release.
5. `verify_bundle.py`: a 40-line dependency-light Python script (using a
   pure-Python ML-DSA or calling `witness verify`) so a helpline can verify a
   bundle without installing anything from us. If pure-Python ML-DSA is not
   practical, ship `witness verify` as a separate tiny static binary instead.

Exit: a stranger can download, verify provenance, run `witness check`, and
verify a bundle, following only the README.

## Phase 5 — External review before telling anyone (2–4 weeks, calendar)

1. Ask for code review from two people who did not write it. Rust
   security-minded reviewers hang out in the RustSec and Rust Foundation
   security channels; this is a small enough codebase that people say yes.
2. Send the threat model and repo to Citizen Lab, Amnesty Security Lab and
   Access Now with a one-paragraph ask: "does this help or hurt your users?"
   Take their answer seriously, including "don't ship this".
3. Fix everything found. Publish the review outcomes in `docs/reviews/`.

Exit: two written reviews in the repo; all high/critical findings closed.

## Phase 6 — Distribution and the Android half

1. Announce only through channels that reach the target population: Access
   Now, FPF, EFF's Security Education group, Consumer Reports Security
   Planner, RightsCon, a BSides talk. No launch posts aimed at the general
   public; they are not the users and they will generate support load.
2. Open a design proposal on the GrapheneOS issue tracker: "MTE crash
   notification → plain-English triage with evidence export". Bring the
   Windows tool as proof the copy and flow work. Offer to write it.
3. Set up a `SUPPORT.md` that routes users to helplines, not to the
   maintainer. The maintainer is not a helpline.

Exit: listed by at least one of the organisations above; GrapheneOS proposal
filed and discussed.

## Ongoing

* Monthly: `cargo update` + `cargo deny` + `cargo audit` + re-verify contacts.
* On every Windows feature update: re-run `tests/triggers/` and confirm event
  IDs have not moved.
* Never: add a network feature, add telemetry, weaken the "we cannot prevent
  attacks" language. If a future maintainer wants to, they fork under a
  different name.

# Contributing

Thank you. Three kinds of help are especially valuable, and none require Rust:

1. **Rules and triage text.** `rules/default.toml` is the product. If a rule
   fires on something innocent, or the text would frighten or confuse
   someone, open a PR. Every rule needs a plain-English explanation a scared
   person can act on; that is a hard requirement, not a style preference.
2. **Contacts.** `rules/contacts.toml`. Country-specific helplines that
   actually answer. Verify they exist before adding; check again before release.
3. **Review.** Read the code. Especially `crates/witness-win/src/{eventlog,keys,harden,notify}.rs`,
   the only files allowed to contain `unsafe`. Tell us what we got wrong.

## Rules for code

* KISS. If a change adds a dependency, the PR explains why the standard
  library or an existing dependency cannot do it. `deny.toml` bans anything
  that opens a socket.
* No `unsafe` outside the four FFI files. CI enforces it.
* No `unwrap`/`expect`/`panic` in library or main code. CI enforces it.
* Everything in `witness-core` must be testable on Linux and have tests.
* Plain-language text is reviewed for tone, not just accuracy. If it would
  make a frightened person more frightened without telling them what to do,
  it is wrong.

## Rules for behaviour

Users of this tool may be in danger. Never add anything that reports on
them, tracks them, or phones home "just for crash stats". Never add
auto-update. Never soften "we cannot prevent attacks" in the UI.

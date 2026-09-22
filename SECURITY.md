# Security policy

Witness is a security tool for people who may be targeted by well-funded
attackers. We treat every report seriously and we do not shoot messengers.

## Reporting

Email the address in `Cargo.toml`'s `authors` field (added at first release),
or open a GitHub Security Advisory (private). Please include a way to reproduce.
We aim to acknowledge within 3 days and to publish a fix or a public
explanation within 30. We will credit you unless you ask us not to.

Do not report through a public issue if the bug could put a user at risk.

## Scope

In scope: anything in this repository, the release pipeline, and the
published binaries. Especially: ways to make Witness lie (false negatives
in rules, forged bundles, report injection), ways to make it phone home,
and ways to escalate through it.

Out of scope: the Windows features Witness observes (report those to
Microsoft), and "Witness didn't stop my exploit" — it never claimed to.

## What we promise

* No network code, ever. If you find any, it is a critical bug.
* No telemetry, analytics, crash reporting or update pings.
* Every release is reproducible from a tagged commit and signed by Sigstore
  with GitHub-issued provenance. Instructions are on every release page.
* `unsafe` lives in four named files and nowhere else; CI enforces this.

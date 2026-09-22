# Proposal sketch: plain-English triage for MTE crashes on GrapheneOS

Status: draft to be filed on the GrapheneOS issue tracker after Phase 5 of
BUILD_PLAN.md, with the Windows tool as working evidence that the copy and
flow hold up with real users.

## Why here and not an app

A third-party Android app cannot read other apps' tombstones or DropBox
entries (`READ_LOGS` is system-only), so the only honest place for this is
the OS itself. GrapheneOS already shows a notification when hardware memory
tagging kills an app. The gap is what that notification says and what the
user can do next.

## The ask

1. When the MTE crash notification fires for an app in a small "high-risk"
   allowlist (messaging, browsers, document viewers), offer a second screen
   with three sections: what happened, what it might mean (usually a bug),
   what to do. Same three-tier severity as Witness: bug / look / urgent.
2. An "export evidence" action that packages the tombstone, the app's
   version, the OS build, and a manifest with hashes into a single file the
   user can hand to a helpline. Signed by a per-device key if the project
   wants it; unsigned is still better than nothing.
3. Contacts shown as text, not links, sourced from a reviewable file.

## What we bring

* Reviewed plain-language triage text, already tested with non-technical
  users on the Windows side.
* A vetted helpline list with a checked-date convention.
* Willingness to write the patch to the project's standards.

## What we are not asking for

Any change to MTE policy, any new permission, any network feature, or any
claim in the UI that the device was attacked.

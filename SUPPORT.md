# Getting help

## If Witness showed you a warning and you are worried

**Do not open a GitHub issue.** Issues are public, and the person who
maintains Witness is not a helpline. These organisations help people for
free and will not think you are paranoid. Type the address yourself:

* **Access Now Digital Security Helpline**: journalists, activists,
  human-rights defenders and civil society; 24/7, free, multilingual.
  `accessnow.org/help`
* **Amnesty International Security Lab**: people who believe they were
  targeted with spyware. `securitylab.amnesty.org`
* **Citizen Lab (University of Toronto)**: journalists and civil society
  targeted by governments. `citizenlab.ca`
* **Freedom of the Press Foundation Digital Security**: journalists and
  newsrooms. `freedom.press/digisec`
* **Australian Cyber Security Centre (ACSC)**: anyone in Australia.
  `1300 CYBER1 (1300 292 371)` or `cyber.gov.au`

Take the evidence folder named in the report with you. Zip it, keep a copy
somewhere that is not the computer, and do not edit anything in it.

## Never post an evidence folder publicly

Evidence bundles contain your computer's name, your Windows account's
security ID and the paths of programs on your machine. Share them only
with a helpline or a person you trust, never in a public issue or forum.

## Bugs in Witness itself

* **Security problems** (Witness could lie, leak, be forged, or talk to a
  network): report privately, see [SECURITY.md](SECURITY.md).
* **A rule that fires on something innocent, or text that confused or
  frightened you**: open an issue with the rule id from the report (for
  example `cig-block`) and the program's name. Describe the event in
  words; do not paste `event.raw.xml`.
* **Anything else that is broken**: open an issue with the output of
  `witness check`, after deleting two lines: `base:` contains your Windows
  user name, and `key:` would link any evidence you ever share to you.

This list mirrors `rules/contacts.toml`, which is what the reports show.
If the two ever disagree, the reports are right and this file is a bug.

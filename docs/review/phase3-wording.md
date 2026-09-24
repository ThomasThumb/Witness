# Witness: plain-language review

**For:** people who have done digital-security support for at-risk users:
journalists, lawyers, activists, human-rights defenders.
**Time:** about an hour, perhaps two.
**What we ask:** read what Witness says to a frightened person, and tell us
where it is wrong, unclear, or does harm. "Do not ship this" is an
acceptable answer.

You need no GitHub account and nothing installed. Reply however suits you;
an email with comments is enough. Name the rule (for example
`remote-image-block`) and say what you would change. Section 7 has a short
sign-off to copy into your reply.

Every quoted line below is copied verbatim from
[`rules/default.toml`](../../rules/default.toml),
[`rules/contacts.toml`](../../rules/contacts.toml) and
[`crates/witness-core/src/report.rs`](../../crates/witness-core/src/report.rs)
as of 2026-09-24. If those files have changed since, they are what counts.

## 1. What Witness is

Windows already stops many attacks on programs' memory. When it does, it
writes a line to a log almost nobody reads, and the program simply
vanishes. Witness is a small free program that runs quietly on a Windows
computer, notices those lines, and explains them in plain English: what
happened, what it might mean, what to do, and who can help. It keeps a
signed copy of what Windows recorded, so a helpline can check nothing was
altered afterwards.

It prevents nothing, never says "you have been hacked", contains no
network code at all, and cannot see an attack that got past Windows'
protections. Most of what it reports will be ordinary software bugs. The
words decide whether a person reacts in proportion, which is why we are
asking you.

## 2. What the person sees

1. A Windows notification. Its title is the rule's title (section 5); its
   text is always *"Witness noticed something. Tap to read what it means."*
2. A report opens in their web browser by itself. It is a file on their
   own computer, with no links, scripts or images.
3. An evidence folder is written; the report says where.

Rules marked `bug` show nothing; the event is only written to a log.

The report, top to bottom:

| Part | Text |
|---|---|
| Title | the rule's title |
| Box | "look" rules: *"This is unusual but usually harmless. It is worth a look."*<br>"urgent" rules: *"This pattern is sometimes seen when someone tries to break into a computer. It does not mean that happened to you."* |
| What happened | from the rule |
| What it might mean | from the rule |
| What to do | from the rule, numbered |
| Who can help | *"These organisations help people for free and will not judge you for asking. Type the address yourself rather than clicking anything."* Then the list in section 4. |
| For a technical helper | *"Evidence folder: `%LOCALAPPDATA%\Witness\evidence\…`. Zip that whole folder and send it; do not edit anything in it."*<br>*"Witness signing key fingerprint: `xxxx-xxxx-…`. If you wrote this down when Witness was installed, check it matches."*<br>Then a table of everything Windows recorded about the event. |
| What Witness is not | *"Witness cannot prevent attacks and cannot tell you for certain whether one happened. It notices when Windows' own protections fire and explains it in plain language. If your computer is already compromised, this report could be wrong. When in doubt, ask a human above."* |

## 3. What we are asking

Read each rule as the person who has just seen that notification, and ask:

1. **Could they act on it?** Every step should be something a frightened,
   non-technical person can actually do.
2. **Is it proportionate?** It must not frighten without saying what to
   do, and must not reassure where it should not.
3. **Is it true?** Especially the advice: disconnect or not, keep evidence
   how, call whom.
4. **Would they ask "so am I hacked?" after reading it?** If so, it is not
   done.

## 4. Text on every report

The helpline list, as it appears (addresses are shown as text to type,
never as links):

- **Access Now Digital Security Helpline** (journalists, activists, human-rights defenders, and civil society; 24/7, free, multilingual): `accessnow.org/help`
- **Amnesty International Security Lab** (people who believe they were targeted with spyware): `securitylab.amnesty.org`
- **Citizen Lab (University of Toronto)** (journalists and civil society targeted by governments): `citizenlab.ca`
- **Freedom of the Press Foundation Digital Security** (journalists and newsrooms): `freedom.press/digisec`
- **Australian Cyber Security Centre (ACSC) hotline** (anyone in Australia): `1300 CYBER1 (1300 292 371) or cyber.gov.au`


**Questions for you:**

- The two box sentences in section 2: right tone for "look" and for "urgent"?
- Is this the right list for the people you support, in the right order?
  Anything missing: a country, a secure channel such as a Signal number?
- Addresses are text to type, never links, so a frightened person cannot
  be sent to a look-alike site. Sensible, or a barrier?
- The notification says "Tap to read what it means", but the report has
  already opened by itself. Better wording?
- "What Witness is not": honest without being alarming?
- The fingerprint check assumes the person wrote their fingerprint on
  paper when Witness was installed. Realistic?

## 5. Every rule, in the order Witness checks them

The first rule that fits an event wins, so specific rules come before
general ones. "Fired on real hardware" means we made Windows raise that
exact event on a real machine and saw Witness match it. "Not seen" means
the rule rests on Microsoft's documentation alone.

### 1. `fastfail-messaging-browser`

*`urgent`: shown as "sometimes seen when someone tries to break in". The event (1000) fired on real hardware from a test program, which matched rule 2; this rule's app list is checked in tests, not by crashing a real messaging app.*

**Behind it:** A program on the list (browsers, messaging apps, email, PDF readers) was shut down by Windows because its memory was corrupted: a stack-cookie check, hardware shadow-stack (CET) check or deliberate fast-fail. Usually a bug in the app; these are also the apps attackers aim at, because they open things strangers send.

**Programs this rule covers:** `signal.exe`, `whatsapp.exe`, `telegram.exe`, `element.exe`, `discord.exe`, `slack.exe`, `teams.exe`, `ms-teams.exe`, `chrome.exe`, `msedge.exe`, `firefox.exe`, `brave.exe`, `opera.exe`, `vivaldi.exe`, `librewolf.exe`, `tor.exe`, `outlook.exe`, `thunderbird.exe`, `olk.exe`, `acrord32.exe`, `acrobat.exe`, `sumatrapdf.exe`, `foxitpdfreader.exe`

**What the person sees:**

> **Windows stopped an app that talks to the internet**
>
> *What happened:* Windows detected that this app's memory was being corrupted and shut it down before the corruption could do anything.
>
> *What it might mean:* Most of the time this is an ordinary bug in the app. But apps that receive messages, web pages or documents from strangers are exactly the ones attackers target, and this is what a blocked break-in attempt looks like from the outside. Witness cannot tell the difference. A person can.
>
> *What to do:*
> 1. Take a breath. Nothing has been stolen by this event; the protection worked.
> 2. Do not uninstall the app or 'clean' the computer yet. That destroys evidence.
> 3. Note what you were doing: had you just received a message, file, link or call from someone you don't know?
> 4. If it happens again with the same app within a few days, treat it as serious.
> 5. If you are a journalist, lawyer, activist, or work with people who are, contact one of the helplines below. It is free and they will not think you are paranoid.
> 6. Zip the evidence folder named in this report and keep a copy somewhere that is not this computer.

**Questions for you:**

- Is **urgent** right for something that is usually a bug, given who these apps are exposed to?
- Is the app list right for your users? Anything missing (for example Zoom, Wire, Threema, Proton apps) or wrong?
- Is "If it happens again with the same app within a few days, treat it as serious" useful, or does it just add worry?

**Your verdict:** approve / approve with changes / rewrite / remove

---

### 2. `fastfail-any`

*`look`: shown as "worth a look". Fired on real hardware.*

**Behind it:** Same protection as above, in any other program.

**What the person sees:**

> **Windows stopped a program to protect its memory**
>
> *What happened:* A program's memory was being corrupted and Windows shut it down before the corruption could do anything.
>
> *What it might mean:* Almost always an ordinary bug in that program. It is on this list because the same protection also stops break-in attempts, and you should know when it fires.
>
> *What to do:*
> 1. If the program is something you installed on purpose and it just crashed once, you can ignore this.
> 2. If it keeps happening, or the program is one that opens files or messages from strangers, keep the evidence folder and ask a technical person to look.

**Questions for you:**

- Is it acceptable to tell someone they "can ignore this"?

**Your verdict:** approve / approve with changes / rewrite / remove

---

### 3. `acg-block-kernel`

*`look`: shown as "worth a look". Fired on real hardware (event 2). The event names the program, not what it was doing.*

**Behind it:** Arbitrary Code Guard, which a person or helper has switched on for a program, refused that program's attempt to make memory runnable. Some legitimate programs do this; almost every memory-corruption exploit needs to.

**What the person sees:**

> **Windows blocked a program from creating new code in memory**
>
> *What happened:* A program tried to turn a chunk of its memory into runnable code, and Windows' Arbitrary Code Guard refused.
>
> *What it might mean:* Some legitimate programs (games, old software, some developer tools) do this and simply crash under Arbitrary Code Guard. It is also the step almost every memory-corruption exploit needs. Look at which program it was.
>
> *What to do:*
> 1. Check the process name in this report. If it is an app you deliberately protected with Exploit Protection and it is known not to work with ACG, that is the cause.
> 2. If it is a browser, messaging or document app, keep the evidence and ask for help.

**Questions for you:**

- "Arbitrary Code Guard" and "known not to work with ACG": can a non-technical person act on this at all, or should the text just say "ask a technical person which it is"?

**Your verdict:** approve / approve with changes / rewrite / remove

---

### 4. `acg-block-user`

*`look`: shown as "worth a look". **Not yet seen on real hardware** in this log; based on Microsoft's documentation.*

**Behind it:** The same refusal, reported through a different Windows log.

**What the person sees:**

> **Windows blocked a program from creating new code in memory**
>
> *What happened:* A program tried to turn a chunk of its memory into runnable code, and Windows' Arbitrary Code Guard refused.
>
> *What it might mean:* Same as the kernel-side version of this event: often an incompatible legitimate program, sometimes the key step of an exploit.
>
> *What to do:*
> 1. Check which program it was. Known-incompatible software you installed yourself is the boring answer.
> 2. Otherwise keep the evidence and ask for help.

**Questions for you:**

- Same question as the rule above.

**Your verdict:** approve / approve with changes / rewrite / remove

---

### 5. `child-process-block`

*`look`: shown as "worth a look". Fired on real hardware (event 4).*

**Behind it:** A program that is not allowed to start other programs (a per-program setting) tried to. The event names the program it tried to start; the report shows that only in the technical table.

**What the person sees:**

> **Windows stopped a protected program from launching another program**
>
> *What happened:* A program that is not allowed to start other programs tried to, and Windows refused.
>
> *What it might mean:* Often a legitimate feature (opening a downloaded file, an updater) in an app you chose to lock down. Launching a second program is also how many exploits go from 'inside one app' to 'on the whole computer'.
>
> *What to do:*
> 1. Look at which program it was and whether you had just clicked something that would reasonably open another app.
> 2. If you had not, or the program is a browser, messaging or document app, keep the evidence and ask for help.

**Questions for you:**

- Is the "inside one app / on the whole computer" explanation clear?
- Should the text tell the reader which program was refused (it is in the technical table), or would that add confusion?

**Your verdict:** approve / approve with changes / rewrite / remove

---

### 6. `low-integrity-image-block`

*`look`: shown as "worth a look". Fired on real hardware (event 6).*

**Behind it:** A protected program tried to load code from a file Windows marks as untrusted (typically something a download or web page wrote). The event names the file.

**What the person sees:**

> **Windows blocked a program from loading code from an untrusted download location**
>
> *What happened:* A protected program tried to load a code library from a location Windows marks as untrusted (usually somewhere a download or a web page wrote to), and Windows refused.
>
> *What it might mean:* Occasionally caused by legitimate software that unpacks itself into a temporary folder. It is also a very common step in getting attacker code to run.
>
> *What to do:*
> 1. Check which program it was. If you had just installed or opened it on purpose, that is the likely cause.
> 2. Otherwise keep the evidence and ask for help.

**Questions for you:**

- Is "untrusted download location" understandable?
- Should the text point at the file name shown in the technical table?

**Your verdict:** approve / approve with changes / rewrite / remove

---

### 7. `remote-image-block`

*`urgent`: shown as "sometimes seen when someone tries to break in". Fired on real hardware (event 8).*

**Behind it:** A protected program tried to load code from a network location. Rare on a personal computer; a known technique for getting attacker code to run. The event names only the program, not the network location.

**What the person sees:**

> **Windows blocked a program from loading code from the network**
>
> *What happened:* A program tried to load a code library from a network location and Windows refused.
>
> *What it might mean:* Legitimate software almost never does this on a personal computer. It is a common way for an attacker to get their own code running. If this computer is on a company network with shared drives, that can be an innocent cause.
>
> *What to do:*
> 1. Disconnect from Wi-Fi or unplug the network cable if you are worried. Do not turn the computer off.
> 2. Keep the evidence folder and contact a helpline or a technical person you trust today.

**Questions for you:**

- Is **urgent** right?
- "Disconnect from Wi-Fi or unplug the network cable ... Do not turn the computer off": is that what your helpline would tell someone, in that order?

**Your verdict:** approve / approve with changes / rewrite / remove

---

### 8. `cig-self-bundled`

*`bug`: logged only, never shown. Fired on real hardware (Brave, event 12).*

**Behind it:** **Never shown to the person**: severity `bug` means it is only written to the log. It covers a program refused one of its *own* libraries (from its own install folder), which browsers such as Brave do several times at every start. Without this rule, every Chromium user would get a "worth a look" alert daily.

**What the person sees:**

> **A program was refused one of its own libraries**
>
> *What happened:* A program that asked Windows to only let it load Microsoft-signed code then tried to load one of its own, non-Microsoft libraries, and was refused.
>
> *What it might mean:* The program's own settings tripped its own protection. Browsers do this routinely and carry on working.
>
> *What to do:*
> 1. Nothing. This is recorded in witness.log in case a technical helper wants to see it.

**Questions for you:**

- Do you agree this should stay silent? One known gap: for apps installed in a folder the user can write to (Signal, Discord, Slack, per-user Chrome), a planted library there would also be silenced. Is that trade-off acceptable, or would you rather see occasional false alarms?

**Your verdict:** approve / approve with changes / rewrite / remove

---

### 9. `cig-block`

*`look`: shown as "worth a look". Fired on real hardware (event 12): Brave's start-up refusals first matched this rule, which is why rule 8 exists.*

**Behind it:** A protected program was refused a library that Microsoft did not sign, from outside the program's own folder. Often plugins, accessibility tools, screen recorders or antivirus injecting themselves.

**What the person sees:**

> **Windows blocked an unsigned code library**
>
> *What happened:* A protected program tried to load a code library that was not signed by Microsoft, and Code Integrity Guard refused.
>
> *What it might mean:* Frequently caused by third-party plugins, accessibility tools, screen recorders or antivirus injecting into apps. Occasionally caused by malware doing the same thing.
>
> *What to do:*
> 1. Check the report for which library was blocked. If you recognise it as something you installed, that is the cause.
> 2. If you do not recognise it, keep the evidence and ask for help.

**Questions for you:**

- "Check the report for which library was blocked": realistic for a non-technical person, or should it just say "ask someone to look"?

**Your verdict:** approve / approve with changes / rewrite / remove

---

### 10. `eaf-block`

*`urgent`: shown as "sometimes seen when someone tries to break in". **Not seen on real hardware** (no test program, by the maintainer's decision). Based on Microsoft's documentation.*

**Behind it:** Export Address Filtering stopped a program reading Windows' table of system functions in the way exploit code does. Only active for programs someone has explicitly opted in.

**What the person sees:**

> **Windows blocked a program from reading its own address book**
>
> *What happened:* Windows' Export Address Filtering caught a program reading the table of system functions in a way normal programs do not, and stopped it.
>
> *What it might mean:* This is a classic step in exploit code that has just gained a foothold and is looking for what to call next. A few security products and old programs trip it innocently; most software never does.
>
> *What to do:*
> 1. Disconnect from the network. Do not turn the computer off; that can destroy evidence in memory.
> 2. Keep the evidence folder. Contact a helpline below today.

**Questions for you:**

- The title ("reading its own address book") is a metaphor. Does it help or confuse? It is shared with the rule below.
- Should these unconfirmed rules be shown as "worth a look" instead of **urgent** until they have been seen for real?

**Your verdict:** approve / approve with changes / rewrite / remove

---

### 11. `iaf-block`

*`urgent`: shown as "sometimes seen when someone tries to break in". **Not seen on real hardware.***

**Behind it:** Import Address Filtering: the same idea as the rule above, for the functions a program imports.

**What the person sees:**

> **Windows blocked a program from reading its own address book**
>
> *What happened:* Windows' Import Address Filtering caught a program reading the table of functions it imports in a way normal programs do not, and stopped it.
>
> *What it might mean:* Like Export Address Filtering above: a classic exploit step with few innocent causes.
>
> *What to do:*
> 1. Disconnect from the network. Do not turn the computer off; that can destroy evidence in memory.
> 2. Keep the evidence folder. Contact a helpline below today.

**Questions for you:**

- See the rule above.

**Your verdict:** approve / approve with changes / rewrite / remove

---

### 12. `rop-stackpivot-block`

*`urgent`: shown as "sometimes seen when someone tries to break in". **Not seen on real hardware.***

**Behind it:** A return-oriented-programming check: the program's stack was swapped in a way ordinary programs never do. Only active for programs someone opted in.

**What the person sees:**

> **Windows blocked a return-oriented-programming attack pattern**
>
> *What happened:* Windows' exploit protection detected a program's control flow being hijacked in a way that has no ordinary explanation, and stopped it.
>
> *What it might mean:* This specific check (stack pivot detection) has very few innocent causes. It is not proof of an attack, but it is the closest thing on this list.
>
> *What to do:*
> 1. Disconnect from the network. Do not turn the computer off; that can destroy evidence in memory.
> 2. Keep the evidence folder. Contact a helpline below today.
> 3. If you are a journalist, lawyer, activist or work with people at risk, say so when you call; it changes how they help you.

**Questions for you:**

- "It is not proof of an attack, but it is the closest thing on this list": right tone, or too alarming?
- The third step ("say so when you call; it changes how they help you"): true for your helpline?

**Your verdict:** approve / approve with changes / rewrite / remove

---

### 13. `rop-callercheck-block`

*`urgent`: shown as "sometimes seen when someone tries to break in". **Not seen on real hardware.***

**Behind it:** A return-oriented-programming check: a sensitive system function was reached by a `return` instead of a `call`.

**What the person sees:**

> **Windows blocked a return-oriented-programming attack pattern**
>
> *What happened:* Windows' exploit protection saw a sensitive system function being called in a way that skips the normal path (a 'return' instead of a 'call'), and stopped it.
>
> *What it might mean:* This is a hallmark of return-oriented programming, the technique exploits use to run code without being allowed to write any. Some just-in-time compilers trigger it innocently, which is why it is only enabled for programs you opted in.
>
> *What to do:*
> 1. Disconnect from the network. Do not turn the computer off; that can destroy evidence in memory.
> 2. Keep the evidence folder. Contact a helpline below today.

**Questions for you:**

- Is the 'return instead of a call' explanation too technical to include?

**Your verdict:** approve / approve with changes / rewrite / remove

---

### 14. `rop-simexec-block`

*`urgent`: shown as "sometimes seen when someone tries to break in". **Not seen on real hardware.***

**Behind it:** A return-oriented-programming check that simulates what the program was about to do.

**What the person sees:**

> **Windows blocked a return-oriented-programming attack pattern**
>
> *What happened:* Windows' exploit protection simulated where a program was about to go next, found it was chaining together fragments of code in a way real programs do not, and stopped it.
>
> *What it might mean:* Same family as the two rules above. Rarely innocent.
>
> *What to do:*
> 1. Disconnect from the network. Do not turn the computer off; that can destroy evidence in memory.
> 2. Keep the evidence folder. Contact a helpline below today.

**Questions for you:**

- "Rarely innocent": fair, given it only runs for opted-in programs?

**Your verdict:** approve / approve with changes / rewrite / remove

---

## 6. Questions across all rules

1. **Disconnect, but do not power off.** Several rules say to disconnect
   from the network and not to turn the computer off, so evidence in
   memory survives. Is that your advice for someone who is not technical?
2. **Keeping evidence.** Rules say to zip the evidence folder and keep a
   copy somewhere that is not this computer. Realistic and safe? Where
   would you want people to keep it?
3. **Privacy of evidence.** The evidence folder holds what Windows
   recorded, which includes the computer's name, the Windows account's ID
   and the paths of programs. The report does not say so. Should it say,
   before "send it", who it is safe to send it to?
4. **Severity.** People see only two levels: "worth a look" and
   "sometimes seen when someone tries to break in". Enough? Too many
   rules at "urgent"?
5. **Anything missing.** Is there a step you always ask people to take
   that no rule mentions?
6. **Overall.** Would you want the people you support to run this? If
   not, why not?

## 7. Sign-off

Copy this into your reply and fill in what you are comfortable with. We
credit reviewers only in the way they ask, or not at all.

```
Reviewer:           (name, or "anonymous")
Organisation:       (optional)
Date:
Overall:            ship / ship after changes / do not ship
Approved as written (rule ids):
Need changes (rule id: what):
Anything else:
```

Reviews and their outcomes are published in `docs/reviews/` with the
credit you choose (BUILD_PLAN.md phases 3 and 5).

## Appendix: reading test with three non-technical people

*For the maintainer: BUILD_PLAN.md phase 3, step 2.*

1. Run `witness selftest` on a Windows computer with Witness. A report
   opens. Cover the "THIS IS A TEST" box, or ask the reader to ignore it.
2. Hand it to someone who is not technical, saying only "this appeared on
   your computer".
3. Ask them, in their own words: what happened, whether they are in
   danger, and what they would do next. Do not help.
4. Note every word they stumble on and every question they ask. If anyone
   asks "so am I hacked?", the text is not done.
5. Selftest only shows a "worth a look" report. Repeat with an "urgent"
   rule by reading them rule 7 (`remote-image-block`) from section 5.

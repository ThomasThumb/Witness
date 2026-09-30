//! `witness` — the Windows binary.
//!
//! Subcommands (all local, none need admin):
//!   run          watch the event log until closed (what the scheduled task runs)
//!   check        print status: rules loaded, channels reachable, key fingerprint
//!   selftest     push a built-in sample event through the whole pipeline
//!   verify DIR [FINGERPRINT]
//!                verify an evidence bundle's signature and hashes; with the
//!                fingerprint the user wrote down, also that this install made it
//!   export DIR   the bundle as one ZIP on the Desktop, ready to send
//!   fingerprint  print the signing-key fingerprint to write down
//!   protect      print the admin commands that switch on the safe protections
//!                for the high-risk apps running now (we change nothing ourselves)
//!   install      print the one-line Scheduled Task command (we do not silently persist)
//!
//! Layout on disk (%LOCALAPPDATA%\Witness):
//!   seed.dpapi        DPAPI-wrapped 32-byte signing seed
//!   rules.toml        optional override of the embedded rules
//!   contacts.toml     optional override of the embedded contacts
//!   evidence\         one folder per finding (evidence\selftest\ for `selftest`)
//!   witness.log       plain-text log

#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![warn(clippy::pedantic)]

mod cli;
mod eventlog;
mod harden;
mod keys;
mod notify;
mod paths;
mod processes;
mod protect;

use std::{
    collections::HashMap,
    fs,
    io::Write as _,
    path::{Path, PathBuf},
    process::ExitCode,
    sync::mpsc,
    time::{Duration, Instant},
};
use witness_core::{
    evidence, history,
    report::{self, Contact},
    rules::{RuleSet, Severity},
    signing::Identity,
    winevt,
};

const EMBEDDED_RULES: &str = include_str!("../../../rules/default.toml");
const EMBEDDED_CONTACTS: &str = include_str!("../../../rules/contacts.toml");

/// Channels we subscribe to. Adding one is a DESIGN.md change.
const CHANNELS: &[&str] = &[
    "Application",
    "Microsoft-Windows-Security-Mitigations/KernelMode",
    "Microsoft-Windows-Security-Mitigations/UserMode",
];

/// An Application Error 1000 (fast-fail in notepad) in the named-field form
/// Windows 11 writes (captured on build 26200, see
/// `crates/witness-core/tests/fixtures/`). Used by `selftest` to exercise
/// parse → match → bundle → sign → toast → open without waiting for a real
/// fault. Matches `fastfail-any` (severity look) in the shipped rules.
const SELFTEST_XML: &str = r"<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System>
<Provider Name='Application Error' Guid='{a0e9b465-b939-57d7-b27d-95d8e925ff57}'/><EventID>1000</EventID><Version>0</Version><Level>2</Level>
<Task>100</Task><Opcode>0</Opcode><Keywords>0x8000000000000000</Keywords><TimeCreated SystemTime='2000-01-01T00:00:00.0000000Z'/>
<EventRecordID>0</EventRecordID><Correlation/><Execution ProcessID='0' ThreadID='0'/><Channel>Application</Channel><Computer>selftest</Computer><Security/></System>
<EventData><Data Name='AppName'>notepad.exe</Data><Data Name='AppVersion'>10.0.0.0</Data><Data Name='AppTimeStamp'>00000000</Data>
<Data Name='ModuleName'>ntdll.dll</Data><Data Name='ModuleVersion'>10.0.0.0</Data><Data Name='ModuleTimeStamp'>00000000</Data>
<Data Name='ExceptionCode'>c0000409</Data><Data Name='FaultingOffset'>0000000000000000</Data><Data Name='ProcessId'>0x0</Data>
<Data Name='ProcessCreationTime'>0x0</Data><Data Name='AppPath'>C:\Windows\System32\notepad.exe</Data>
<Data Name='ModulePath'>C:\Windows\System32\ntdll.dll</Data><Data Name='IntegratorReportId'>selftest</Data>
<Data Name='PackageFullName'></Data><Data Name='PackageRelativeAppId'></Data></EventData></Event>";

#[derive(serde::Deserialize)]
struct Contacts {
    #[serde(default, rename = "contact")]
    contact: Vec<Contact>,
}

/// One toast per (rule, process) per this long. Every event still gets its
/// own bundle; only the interruption is throttled. Observed need: Chromium
/// trips the same mitigation several times within a second.
const NOTIFY_WINDOW: Duration = Duration::from_secs(60);

/// Everything the watcher needs, loaded once.
struct App {
    rules: RuleSet,
    contacts: Vec<Contact>,
    id: Identity,
    evidence_root: PathBuf,
    last_notified: HashMap<String, Instant>,
    /// `witness selftest`: bundles go under `evidence\selftest\` and the report
    /// and toast say TEST. Never set by `run`.
    test: bool,
}

fn main() -> ExitCode {
    // Harden ourselves before touching anything else. Failure is logged, not fatal:
    // an old Windows without these policies should still get the rest.
    harden::apply();

    let args: Vec<String> = std::env::args().collect();
    let cmd = args.get(1).map_or("help", String::as_str);
    let result = match cmd {
        "run" => run(),
        "check" => check(),
        "selftest" => selftest(),
        "verify" => args.get(2).map_or_else(
            || Err("usage: witness verify <bundle-dir> [expected-fingerprint]".into()),
            |d| cli::verify(Path::new(d), args.get(3).map(String::as_str)),
        ),
        "export" => {
            args.get(2).map_or_else(|| Err("usage: witness export <bundle-dir>".into()), |d| cli::export(Path::new(d)))
        }
        "fingerprint" => cli::fingerprint(),
        "protect" => App::load(false).and_then(|app| protect::commands(&app.rules)),
        "install" => cli::install(),
        _ => {
            println!(
                "witness {} — see README.md\n  run | check | selftest | verify <dir> [fingerprint] | export <dir> | fingerprint | protect | install",
                witness_core::VERSION
            );
            Ok(())
        }
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("witness: {e}");
            log(&format!("error: {e}"));
            ExitCode::FAILURE
        }
    }
}

impl App {
    fn load(test: bool) -> Result<Self, String> {
        let base = paths::base()?;
        let rules = RuleSet::parse(&override_or(&base, "rules.toml", EMBEDDED_RULES)?).map_err(|e| e.to_string())?;
        let contacts: Contacts =
            toml::from_str(&override_or(&base, "contacts.toml", EMBEDDED_CONTACTS)?).map_err(|e| e.to_string())?;
        let seed = keys::load_or_create_seed()?;
        let id = Identity::from_seed(&seed).map_err(|e| e.to_string())?;
        let mut evidence_root = base.join("evidence");
        if test {
            evidence_root.push("selftest");
        }
        fs::create_dir_all(evidence_root.join("quiet")).map_err(|e| e.to_string())?;
        Ok(App { rules, contacts: contacts.contact, id, evidence_root, last_notified: HashMap::new(), test })
    }

    /// One event, start to finish. Returns the bundle directory if one was written.
    /// Every failure is a `String` the caller logs; nothing here ends the watcher.
    fn handle(&mut self, xml: &str) -> Result<Option<PathBuf>, String> {
        let ev = winevt::parse(xml).map_err(|e| format!("unparseable event ignored: {e:?}"))?;
        let Some(rule) = self.rules.first_match(&ev) else {
            // The Application channel is chatty; only note the event families we
            // could plausibly have rules for, so a helper can tune rules.toml.
            if ev.provider.eq_ignore_ascii_case("Application Error") || ev.channel.contains("Security-Mitigations") {
                log(&format!(
                    "no rule: {} id={} process={:?} exception={:?}",
                    ev.channel,
                    ev.event_id,
                    ev.process_basename(),
                    ev.exception_code.map(|c| format!("0x{c:08X}"))
                ));
            }
            return Ok(None);
        };
        // The refused library is named too, so a helper reading the log can
        // judge a `bug`-severity CIG event, which gets no bundle, for themselves.
        let image = ["ImageName", "ImagePath"].iter().find_map(|k| ev.data.get(*k));
        log(&format!("match {} ({}) process={:?} image={:?}", rule.id, rule.severity, ev.process, image));
        if rule.severity == Severity::Bug {
            // Never shown, but not lost: the first time this program is refused
            // this library, the evidence is written under evidence\quiet\, signed
            // like any other. Repeats (Brave, four per start) cost nothing.
            let dir = history::quiet_dir(&self.evidence_root, &ev, rule);
            if dir.exists() {
                return Ok(None);
            }
            let html =
                report::render(&ev, rule, &self.contacts, &self.id.fingerprint(), &paths::shown(&dir), self.test, 1);
            evidence::write_bundle(&dir, &ev, rule, &html, &self.id)
                .map_err(|e| format!("quiet bundle {}: {e}", paths::shown(&dir)))?;
            log(&format!("quiet bundle written (first time for this program and library): {}", paths::shown(&dir)));
            return Ok(None);
        }
        let dir = evidence::bundle_dir(&self.evidence_root, &ev, rule);
        // This event plus the earlier ones for the same program and rule this
        // week. The rules' text tells people repeats are what matters; from the
        // third, the report and the toast say it for them.
        let basename = ev.process_basename().unwrap_or_default();
        // A selftest always looks like a first alert; its bundles all share one date.
        let repeats =
            if self.test { 1 } else { 1 + history::repeats(&self.evidence_root, &rule.id, &basename, &ev.time, 7) };
        let html =
            report::render(&ev, rule, &self.contacts, &self.id.fingerprint(), &paths::shown(&dir), self.test, repeats);
        evidence::write_bundle(&dir, &ev, rule, &html, &self.id)
            .map_err(|e| format!("bundle {}: {e}", paths::shown(&dir)))?;
        if repeats >= report::REPEAT_THRESHOLD {
            log(&format!("repeat: {} for {basename}, {repeats} times in 7 days", rule.id));
        }

        let key = format!("{}|{}", rule.id, ev.process_basename().unwrap_or_default());
        let now = Instant::now();
        // The event that crosses the repeat threshold is the one to interrupt
        // with; it goes through the throttle. Only that one: the throttle is
        // for Chromium tripping the same guard several times a second.
        let crossing = repeats == report::REPEAT_THRESHOLD;
        if !crossing && self.last_notified.get(&key).is_some_and(|t| now.duration_since(*t) < NOTIFY_WINDOW) {
            log(&format!("notification suppressed (same rule and process within {}s)", NOTIFY_WINDOW.as_secs()));
            return Ok(Some(dir));
        }
        self.last_notified.insert(key, now);
        // Open the report first, then say what happened. The toast borrows
        // PowerShell's notification identity, so tapping it does nothing
        // (checked on Windows 11); it must never ask the person to tap.
        let title = match (self.test, repeats >= report::REPEAT_THRESHOLD) {
            (true, _) => format!("TEST: {}", rule.title),
            (false, true) => format!("AGAIN ({repeats} times this week): {}", rule.title),
            (false, false) => rule.title.clone(),
        };
        let body = match notify::open(&dir.join("report.html")) {
            Ok(()) => "Witness noticed something. A report has opened in your browser.".to_string(),
            Err(e) => {
                log(&format!("open report failed (report still written): {e}"));
                format!("Witness noticed something. The report is saved under {}", paths::SHOWN_BASE)
            }
        };
        if let Err(e) = notify::toast(&title, &body) {
            log(&format!("toast failed (report still written): {e}"));
        }
        Ok(Some(dir))
    }
}

/// Contents of `<base>\<name>` if the user dropped an override there, else the embedded text.
fn override_or(base: &Path, name: &str, embedded: &str) -> Result<String, String> {
    let p = base.join(name);
    if p.exists() {
        fs::read_to_string(&p).map_err(|e| format!("{}: {e}", paths::shown(&p)))
    } else {
        Ok(embedded.to_string())
    }
}

fn run() -> Result<(), String> {
    let mut app = App::load(false)?;
    let (tx, rx) = mpsc::sync_channel::<String>(eventlog::QUEUE_RECORDS);
    let _subs = eventlog::subscribe_all(CHANNELS, &tx)?; // dropped on exit = unsubscribed
    drop(tx); // only the OS callbacks hold senders now; rx ends when they are gone
    log(&format!("running; {} rules; key {}", app.rules.rules.len(), app.id.fingerprint()));
    for ch in CHANNELS {
        if eventlog::enabled(ch) == Ok(false) {
            log(&format!("warning: channel {ch} is disabled; nothing from it will arrive (see `witness check`)"));
        }
    }
    let mut dropped_seen = 0;
    paths::touch_alive();
    loop {
        // Wake at least every HEARTBEAT to touch `alive`, so `check` can
        // tell a quiet machine from a dead watcher.
        let xml = match rx.recv_timeout(paths::HEARTBEAT) {
            Ok(xml) => xml,
            Err(mpsc::RecvTimeoutError::Timeout) => {
                paths::touch_alive();
                continue;
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        };
        eventlog::dequeued(xml.len());
        match app.handle(&xml) {
            Ok(Some(dir)) => log(&format!("bundle written: {}", paths::shown(&dir))),
            Ok(None) => {}
            Err(e) => log(&e), // this event is lost; the watcher keeps running (DESIGN.md)
        }
        paths::touch_alive();
        let dropped = eventlog::dropped();
        if dropped != dropped_seen {
            log(&format!(
                "warning: {} event(s) dropped because they arrived faster than Witness could handle them; \
                 {dropped} since start. Windows keeps them in the Event Log.",
                dropped - dropped_seen
            ));
            dropped_seen = dropped;
        }
    }
    Ok(())
}

fn check() -> Result<(), String> {
    let app = App::load(false)?;
    println!("witness {}", witness_core::VERSION);
    println!("rules:    {} loaded", app.rules.rules.len());
    println!("contacts: {} loaded", app.contacts.len());
    println!("key:      {}", app.id.fingerprint());
    println!("base:     {}", paths::SHOWN_BASE);
    let mut unavailable = 0;
    for ch in CHANNELS {
        match eventlog::probe(ch).and_then(|()| eventlog::enabled(ch)) {
            Ok(true) => println!("channel:  {ch}  ok"),
            Ok(false) => {
                unavailable += 1;
                println!("channel:  {ch}  DISABLED: Windows writes nothing here, so Witness sees nothing from it.");
                println!("          To turn it on, as administrator:  wevtutil sl \"{ch}\" /e:true");
            }
            Err(e) => {
                unavailable += 1;
                println!("channel:  {ch}  UNAVAILABLE ({e})");
            }
        }
    }
    println!("self:     {}", harden::status());
    match paths::alive_age_secs() {
        None => println!("watcher:  has never run on this machine. `witness install` prints how to start it at logon."),
        Some(s) if s <= 2 * paths::HEARTBEAT.as_secs() => println!("watcher:  alive ({} min ago)", s / 60),
        Some(s) => println!(
            "watcher:  NOT RUNNING. Last alive {} ago; nothing has been watched since. `witness install` prints how to start it.",
            if s < 86_400 { format!("{} h {} min", s / 3600, (s % 3600) / 60) } else { format!("{} days", s / 86_400) }
        ),
    }
    if let Err(e) = protect::report(&app.rules) {
        println!("apps:     could not list running programs ({e})");
    }
    if unavailable == CHANNELS.len() {
        return Err("no channel is readable; Witness would see nothing".into());
    }
    Ok(())
}

fn selftest() -> Result<(), String> {
    let mut app = App::load(true)?;
    log("selftest: pushing the built-in sample event");
    println!("Pushing a built-in sample event (a fast-fail in notepad.exe) through Witness.");
    println!("You should see a toast and the report should open in your browser.");
    match app.handle(SELFTEST_XML)? {
        Some(dir) => {
            let m = evidence::verify_bundle(&dir, Some(&app.id.fingerprint()))?;
            println!("OK: bundle {} rule={} severity={} verified", paths::shown(&dir), m.rule_id, m.severity);
            println!("This was a test. The folder above is safe to delete.");
            Ok(())
        }
        None => Err("sample event matched no rule; rules.toml override may be wrong".into()),
    }
}

fn log(line: &str) {
    if let Ok(base) = paths::base() {
        if let Ok(mut f) = fs::OpenOptions::new().create(true).append(true).open(base.join("witness.log")) {
            let _ = writeln!(f, "{} {}", now(), line);
        }
    }
}

fn now() -> String {
    // No chrono dependency: seconds since epoch is enough for a local log.
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs().to_string())
        .unwrap_or_default()
}

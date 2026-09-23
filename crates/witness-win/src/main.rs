//! `witness` — the Windows binary.
//!
//! Subcommands (all local, none need admin):
//!   run          watch the event log until closed (what the scheduled task runs)
//!   check        print status: rules loaded, channels reachable, key fingerprint
//!   selftest     push a built-in sample event through the whole pipeline
//!   verify DIR   verify an evidence bundle's signature and hashes
//!   fingerprint  print the signing-key fingerprint to write down
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

mod eventlog;
mod harden;
mod keys;
mod notify;
mod paths;

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
    evidence,
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
        "verify" => {
            args.get(2).map_or_else(|| Err("usage: witness verify <bundle-dir>".into()), |d| verify(Path::new(d)))
        }
        "fingerprint" => fingerprint(),
        "install" => install(),
        _ => {
            println!(
                "witness {} — see README.md\n  run | check | selftest | verify <dir> | fingerprint | install",
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
    fn load(evidence_subdir: Option<&str>) -> Result<Self, String> {
        let base = paths::base()?;
        let rules = RuleSet::parse(&override_or(&base, "rules.toml", EMBEDDED_RULES)?).map_err(|e| e.to_string())?;
        let contacts: Contacts =
            toml::from_str(&override_or(&base, "contacts.toml", EMBEDDED_CONTACTS)?).map_err(|e| e.to_string())?;
        let seed = keys::load_or_create_seed()?;
        let id = Identity::from_seed(&seed).map_err(|e| e.to_string())?;
        let mut evidence_root = base.join("evidence");
        if let Some(sub) = evidence_subdir {
            evidence_root.push(sub);
        }
        fs::create_dir_all(&evidence_root).map_err(|e| e.to_string())?;
        Ok(App { rules, contacts: contacts.contact, id, evidence_root, last_notified: HashMap::new() })
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
        log(&format!("match {} ({}) process={:?}", rule.id, rule.severity, ev.process));
        if rule.severity == Severity::Bug {
            return Ok(None); // logged, not shown
        }
        let dir = evidence::bundle_dir(&self.evidence_root, &ev, rule);
        let html = report::render(&ev, rule, &self.contacts, &self.id.fingerprint(), &dir.display().to_string());
        evidence::write_bundle(&dir, &ev, rule, &html, &self.id)
            .map_err(|e| format!("bundle {}: {e}", dir.display()))?;

        let key = format!("{}|{}", rule.id, ev.process_basename().unwrap_or_default());
        let now = Instant::now();
        if self.last_notified.get(&key).is_some_and(|t| now.duration_since(*t) < NOTIFY_WINDOW) {
            log(&format!("notification suppressed (same rule and process within {}s)", NOTIFY_WINDOW.as_secs()));
            return Ok(Some(dir));
        }
        self.last_notified.insert(key, now);
        if let Err(e) = notify::toast(&rule.title, "Witness noticed something. Tap to read what it means.") {
            log(&format!("toast failed (report still written): {e}"));
        }
        if let Err(e) = notify::open(&dir.join("report.html")) {
            log(&format!("open report failed (report still written): {e}"));
        }
        Ok(Some(dir))
    }
}

/// Contents of `<base>\<name>` if the user dropped an override there, else the embedded text.
fn override_or(base: &Path, name: &str, embedded: &str) -> Result<String, String> {
    let p = base.join(name);
    if p.exists() {
        fs::read_to_string(&p).map_err(|e| format!("{}: {e}", p.display()))
    } else {
        Ok(embedded.to_string())
    }
}

fn run() -> Result<(), String> {
    let mut app = App::load(None)?;
    let (tx, rx) = mpsc::channel::<String>();
    let _subs = eventlog::subscribe_all(CHANNELS, &tx)?; // dropped on exit = unsubscribed
    drop(tx); // only the OS callbacks hold senders now; rx ends when they are gone
    log(&format!("running; {} rules; key {}", app.rules.rules.len(), app.id.fingerprint()));
    for xml in rx {
        match app.handle(&xml) {
            Ok(Some(dir)) => log(&format!("bundle written: {}", dir.display())),
            Ok(None) => {}
            Err(e) => log(&e), // this event is lost; the watcher keeps running (DESIGN.md)
        }
    }
    Ok(())
}

fn check() -> Result<(), String> {
    let app = App::load(None)?;
    println!("witness {}", witness_core::VERSION);
    println!("rules:    {} loaded", app.rules.rules.len());
    println!("contacts: {} loaded", app.contacts.len());
    println!("key:      {}", app.id.fingerprint());
    println!("base:     {}", paths::base()?.display());
    let mut unavailable = 0;
    for ch in CHANNELS {
        match eventlog::probe(ch) {
            Ok(()) => println!("channel:  {ch}  ok"),
            Err(e) => {
                unavailable += 1;
                println!("channel:  {ch}  UNAVAILABLE ({e})");
            }
        }
    }
    println!("self:     {}", harden::status());
    if unavailable == CHANNELS.len() {
        return Err("no channel is readable; Witness would see nothing".into());
    }
    Ok(())
}

fn selftest() -> Result<(), String> {
    let mut app = App::load(Some("selftest"))?;
    log("selftest: pushing the built-in sample event");
    println!("Pushing a built-in sample event (a fast-fail in notepad.exe) through Witness.");
    println!("You should see a toast and the report should open in your browser.");
    match app.handle(SELFTEST_XML)? {
        Some(dir) => {
            let m = evidence::verify_bundle(&dir)?;
            println!("OK: bundle {} rule={} severity={} verified", dir.display(), m.rule_id, m.severity);
            println!("This was a test. The folder above is safe to delete.");
            Ok(())
        }
        None => Err("sample event matched no rule; rules.toml override may be wrong".into()),
    }
}

fn verify(dir: &Path) -> Result<(), String> {
    let m = evidence::verify_bundle(dir)?;
    println!(
        "OK: bundle {} rule={} severity={} witness={} key={}",
        dir.display(),
        m.rule_id,
        m.severity,
        m.witness_version,
        m.key_fingerprint
    );
    println!("The key must match the fingerprint written down when Witness was installed; if it differs, another install made this bundle.");
    let extra = evidence::unsigned_entries(dir).map_err(|e| e.to_string())?;
    if !extra.is_empty() {
        println!("NOT covered by the signature, do not trust: {}", extra.join(", "));
    }
    Ok(())
}

fn fingerprint() -> Result<(), String> {
    let seed = keys::load_or_create_seed()?;
    let id = Identity::from_seed(&seed).map_err(|e| e.to_string())?;
    println!("{}", id.fingerprint());
    println!("Write this down on paper. If a report ever shows a different fingerprint, the evidence was not made by this install.");
    Ok(())
}

fn install() -> Result<(), String> {
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    println!("Witness does not install itself. To start it at logon, run in PowerShell:");
    println!();
    println!("  schtasks /Create /TN Witness /SC ONLOGON /RL LIMITED /TR \"\\\"{}\\\" run\"", exe.display());
    println!();
    println!("To remove:  schtasks /Delete /TN Witness /F");
    println!("Then run:   witness fingerprint   and write the result down.");
    println!("Optional:   witness selftest     to see what a real alert looks like.");
    Ok(())
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

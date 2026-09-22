//! Golden tests over the files we actually ship: `rules/default.toml` and
//! `rules/contacts.toml`. If these fail, the product is broken regardless of
//! what the unit tests say.

use witness_core::{
    report::Contact,
    rules::{RuleSet, Severity},
    winevt,
};

const RULES: &str = include_str!("../../../rules/default.toml");
const CONTACTS: &str = include_str!("../../../rules/contacts.toml");

#[derive(serde::Deserialize)]
struct Contacts {
    contact: Vec<Contact>,
}

fn app_error(exe_path: &str, code: &str) -> String {
    format!(
        r#"<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System>
<Provider Name="Application Error"/><EventID Qualifiers="0">1000</EventID><Version>0</Version><Level>2</Level>
<Task>100</Task><Opcode>0</Opcode><Keywords>0x80000000000000</Keywords>
<TimeCreated SystemTime="2026-09-22T04:00:00.1234567Z"/><EventRecordID>4242</EventRecordID><Correlation/>
<Execution ProcessID="0" ThreadID="0"/><Channel>Application</Channel><Computer>desktop</Computer><Security/></System>
<EventData><Data>{name}</Data><Data>1.0.0.0</Data><Data>66f00000</Data><Data>ntdll.dll</Data><Data>10.0.26100.1</Data>
<Data>66e00000</Data><Data>{code}</Data><Data>000000000009d1d5</Data><Data>0x1a2c</Data><Data>0x1dc2b7f3a9e1c00</Data>
<Data>{path}</Data><Data>C:\WINDOWS\SYSTEM32\ntdll.dll</Data><Data>5d1e0f2a-3b4c-4d5e-8f60-718293a4b5c6</Data>
<Data></Data><Data></Data></EventData></Event>"#,
        name = exe_path.rsplit('\\').next().unwrap_or(exe_path),
        path = exe_path,
    )
}

fn mitigation(channel: &str, id: u32, process: &str) -> String {
    format!(
        r#"<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System>
<Provider Name="Microsoft-Windows-Security-Mitigations" Guid="{{fae10392-f0af-4ac0-b8ff-9f4d920c3cdf}}"/>
<EventID>{id}</EventID><Version>0</Version><Level>3</Level><Task>0</Task><Opcode>0</Opcode>
<TimeCreated SystemTime="2026-09-22T04:01:00.0000000Z"/><Channel>{channel}</Channel><Computer>desktop</Computer></System>
<EventData><Data Name="ProcessPathLength">{len}</Data><Data Name="ProcessPath">{process}</Data>
<Data Name="ProcessCommandLineLength">0</Data><Data Name="ProcessCommandLine"></Data>
<Data Name="ProcessId">1234</Data><Data Name="ProcessCreateTime">2026-09-22T04:00:59Z</Data>
<Data Name="ProcessStartKey">1</Data><Data Name="ProcessSignatureLevel">4</Data><Data Name="ProcessSectionSignatureLevel">4</Data>
<Data Name="ProcessProtection">0</Data></EventData></Event>"#,
        len = process.len(),
    )
}

#[test]
fn shipped_rules_parse_and_cover_the_families_we_promise() {
    let set = RuleSet::parse(RULES).expect("rules/default.toml must parse");
    assert!(set.rules.len() >= 6);
    // Specific-before-general ordering: the messaging rule must come before the catch-all.
    let pos = |id: &str| set.rules.iter().position(|r| r.id == id).unwrap_or_else(|| panic!("rule {id} missing"));
    assert!(pos("fastfail-messaging-browser") < pos("fastfail-any"));
    assert!(pos("cig-self-bundled") < pos("cig-block"), "the quiet self-bundled rule must shadow the loud one");
    // Every severity that shows a report must tell the user what to do.
    for r in &set.rules {
        assert!(!r.triage.what_to_do.is_empty(), "{}", r.id);
        assert!(
            !r.triage.what_it_might_mean.to_lowercase().contains("you have been hacked"),
            "{} violates THREAT_MODEL.md",
            r.id
        );
    }
}

#[test]
fn shipped_rules_classify_realistic_events() {
    let set = RuleSet::parse(RULES).expect("rules parse");
    let cases: &[(String, Option<(&str, Severity)>)] = &[
        (
            app_error(r"C:\Users\x\AppData\Local\Programs\signal-desktop\Signal.exe", "c0000409"),
            Some(("fastfail-messaging-browser", Severity::Urgent)),
        ),
        (
            app_error(r"C:\Program Files\Google\Chrome\Application\chrome.exe", "c0000409"),
            Some(("fastfail-messaging-browser", Severity::Urgent)),
        ),
        (app_error(r"C:\Windows\System32\notepad.exe", "c0000409"), Some(("fastfail-any", Severity::Look))),
        (app_error(r"C:\Windows\System32\notepad.exe", "c0000005"), None), // plain access violation: not our business
        (
            mitigation("Microsoft-Windows-Security-Mitigations/KernelMode", 2, r"C:\Program Files\Foo\foo.exe"),
            Some(("acg-block-kernel", Severity::Look)),
        ),
        (
            mitigation("Microsoft-Windows-Security-Mitigations/UserMode", 2, r"C:\Program Files\Foo\foo.exe"),
            Some(("acg-block-user", Severity::Look)),
        ),
        (
            mitigation("Microsoft-Windows-Security-Mitigations/KernelMode", 8, r"C:\x\a.exe"),
            Some(("remote-image-block", Severity::Urgent)),
        ),
        (
            mitigation("Microsoft-Windows-Security-Mitigations/KernelMode", 12, r"C:\x\a.exe"),
            Some(("cig-block", Severity::Look)),
        ),
        (
            mitigation("Microsoft-Windows-Security-Mitigations/UserMode", 20, r"C:\x\a.exe"),
            Some(("rop-stackpivot-block", Severity::Urgent)),
        ),
        (mitigation("Microsoft-Windows-Security-Mitigations/KernelMode", 1, r"C:\x\a.exe"), None), // audit event: noise
        // Captured on Windows 11 build 26200 from tests/triggers/trigger.exe fastfail (named fields).
        (
            include_str!("fixtures/win11-26200-app-error-1000-fastfail.xml").to_string(),
            Some(("fastfail-any", Severity::Look)),
        ),
        (
            include_str!("fixtures/win11-26200-app-error-1000-fastfail.xml").replace("trigger.exe", "signal.exe"),
            Some(("fastfail-messaging-browser", Severity::Urgent)),
        ),
    ];
    for (xml, expected) in cases {
        let ev = winevt::parse(xml).expect("fixture parses");
        let got = set.first_match(&ev).map(|r| (r.id.as_str(), r.severity));
        assert_eq!(got, *expected, "event {} on {}", ev.event_id, ev.channel);
    }
}

#[test]
fn shipped_contacts_parse_and_are_dated() {
    let c: Contacts = toml::from_str(CONTACTS).expect("rules/contacts.toml must parse");
    assert!(!c.contact.is_empty());
    for k in &c.contact {
        assert!(!k.name.is_empty() && !k.for_whom.is_empty() && !k.how.is_empty(), "{:?}", k.name);
        assert!(!k.how.starts_with("http"), "{}: show addresses as text to type, not links", k.name);
        let ok = k.checked.len() == 7
            && k.checked.as_bytes()[4] == b'-'
            && k.checked.chars().filter(|c| c.is_ascii_digit()).count() == 6;
        assert!(ok, "{}: checked must be YYYY-MM, got {:?}", k.name, k.checked);
    }
}

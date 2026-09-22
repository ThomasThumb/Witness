//! Parse Windows Event Log XML (as rendered by `EvtRender(EvtRenderEventXml)`)
//! into an [`Event`]. Pure code: lives in core so it is tested on every OS.
//!
//! We parse only what rules can match on and copy everything else verbatim.
//! If Microsoft changes a schema, the rule stops matching and the raw XML is
//! still in the bundle; we never silently guess.

use crate::event::{parse_code, Event};
use std::collections::BTreeMap;

/// Largest event record we will parse. The OS side enforces the same cap
/// before allocating; this is defence in depth for callers that don't.
pub const MAX_EVENT_BYTES: usize = 8 * 1024 * 1024;

/// Parse errors.
#[derive(Debug, PartialEq, Eq)]
pub enum ParseError {
    /// Not well-formed XML.
    Xml(String),
    /// Well-formed but missing the `System` block we need.
    Missing(&'static str),
    /// Larger than [`MAX_EVENT_BYTES`].
    TooLarge(usize),
}

/// Parse one event record.
///
/// # Errors
/// Oversized input, malformed XML, or a record without the `System` fields rules need.
pub fn parse(xml: &str) -> Result<Event, ParseError> {
    if xml.len() > MAX_EVENT_BYTES {
        return Err(ParseError::TooLarge(xml.len()));
    }
    let doc = roxmltree::Document::parse(xml).map_err(|e| ParseError::Xml(e.to_string()))?;
    let root = doc.root_element();
    let system = root.children().find(|n| n.has_tag_name("System")).ok_or(ParseError::Missing("System"))?;

    let text_of = |tag: &str| -> Option<String> {
        system.children().find(|n| n.has_tag_name(tag)).and_then(|n| n.text()).map(str::trim).map(String::from)
    };
    let attr_of = |tag: &str, attr: &str| -> Option<String> {
        system.children().find(|n| n.has_tag_name(tag)).and_then(|n| n.attribute(attr)).map(String::from)
    };

    let event_id = text_of("EventID").and_then(|s| s.parse::<u32>().ok()).ok_or(ParseError::Missing("EventID"))?;
    let channel = text_of("Channel").ok_or(ParseError::Missing("Channel"))?;
    let provider = attr_of("Provider", "Name").unwrap_or_default();
    let record_id = text_of("EventRecordID").and_then(|s| s.parse::<u64>().ok()).unwrap_or(0);
    let time = attr_of("TimeCreated", "SystemTime").unwrap_or_default();

    // EventData: named <Data Name="..."> or, for classic providers like
    // "Application Error", positional <Data> elements. Keep both.
    let mut data = BTreeMap::new();
    let mut positional = Vec::new();
    if let Some(ed) = root.children().find(|n| n.has_tag_name("EventData")) {
        for d in ed.children().filter(|n| n.has_tag_name("Data")) {
            let v = d.text().unwrap_or("").trim().to_string();
            match d.attribute("Name") {
                Some(name) => {
                    data.insert(name.to_string(), v);
                }
                None => positional.push(v),
            }
        }
    }
    for (i, v) in positional.iter().enumerate() {
        data.insert(format!("p{}", i + 1), v.clone());
    }

    let (process, exception_code) = extract(&provider, event_id, &data);

    Ok(Event { time, channel, provider, event_id, record_id, process, exception_code, data, raw: xml.to_string() })
}

/// Field extraction. Deliberately small and explicit.
///
/// Named fields first: Windows 11 (observed on build 26200) writes Application
/// Error 1000 with `AppPath` / `ExceptionCode` names, and every
/// Security-Mitigations event names its fields. Positional fallback second:
/// older Windows writes Application Error 1000 as bare `<Data>` in the order of
/// the message template (%1 app name … %7 exception code … %11 app path).
fn extract(provider: &str, event_id: u32, data: &BTreeMap<String, String>) -> (Option<String>, Option<u32>) {
    let first = |keys: &[&str]| keys.iter().filter_map(|k| data.get(*k)).find(|s| !s.is_empty()).cloned();
    let mut process =
        first(&["AppPath", "ProcessPath", "ProcessName", "ImagePath", "Image", "TargetProcessPath", "AppName"]);
    let mut code = first(&["ExceptionCode", "Status", "NTSTATUS"]).and_then(|s| parse_code(&s));
    if provider.eq_ignore_ascii_case("Application Error") && event_id == 1000 {
        process = process.or_else(|| first(&["p11", "p1"]));
        code = code.or_else(|| first(&["p7"]).and_then(|s| parse_code(&s)));
    }
    (process, code)
}

#[cfg(test)]
mod tests {
    use super::*;

    const APP_ERROR: &str = r#"<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
<System><Provider Name="Application Error"/><EventID Qualifiers="0">1000</EventID>
<TimeCreated SystemTime="2026-09-22T04:00:00.0000000Z"/><Channel>Application</Channel></System>
<EventData><Data>Signal.exe</Data><Data>7.0.0.0</Data><Data>66f00000</Data><Data>ntdll.dll</Data>
<Data>10.0.26100.1</Data><Data>66e00000</Data><Data>c0000409</Data><Data>0000000000012345</Data>
<Data>1a2c</Data><Data>01dc2b7f3a9e1c00</Data><Data>C:\Users\x\AppData\Local\Programs\signal-desktop\Signal.exe</Data>
<Data>C:\WINDOWS\SYSTEM32\ntdll.dll</Data><Data>5d1e0f2a-3b4c-4d5e-8f60-718293a4b5c6</Data></EventData></Event>"#;

    const MITIGATION: &str = r#"<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
<System><Provider Name="Microsoft-Windows-Security-Mitigations"/><EventID>2</EventID>
<TimeCreated SystemTime="2026-09-22T04:01:00Z"/><Channel>Microsoft-Windows-Security-Mitigations/KernelMode</Channel></System>
<EventData><Data Name="ProcessPath">C:\Program Files\Foo\foo.exe</Data><Data Name="ProcessId">1234</Data></EventData></Event>"#;

    #[test]
    fn parses_classic_application_error() {
        let e = parse(APP_ERROR).expect("parse");
        assert_eq!(e.event_id, 1000);
        assert_eq!(e.channel, "Application");
        assert_eq!(e.exception_code, Some(0xC000_0409));
        assert_eq!(e.process_basename().as_deref(), Some("signal.exe"));
        assert_eq!(e.process.as_deref(), Some(r"C:\Users\x\AppData\Local\Programs\signal-desktop\Signal.exe"));
        assert_eq!(e.data.get("p1").map(String::as_str), Some("Signal.exe"));
        assert_eq!(e.data.get("p12").map(String::as_str), Some(r"C:\WINDOWS\SYSTEM32\ntdll.dll"));
        assert_eq!(e.raw, APP_ERROR);
    }

    #[test]
    fn parses_named_mitigation_event() {
        let e = parse(MITIGATION).expect("parse");
        assert_eq!(e.event_id, 2);
        assert_eq!(e.process_basename().as_deref(), Some("foo.exe"));
        assert_eq!(e.exception_code, None);
        assert_eq!(e.provider, "Microsoft-Windows-Security-Mitigations");
    }

    #[test]
    fn parses_named_application_error_as_written_by_windows_11() {
        let xml = include_str!("../tests/fixtures/win11-26200-app-error-1000-fastfail.xml");
        let e = parse(xml).expect("parse");
        assert_eq!(e.event_id, 1000);
        assert_eq!(e.record_id, 438_227);
        assert_eq!(e.exception_code, Some(0xC000_0409));
        assert_eq!(e.process.as_deref(), Some(r"C:\Witness\witness\tests\triggers\trigger.exe"));
        assert_eq!(e.process_basename().as_deref(), Some("trigger.exe"));
        assert_eq!(
            e.data.get("ModulePath").map(String::as_str),
            Some(r"C:\Witness\witness\tests\triggers\trigger.exe")
        );
    }

    #[test]
    fn app_error_without_path_falls_back_to_name() {
        let short = APP_ERROR
            .replace(r"<Data>C:\Users\x\AppData\Local\Programs\signal-desktop\Signal.exe</Data>", "<Data></Data>");
        let e = parse(&short).expect("parse");
        assert_eq!(e.process.as_deref(), Some("Signal.exe"));
    }

    #[test]
    fn rejects_garbage_without_panicking() {
        assert!(matches!(parse("<not xml"), Err(ParseError::Xml(_))));
        assert_eq!(parse("<Event/>"), Err(ParseError::Missing("System")));
        assert_eq!(parse("<Event><System><Channel>x</Channel></System></Event>"), Err(ParseError::Missing("EventID")));
        let huge = format!("<Event>{}</Event>", " ".repeat(MAX_EVENT_BYTES));
        assert!(matches!(parse(&huge), Err(ParseError::TooLarge(_))));
    }

    #[test]
    fn external_entities_are_not_expanded() {
        // roxmltree refuses DTDs with external entities; a compromised process
        // cannot make us read a file into the report.
        let xxe = r#"<!DOCTYPE e [<!ENTITY x SYSTEM "file:///c:/secret">]><Event><System><EventID>1</EventID><Channel>&x;</Channel></System></Event>"#;
        assert!(matches!(parse(xxe), Err(ParseError::Xml(_))));
    }

    proptest::proptest! {
        #[test]
        fn never_panics_on_arbitrary_input(s in "\\PC{0,512}") {
            let _ = parse(&s);
        }

        #[test]
        fn never_panics_on_arbitrary_event_shapes(
            id in "[0-9]{0,12}", ch in "[^<&\\r]{0,32}", name in "[^<&\"]{0,16}", val in "[^<&]{0,64}"
        ) {
            let xml = format!(
                "<Event><System><EventID>{id}</EventID><Channel>{ch}</Channel></System>\
                 <EventData><Data Name=\"{name}\">{val}</Data><Data>{val}</Data></EventData></Event>"
            );
            if let Ok(e) = parse(&xml) {
                proptest::prop_assert_eq!(e.raw, xml);
                proptest::prop_assert_eq!(e.channel, ch.trim());
            }
        }
    }
}

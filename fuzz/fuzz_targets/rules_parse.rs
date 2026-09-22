//! Rules come from a file the user (or a helper) can edit. A malformed file
//! must produce an error, never a panic, and a well-formed one must be
//! usable against an arbitrary event without panicking.
#![no_main]
use libfuzzer_sys::fuzz_target;
use std::collections::BTreeMap;

fuzz_target!(|data: &[u8]| {
    let Ok(s) = std::str::from_utf8(data) else { return };
    let Ok(set) = witness_core::rules::RuleSet::parse(s) else { return };
    let ev = witness_core::event::Event {
        time: "2026-09-22T04:00:00Z".into(),
        channel: "Application".into(),
        provider: "Application Error".into(),
        event_id: 1000,
        record_id: 1,
        process: Some(r"C:\x\notepad.exe".into()),
        exception_code: Some(0xC000_0409),
        data: BTreeMap::new(),
        raw: String::new(),
    };
    let _ = set.first_match(&ev);
});

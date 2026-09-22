//! The only parser of OS-supplied input. Must never panic, whatever the
//! Event Log hands us, and whatever a process able to influence event
//! fields writes into them.
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        if let Ok(ev) = witness_core::winevt::parse(s) {
            // Everything downstream of a successful parse must also hold up.
            let _ = ev.process_basename();
            let _ = ev.image_in_process_dir();
            let _ = witness_core::report::esc(&ev.raw);
        }
    }
});

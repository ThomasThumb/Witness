//! A normalized, OS-agnostic view of one "something tripped" event.
//!
//! The Windows crate turns raw Event Log XML into this. Rules only ever see
//! this struct, so the matching logic is testable without Windows.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// One normalized event.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Event {
    /// RFC 3339 timestamp as reported by the OS.
    pub time: String,
    /// Log channel, e.g. `Application` or `Microsoft-Windows-Security-Mitigations/UserMode`.
    pub channel: String,
    /// Provider name, e.g. `Application Error`.
    pub provider: String,
    /// Numeric event ID.
    pub event_id: u32,
    /// `EventRecordID`: unique per channel on the machine that wrote it. 0 if absent.
    #[serde(default)]
    pub record_id: u64,
    /// Path or name of the process the event concerns, if known.
    pub process: Option<String>,
    /// Exception / NTSTATUS code if the event carries one (e.g. `0xC0000409`).
    pub exception_code: Option<u32>,
    /// Every `<Data Name=..>` field the OS gave us, verbatim. Kept for evidence.
    pub data: BTreeMap<String, String>,
    /// The raw record as rendered by the OS. Written to the evidence bundle untouched.
    pub raw: String,
}

impl Event {
    /// Lower-cased file name of `process`, e.g. `chrome.exe`, for matching.
    #[must_use]
    pub fn process_basename(&self) -> Option<String> {
        let p = self.process.as_deref()?;
        let name = p.rsplit(['\\', '/']).next().unwrap_or(p);
        Some(name.to_ascii_lowercase())
    }

    /// Does the blocked image (`ImageName` / `ImagePath` in the event data) live
    /// inside the directory of the process that tried to load it?
    ///
    /// Observed on Windows 11: Chromium browsers enable Code Integrity Guard on
    /// their own child processes and are then refused their own bundled DLLs
    /// (`brave.exe` → `<install>\<version>\vulkan-1.dll`). That is a bug in the
    /// program's own configuration, not an intrusion, and rules use this to
    /// keep it quiet. `false` whenever either path is unknown.
    #[must_use]
    pub fn image_in_process_dir(&self) -> bool {
        let Some(process) = self.process.as_deref() else { return false };
        let Some(image) = ["ImageName", "ImagePath"].iter().find_map(|k| self.data.get(*k)) else { return false };
        let process = normalize_path(process);
        let Some(dir) = process.rfind('\\').map(|i| &process[..=i]) else { return false };
        normalize_path(image).starts_with(dir)
    }
}

/// Lower-case, backslashes only, and strip the two prefixes the kernel and the
/// Win32 layer disagree about: `\Device\HarddiskVolumeN` and a drive letter.
/// Good enough to compare two paths from the same event; not a general canonicaliser.
fn normalize_path(p: &str) -> String {
    let mut s = p.replace('/', "\\").to_ascii_lowercase();
    if let Some(rest) = s.strip_prefix("\\device\\harddiskvolume") {
        s = rest.trim_start_matches(|c: char| c.is_ascii_digit()).to_string();
    } else if s.len() > 2 && s.as_bytes()[1] == b':' {
        s = s[2..].to_string();
    }
    s
}

/// Parse a hex or decimal code such as `c0000409`, `0xC0000409` or `3221226505`.
#[must_use]
pub fn parse_code(s: &str) -> Option<u32> {
    let t = s.trim();
    let t = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")).unwrap_or(t);
    // Event Log renders exception codes as bare hex; try hex first, then decimal.
    u32::from_str_radix(t, 16).ok().or_else(|| t.parse::<u32>().ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basename_is_lowercased_and_stripped() {
        let e = Event {
            time: String::new(),
            channel: String::new(),
            provider: String::new(),
            event_id: 0,
            record_id: 0,
            process: Some(r"C:\Program Files\Google\Chrome\CHROME.EXE".into()),
            exception_code: None,
            data: BTreeMap::new(),
            raw: String::new(),
        };
        assert_eq!(e.process_basename().as_deref(), Some("chrome.exe"));
    }

    #[test]
    fn image_in_process_dir_bridges_kernel_and_win32_paths() {
        let mut e = Event {
            time: String::new(),
            channel: String::new(),
            provider: String::new(),
            event_id: 12,
            record_id: 0,
            process: Some(
                r"\Device\HarddiskVolume3\Program Files\BraveSoftware\Brave-Browser\Application\brave.exe".into(),
            ),
            exception_code: None,
            data: BTreeMap::new(),
            raw: String::new(),
        };
        assert!(!e.image_in_process_dir(), "no image → false");
        e.data.insert(
            "ImageName".into(),
            r"\Program Files\BraveSoftware\Brave-Browser\Application\153.1.95.104\vulkan-1.dll".into(),
        );
        assert!(e.image_in_process_dir());
        e.data.insert("ImageName".into(), r"C:\PROGRAM FILES\BraveSoftware\Brave-Browser\Application\x.dll".into());
        assert!(e.image_in_process_dir(), "drive letter and case must not matter");
        e.data.insert("ImageName".into(), r"\Users\x\AppData\Local\Temp\evil.dll".into());
        assert!(!e.image_in_process_dir());
        e.data.insert("ImageName".into(), r"\Program Files\BraveSoftware\Brave-Browser\Application-evil\x.dll".into());
        assert!(!e.image_in_process_dir(), "sibling directory with a shared prefix must not match");
    }

    #[test]
    fn parses_codes_in_the_forms_windows_uses() {
        assert_eq!(parse_code("c0000409"), Some(0xC000_0409));
        assert_eq!(parse_code("0xC0000409"), Some(0xC000_0409));
        assert_eq!(parse_code(" C0000005 "), Some(0xC000_0005));
        assert_eq!(parse_code("nope"), None);
    }
}

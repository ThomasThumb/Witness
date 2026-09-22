//! Tell the user. A toast, then open the report in their default browser.
//! The report is a local file with a CSP of `default-src 'none'`, so opening
//! it in a browser is safe; nothing in it can load or run anything.
//!
//! `ShellExecuteW` signature checked by hand against `windows` 0.61.3.

use std::path::Path;
use windows::{
    core::{HSTRING, PCWSTR},
    Win32::UI::{Shell::ShellExecuteW, WindowsAndMessaging::SW_SHOWNORMAL},
};

/// Show a Windows toast. Failure is not fatal: the report still exists on disk.
/// Uses PowerShell's registered `AppUserModelID` so no Start Menu shortcut or
/// installer is needed; the toast is attributed to "Windows PowerShell".
pub fn toast(title: &str, body: &str) -> Result<(), String> {
    use tauri_winrt_notification::{Duration, Toast};
    Toast::new(Toast::POWERSHELL_APP_ID)
        .title(title)
        .text1(body)
        .duration(Duration::Long)
        .show()
        .map_err(|e| e.to_string())
}

/// Open the report. Uses the "open" verb on a concrete file path, never a URL
/// and never a string built from event data, so there is nothing to inject.
pub fn open(report: &Path) -> Result<(), String> {
    let verb = HSTRING::from("open");
    let file = HSTRING::from(report);
    // SAFETY: the HSTRINGs are valid null-terminated wide strings that outlive the call.
    let h = unsafe { ShellExecuteW(None, &verb, &file, PCWSTR::null(), PCWSTR::null(), SW_SHOWNORMAL) };
    // Documented contract: a value > 32 is success; anything else is an error code.
    if h.0 as usize > 32 {
        Ok(())
    } else {
        Err(format!("ShellExecuteW returned {}", h.0 as usize))
    }
}

//! Which of the high-risk programs are running right now. One OS facility
//! (a Toolhelp process snapshot) and the fifth and last module allowed
//! `unsafe`; see eventlog.rs, keys.rs, harden.rs, notify.rs.
//!
//! Needed because a process's exploit protections can only be read from the
//! live process (`harden::protection_of`): Windows keeps the per-program
//! settings in an undocumented registry blob, and guessing at that would be
//! worse than saying "start the app and check again".
//!
//! Signatures checked by hand against `windows` 0.61.3
//! (`Win32::System::Diagnostics::ToolHelp`).

use windows::Win32::{
    Foundation::CloseHandle,
    System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS,
    },
};

/// Every running process whose lower-cased executable name is in `names`,
/// as `(name, pid)`, in snapshot order. Processes we cannot see are simply
/// absent; nothing here needs admin.
pub fn running(names: &[String]) -> Result<Vec<(String, u32)>, String> {
    // SAFETY: a snapshot of the process list; the handle is closed below, once.
    let snap = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) }.map_err(|e| format!("process list: {e}"))?;
    let mut entry = PROCESSENTRY32W {
        dwSize: u32::try_from(std::mem::size_of::<PROCESSENTRY32W>()).unwrap_or(0),
        ..Default::default()
    };
    let mut found = Vec::new();
    // SAFETY: `entry.dwSize` is set as the API requires and `entry` outlives
    // both calls; each call fills the struct or fails.
    let mut ok = unsafe { Process32FirstW(snap, &raw mut entry) }.is_ok();
    while ok {
        let len = entry.szExeFile.iter().position(|&c| c == 0).unwrap_or(entry.szExeFile.len());
        let name = String::from_utf16_lossy(&entry.szExeFile[..len]).to_ascii_lowercase();
        if names.contains(&name) {
            found.push((name, entry.th32ProcessID));
        }
        // SAFETY: as above.
        ok = unsafe { Process32NextW(snap, &raw mut entry) }.is_ok();
    }
    // SAFETY: closing the snapshot handle we opened, exactly once.
    let _ = unsafe { CloseHandle(snap) };
    Ok(found)
}

#[cfg(test)]
mod tests {
    use super::running;

    #[test]
    fn finds_this_very_process() {
        let me =
            std::env::current_exe().ok().and_then(|p| p.file_name().map(|n| n.to_string_lossy().to_ascii_lowercase()));
        let me = me.unwrap_or_default();
        let hits = running(std::slice::from_ref(&me)).unwrap_or_default();
        assert!(
            hits.iter().any(|(n, pid)| *n == me && *pid == std::process::id()),
            "own process {me} missing from {hits:?}"
        );
        assert!(running(&["no-such-program-ever.exe".into()]).unwrap_or_default().is_empty());
    }
}

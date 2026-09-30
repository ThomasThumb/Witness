//! Where Witness keeps its files. One place, under the user's own profile.
//!
//! People see it as `%LOCALAPPDATA%\Witness`, never expanded: the expanded
//! form contains the Windows user name, and `check` output, errors and
//! reports get pasted into emails and bug reports. Explorer's address bar
//! expands the short form, so it still gets a helper to the right folder.
use std::path::{Path, PathBuf};

/// The base folder as it is shown to people.
pub const SHOWN_BASE: &str = r"%LOCALAPPDATA%\Witness";

/// `%LOCALAPPDATA%\Witness`, created if missing.
pub fn base() -> Result<PathBuf, String> {
    let local = std::env::var_os("LOCALAPPDATA").ok_or("LOCALAPPDATA is not set")?;
    let p = PathBuf::from(local).join("Witness");
    std::fs::create_dir_all(&p).map_err(|e| format!("create {SHOWN_BASE}: {e}"))?;
    Ok(p)
}

/// The watcher's heartbeat: `alive` under the base folder, touched by `run`
/// every ten minutes and after every event. There is no tray icon, on
/// purpose, so this is the only way `check` can say whether Witness is
/// actually running; silence must never be mistaken for safety.
const ALIVE: &str = "alive";

/// How often `run` touches the heartbeat when nothing happens.
pub const HEARTBEAT: std::time::Duration = std::time::Duration::from_secs(600);

/// Touch the heartbeat. Failure is not worth stopping the watcher for.
pub fn touch_alive() {
    if let Ok(base) = base() {
        let _ = std::fs::write(base.join(ALIVE), b"");
    }
}

/// Seconds since the heartbeat was last touched; `None` if it never was.
pub fn alive_age_secs() -> Option<u64> {
    let modified = std::fs::metadata(base().ok()?.join(ALIVE)).ok()?.modified().ok()?;
    Some(modified.elapsed().map_or(0, |d| d.as_secs()))
}

/// `p` as a person should see it: `%LOCALAPPDATA%\Witness\…` if it is under
/// the base folder, otherwise only its last component.
pub fn shown(p: &Path) -> String {
    let rel = std::env::var_os("LOCALAPPDATA")
        .and_then(|l| p.strip_prefix(PathBuf::from(l).join("Witness")).ok().map(Path::to_path_buf));
    match rel {
        Some(r) if r.as_os_str().is_empty() => SHOWN_BASE.to_string(),
        Some(r) => format!(r"{SHOWN_BASE}\{}", r.display()),
        None => p.file_name().map_or_else(String::new, |n| n.to_string_lossy().into_owned()),
    }
}

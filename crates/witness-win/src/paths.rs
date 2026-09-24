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

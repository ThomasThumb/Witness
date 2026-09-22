//! Where Witness keeps its files. One place, under the user's own profile.
use std::path::PathBuf;

/// `%LOCALAPPDATA%\Witness`, created if missing.
pub fn base() -> Result<PathBuf, String> {
    let local = std::env::var_os("LOCALAPPDATA").ok_or("LOCALAPPDATA is not set")?;
    let p = PathBuf::from(local).join("Witness");
    std::fs::create_dir_all(&p).map_err(|e| format!("create {}: {e}", p.display()))?;
    Ok(p)
}

//! The commands that do not watch: `verify`, `export`, `fingerprint`,
//! `install`. Safe glue; `main.rs` keeps the watcher and its state.

use crate::{keys, paths};
use std::path::{Path, PathBuf};
use witness_core::{evidence, signing::Identity, zip};

/// Everything printed here came from the bundle, or from a folder name someone
/// else chose, so it goes through `visible`: nothing in it may carry a line
/// break or an escape sequence that could forge or hide the key line a helper
/// is about to compare. The manifest fields have already passed their grammar
/// checks; `visible` is the second line of defence.
pub fn verify(dir: &Path, expected: Option<&str>) -> Result<(), String> {
    let m = evidence::verify_bundle(dir, expected)?;
    println!(
        "OK: bundle {} rule={} severity={} witness={} created={}",
        evidence::visible(&paths::shown(dir)),
        evidence::visible(&m.rule_id),
        evidence::visible(&m.severity),
        evidence::visible(&m.witness_version),
        evidence::visible(&m.created)
    );
    println!("key: {}", evidence::visible(&m.key_fingerprint));
    if expected.is_some() {
        println!("The key matches the fingerprint you gave: this bundle was made by that install.");
    } else {
        println!("The key must match the fingerprint written down when Witness was installed; if it differs, another install made this bundle.");
        println!("To have Witness check instead:  witness verify <bundle-dir> <fingerprint>");
    }
    let extra = evidence::unsigned_entries(dir).map_err(|e| e.to_string())?;
    if !extra.is_empty() {
        let names: Vec<String> = extra.iter().map(|n| evidence::visible(n)).collect();
        println!("NOT covered by the signature, do not trust: {}", names.join(", "));
    }
    Ok(())
}

/// One file to send: the bundle's six files as a ZIP on the Desktop (or the
/// current folder if there is no Desktop). Verified first, so a person is
/// never handed a broken bundle to forward without knowing.
pub fn export(dir: &Path) -> Result<(), String> {
    let verdict = evidence::verify_bundle(dir, None).map_or("NOT verified; send it anyway and say so", |_| "verified");
    let name = dir.file_name().map_or_else(|| "bundle".to_string(), |n| n.to_string_lossy().into_owned());
    let (folder, shown_folder) = desktop_or_here();
    let out = folder.join(format!("witness-{name}.zip"));
    zip::write_bundle_zip(dir, &out).map_err(|e| format!("could not write the zip: {e}"))?;
    println!("Written: {}\\witness-{}.zip ({verdict})", shown_folder, evidence::visible(&name));
    println!("Send that one file to the helpline. Keep the original folder; do not edit either.");
    Ok(())
}

/// `%USERPROFILE%\Desktop` if it exists, else the current directory; with
/// how to show it (never the expanded user profile path).
fn desktop_or_here() -> (PathBuf, String) {
    if let Some(profile) = std::env::var_os("USERPROFILE") {
        let desktop = PathBuf::from(profile).join("Desktop");
        if desktop.is_dir() {
            return (desktop, r"%USERPROFILE%\Desktop".into());
        }
    }
    (PathBuf::from("."), "the current folder".into())
}

pub fn fingerprint() -> Result<(), String> {
    let seed = keys::load_or_create_seed()?;
    let id = Identity::from_seed(&seed).map_err(|e| e.to_string())?;
    println!("{}", id.fingerprint());
    println!("Write this down on paper. If a report ever shows a different fingerprint, the evidence was not made by this install.");
    Ok(())
}

pub fn install() -> Result<(), String> {
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    println!("Witness does not install itself. To start it at logon, run in PowerShell:");
    println!();
    println!("  schtasks /Create /TN Witness /SC ONLOGON /RL LIMITED /TR \"\\\"{}\\\" run\"", exe.display());
    println!();
    println!("To remove:  schtasks /Delete /TN Witness /F");
    println!("Then run:   witness fingerprint   and write the result down.");
    println!("Optional:   witness selftest     to see what a real alert looks like.");
    Ok(())
}

//! Evidence bundles: a directory a frightened person can zip and hand to a helpline.
//!
//! Layout:
//! ```text
//! <root>/<YYYYMMDD-HHMMSS>-<rule-id>/
//!   event.json      normalized event
//!   event.raw.xml   exactly what the OS said
//!   report.html     the triage page, self-contained, no scripts, no network
//!   manifest.json   what is in here, BLAKE3 of each file, tool version
//!   manifest.sig    ML-DSA-87 signature over manifest.json
//!   pubkey.bin      the public key that verifies manifest.sig
//! ```
//! `manifest.json` is written last and signed last, so a half-written bundle
//! (power loss, crash) is detectable: no manifest means "incomplete".

use crate::{event::Event, rules::Rule, signing::Identity};
use serde::{Deserialize, Serialize};
use std::{
    fs, io,
    path::{Path, PathBuf},
};

/// One file entry in a manifest.
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct FileEntry {
    /// File name within the bundle directory.
    pub name: String,
    /// BLAKE3 hash, hex.
    pub blake3: String,
    /// Size in bytes.
    pub bytes: u64,
}

/// The manifest.
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Manifest {
    /// Tool version that wrote the bundle.
    pub witness_version: String,
    /// Signature scheme over this manifest (`ML-DSA-87`). A verifier checks it
    /// before decoding, so a bundle from a future scheme fails clearly, not cryptically.
    pub algorithm: String,
    /// Rule that fired.
    pub rule_id: String,
    /// Severity as a string.
    pub severity: String,
    /// When the bundle was created (event time; the OS clock is the only clock we trust).
    pub created: String,
    /// Fingerprint of the signing key, for cross-checking against what the user wrote down.
    pub key_fingerprint: String,
    /// Files and their hashes.
    pub files: Vec<FileEntry>,
}

/// The directory a bundle for this event/rule will be written to. Deterministic
/// for a given root, so the caller can put the real path in the report before
/// writing it. If that directory already exists (several identical events in
/// the same second happen: Chromium's GPU process trips CIG four times at
/// once), a `-2`, `-3`… suffix keeps every event's evidence instead of
/// overwriting the first.
#[must_use]
pub fn bundle_dir(root: &Path, ev: &Event, rule: &Rule) -> PathBuf {
    let base = format!("{}-{}", sanitize(&ev.time), rule.id);
    let first = root.join(&base);
    if !first.exists() {
        return first;
    }
    // Bounded: after 10 000 same-second events something else is very wrong,
    // and overwriting the last one is preferable to an unbounded loop.
    (2..10_000u32).map(|n| root.join(format!("{base}-{n}"))).find(|p| !p.exists()).unwrap_or(first)
}

/// Write a bundle into `dir` (from [`bundle_dir`]).
///
/// # Errors
/// Any filesystem or serialisation failure. The watcher logs it and keeps running.
pub fn write_bundle(dir: &Path, ev: &Event, rule: &Rule, report_html: &str, id: &Identity) -> io::Result<()> {
    fs::create_dir_all(dir)?;

    let event_json = serde_json::to_vec_pretty(ev).map_err(io::Error::other)?;
    let files: [(&str, &[u8]); 3] =
        [("event.json", &event_json), ("event.raw.xml", ev.raw.as_bytes()), ("report.html", report_html.as_bytes())];
    let mut entries = Vec::with_capacity(files.len());
    for (name, bytes) in files {
        fs::write(dir.join(name), bytes)?;
        entries.push(FileEntry {
            name: name.to_string(),
            blake3: blake3::hash(bytes).to_hex().to_string(),
            bytes: bytes.len() as u64,
        });
    }

    let manifest = Manifest {
        witness_version: crate::VERSION.to_string(),
        algorithm: crate::signing::ALGORITHM.to_string(),
        rule_id: rule.id.clone(),
        severity: rule.severity.to_string(),
        created: ev.time.clone(),
        key_fingerprint: id.fingerprint(),
        files: entries,
    };
    let manifest_bytes = serde_json::to_vec_pretty(&manifest).map_err(io::Error::other)?;
    fs::write(dir.join("pubkey.bin"), id.public_key())?;
    fs::write(dir.join("manifest.sig"), id.sign(&manifest_bytes))?;
    fs::write(dir.join("manifest.json"), &manifest_bytes)?;
    Ok(())
}

/// Verify a bundle directory: signature over manifest, and every hash. Used by
/// `witness verify <dir>` and by anyone auditing a bundle they were handed.
///
/// # Errors
/// A human-readable reason: missing file, bad signature, fingerprint mismatch, or a modified file.
pub fn verify_bundle(dir: &Path) -> Result<Manifest, String> {
    let manifest_bytes = fs::read(dir.join("manifest.json")).map_err(|e| format!("manifest.json: {e}"))?;
    let sig = fs::read(dir.join("manifest.sig")).map_err(|e| format!("manifest.sig: {e}"))?;
    let pk = fs::read(dir.join("pubkey.bin")).map_err(|e| format!("pubkey.bin: {e}"))?;
    let manifest: Manifest = serde_json::from_slice(&manifest_bytes).map_err(|e| format!("manifest: {e}"))?;
    if manifest.algorithm != crate::signing::ALGORITHM {
        return Err(format!(
            "manifest signed with {:?}; this build verifies {}",
            manifest.algorithm,
            crate::signing::ALGORITHM
        ));
    }
    crate::signing::verify(&pk, &manifest_bytes, &sig).map_err(|e| format!("signature: {e}"))?;
    if manifest.key_fingerprint != crate::signing::fingerprint_of(&pk) {
        return Err("manifest fingerprint does not match pubkey.bin".into());
    }
    for f in &manifest.files {
        let bytes = fs::read(dir.join(&f.name)).map_err(|e| format!("{}: {e}", f.name))?;
        if blake3::hash(&bytes).to_hex().as_str() != f.blake3 || bytes.len() as u64 != f.bytes {
            return Err(format!("{} has been modified", f.name));
        }
    }
    Ok(manifest)
}

/// Make a timestamp safe for a directory name: keep digits, drop everything else.
fn sanitize(time: &str) -> String {
    let digits: String = time.chars().filter(char::is_ascii_digit).collect();
    // 2026-09-22T04:00:00Z -> 20260922040000 -> 20260922-040000
    if digits.len() >= 14 {
        format!("{}-{}", &digits[..8], &digits[8..14])
    } else {
        digits
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::{Match, Severity, Triage};
    use std::collections::BTreeMap;

    fn fixture() -> (Event, Rule) {
        let ev = Event {
            time: "2026-09-22T04:00:00Z".into(),
            channel: "Application".into(),
            provider: "Application Error".into(),
            event_id: 1000,
            record_id: 0,
            process: Some("signal.exe".into()),
            exception_code: Some(0xC000_0409),
            data: BTreeMap::new(),
            raw: "<Event/>".into(),
        };
        let rule = Rule {
            id: "test-rule".into(),
            title: "t".into(),
            severity: Severity::Look,
            matcher: Match { channel: "Application".into(), event_id: 1000, ..Default::default() },
            triage: Triage { what_happened: "a".into(), what_it_might_mean: "b".into(), what_to_do: vec!["c".into()] },
        };
        (ev, rule)
    }

    #[test]
    fn bundle_roundtrips_and_detects_tampering() -> Result<(), String> {
        let tmp = tempfile::tempdir().map_err(|e| e.to_string())?;
        let id = Identity::from_seed(&[3u8; 32]).map_err(|e| e.to_string())?;
        let (ev, rule) = fixture();
        let dir = bundle_dir(tmp.path(), &ev, &rule);
        write_bundle(&dir, &ev, &rule, "<html></html>", &id).map_err(|e| e.to_string())?;
        assert!(dir.ends_with("20260922-040000-test-rule"));
        let second = bundle_dir(tmp.path(), &ev, &rule);
        assert!(second.ends_with("20260922-040000-test-rule-2"), "same second, same rule: never overwrite evidence");
        let m = verify_bundle(&dir)?;
        assert_eq!(m.rule_id, "test-rule");
        assert_eq!(m.algorithm, "ML-DSA-87");
        assert_eq!(m.files.len(), 3);
        assert_eq!(fs::read(dir.join("manifest.sig")).map_err(|e| e.to_string())?.len(), 4627);
        assert_eq!(fs::read(dir.join("pubkey.bin")).map_err(|e| e.to_string())?.len(), 2592);

        fs::write(dir.join("report.html"), "<html>edited</html>").map_err(|e| e.to_string())?;
        assert!(verify_bundle(&dir).is_err(), "edited file must fail verification");
        Ok(())
    }

    #[test]
    fn sanitize_handles_odd_timestamps() {
        assert_eq!(sanitize("2026-09-22T04:00:00.123Z"), "20260922-040000");
        assert_eq!(sanitize("garbage"), "");
    }
}

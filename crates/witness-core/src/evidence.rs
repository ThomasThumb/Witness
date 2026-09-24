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
//!
//! Verification treats the whole directory as untrusted: it arrives from
//! whoever hands it over, it brings its own public key, and a crafted one
//! signs cleanly under that key. So nothing in it may steer a file open, an
//! allocation or the terminal before the helper has compared the fingerprint.

use crate::{event::Event, rules::Rule, signing::Identity};
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read},
    path::{Path, PathBuf},
};

/// The files a manifest lists: exactly these, each once. `verify_bundle`
/// rejects any other name before opening a single file, because the manifest
/// comes from whoever handed the bundle over, and a crafted `..\x` or
/// `\\host\share\x` would otherwise make `witness verify` read outside the
/// bundle, or reach across the network from a helper's machine.
pub const BUNDLE_FILES: [&str; 3] = ["event.json", "event.raw.xml", "report.html"];

/// Written beside the listed files; the signature itself covers them.
const SIGNATURE_FILES: [&str; 3] = ["manifest.json", "manifest.sig", "pubkey.bin"];

/// A real manifest, signature or public key is a few KB. Refuse to read more.
const MAX_META_BYTES: u64 = 1024 * 1024;

/// The largest payload a bundle may declare or hold. `event.raw.xml` is capped
/// at 8 MiB by the parser; `event.json` and `report.html` are derived from it
/// with escaping, so a real one is far below this. Payloads are hashed as a
/// stream, so this bounds time, not memory.
pub const MAX_PAYLOAD_BYTES: u64 = 64 * 1024 * 1024;

/// Open the file itself, never a target it points at (Windows).
#[cfg(windows)]
const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;

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
    // Bounded: after 10 000 same-second events something else is very wrong.
    // Returning an existing directory is safe: `write_bundle` refuses it, so
    // the event is logged as lost rather than written over another's evidence.
    (2..10_000u32).map(|n| root.join(format!("{base}-{n}"))).find(|p| !p.exists()).unwrap_or(first)
}

/// Write a bundle into `dir` (from [`bundle_dir`]). The directory must not
/// exist yet: evidence is never overwritten, whatever the caller passes.
///
/// # Errors
/// Any filesystem or serialisation failure. The watcher logs it and keeps running.
pub fn write_bundle(dir: &Path, ev: &Event, rule: &Rule, report_html: &str, id: &Identity) -> io::Result<()> {
    fs::create_dir(dir)?;

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
/// `expected` is the fingerprint the helper was given out of band (the one the
/// user wrote on paper). With it, a bundle from any other key fails here,
/// before a single payload is read. Without it, the caller must show the
/// fingerprint and let a person compare.
///
/// Order matters: the manifest's text is checked against fixed grammars and
/// the fixed file list before any name is used, the signature and fingerprint
/// before any payload is opened, and every file is opened without following
/// links and read through a size budget.
///
/// # Errors
/// A human-readable reason: missing file, bad signature, fingerprint mismatch, or a modified file.
pub fn verify_bundle(dir: &Path, expected: Option<&str>) -> Result<Manifest, String> {
    let manifest_bytes = read_meta(dir, "manifest.json")?;
    let sig = read_meta(dir, "manifest.sig")?;
    let pk = read_meta(dir, "pubkey.bin")?;
    let manifest: Manifest = serde_json::from_slice(&manifest_bytes).map_err(|e| format!("manifest: {e}"))?;
    if manifest.algorithm != crate::signing::ALGORITHM {
        return Err(format!(
            "manifest signed with {:?}; this build verifies {}",
            manifest.algorithm,
            crate::signing::ALGORITHM
        ));
    }
    check_grammar(&manifest)?;
    let mut listed: Vec<&str> = manifest.files.iter().map(|f| f.name.as_str()).collect();
    listed.sort_unstable();
    let mut want = BUNDLE_FILES;
    want.sort_unstable();
    if listed != want {
        return Err(format!("manifest lists {listed:?}; a Witness bundle lists exactly {BUNDLE_FILES:?}"));
    }
    for f in &manifest.files {
        if f.blake3.len() != 64 || !f.blake3.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()) {
            return Err(format!("{}: the manifest's hash is not a BLAKE3 hex digest", f.name));
        }
        if f.bytes > MAX_PAYLOAD_BYTES {
            return Err(format!(
                "{}: the manifest declares {} bytes; the limit is {MAX_PAYLOAD_BYTES}",
                f.name, f.bytes
            ));
        }
    }
    crate::signing::verify(&pk, &manifest_bytes, &sig).map_err(|e| format!("signature: {e}"))?;
    let actual = crate::signing::fingerprint_of(&pk);
    if manifest.key_fingerprint != actual {
        return Err("manifest fingerprint does not match pubkey.bin".into());
    }
    if let Some(want) = expected {
        if want != actual {
            return Err(format!(
                "this bundle was signed by key {actual}, not the expected {}; another install made it",
                visible(want)
            ));
        }
    }
    for f in &manifest.files {
        let file = open_regular(dir, &f.name)?;
        let (hash, len) = hash_bounded(file, f.bytes).map_err(|e| format!("{}: {e}", f.name))?;
        if len != f.bytes || hash != f.blake3 {
            return Err(format!("{} has been modified", f.name));
        }
    }
    Ok(manifest)
}

/// Anything in `dir` the signature does not cover, sorted. A helper should not
/// trust, say, a `README.txt` added after Witness wrote the bundle. A warning,
/// not a failure: Windows itself sometimes drops `desktop.ini` into folders.
/// Names are returned raw; print them through [`visible`].
///
/// # Errors
/// The directory cannot be listed.
pub fn unsigned_entries(dir: &Path) -> io::Result<Vec<String>> {
    let mut extra = Vec::new();
    for entry in fs::read_dir(dir)? {
        let name = entry?.file_name().to_string_lossy().into_owned();
        if !BUNDLE_FILES.contains(&name.as_str()) && !SIGNATURE_FILES.contains(&name.as_str()) {
            extra.push(name);
        }
    }
    extra.sort();
    Ok(extra)
}

/// Text from a bundle, or a path someone else chose, made safe for a terminal:
/// printable ASCII stays, everything else becomes `\u{..}`. A crafted folder
/// name or file name could otherwise carry `\r`, `\n` or an escape sequence
/// that moves the cursor, changes colours or hides the fingerprint line a
/// helper is about to compare.
#[must_use]
pub fn visible(s: &str) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if (' '..='~').contains(&c) {
            out.push(c);
        } else {
            let _ = write!(out, "\\u{{{:x}}}", u32::from(c));
        }
    }
    out
}

/// The fixed grammar of every text field a manifest carries, so a crafted one
/// can neither reach the terminal with control characters nor pass off text
/// as a fingerprint. Witness only ever writes values that pass this.
fn check_grammar(m: &Manifest) -> Result<(), String> {
    let field = |name: &str, s: &str, max: usize, ok: fn(char) -> bool| {
        if s.is_empty() || s.len() > max || !s.chars().all(ok) {
            return Err(format!("manifest field {name} is malformed"));
        }
        Ok(())
    };
    field("rule_id", &m.rule_id, 64, |c| c.is_ascii_alphanumeric() || c == '-')?;
    field("witness_version", &m.witness_version, 32, |c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '+'))?;
    field("created", &m.created, 40, |c| c.is_ascii_alphanumeric() || matches!(c, '-' | ':' | '.' | '+'))?;
    if !matches!(m.severity.as_str(), "bug" | "look" | "urgent") {
        return Err("manifest field severity is malformed".into());
    }
    // 8 groups of 4 lower-case hex digits joined by '-', as `fingerprint_of` writes.
    let fp = &m.key_fingerprint;
    let groups: Vec<&str> = fp.split('-').collect();
    if groups.len() != 8
        || groups.iter().any(|g| g.len() != 4 || !g.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')))
    {
        return Err("manifest field key_fingerprint is malformed".into());
    }
    Ok(())
}

/// Read one of the signature files through the metadata size budget.
fn read_meta(dir: &Path, name: &str) -> Result<Vec<u8>, String> {
    let file = open_regular(dir, name)?;
    let mut bytes = Vec::new();
    // One byte past the budget is enough to know it was exceeded.
    file.take(MAX_META_BYTES + 1).read_to_end(&mut bytes).map_err(|e| format!("{name}: {e}"))?;
    if bytes.len() as u64 > MAX_META_BYTES {
        return Err(format!("{name} is over {MAX_META_BYTES} bytes; a real one is a few KB"));
    }
    Ok(bytes)
}

/// Open `dir/name` as the regular file it is, never as a link to something
/// else. A bundle that arrives on prepared media, or is unpacked by a tool
/// that keeps links, could otherwise point `event.json` at a file elsewhere on
/// the helper's disk, or at a network share that would be contacted on open.
/// The judgement is made on the handle actually held, so nothing swapped in
/// between a check and the read can change what is read.
fn open_regular(dir: &Path, name: &str) -> Result<File, String> {
    let path = dir.join(name);
    let mut opts = OpenOptions::new();
    opts.read(true);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        opts.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }
    let file = opts.open(&path).map_err(|e| format!("{name}: {e}"))?;
    let meta = file.metadata().map_err(|e| format!("{name}: {e}"))?;
    if meta.file_type().is_symlink() {
        return Err(format!("{name} is a link, not a file; refusing to follow it"));
    }
    if !meta.is_file() {
        return Err(format!("{name} is not a regular file"));
    }
    #[cfg(unix)]
    {
        // Unix opens follow links. Confirm what was opened is what sits at
        // that name now, and that the name is not a link.
        use std::os::unix::fs::MetadataExt;
        let at_name = fs::symlink_metadata(&path).map_err(|e| format!("{name}: {e}"))?;
        if at_name.file_type().is_symlink() || (at_name.dev(), at_name.ino()) != (meta.dev(), meta.ino()) {
            return Err(format!("{name} is a link, not a file; refusing to follow it"));
        }
    }
    Ok(file)
}

/// BLAKE3 of a file read in fixed chunks, stopping one byte past `expected`.
/// Memory stays at the chunk size whatever the file's length, and a file that
/// grows past its declared size is caught by the count, not by trust.
fn hash_bounded(file: File, expected: u64) -> io::Result<(String, u64)> {
    let mut hasher = blake3::Hasher::new();
    let mut reader = file.take(expected + 1);
    let mut buf = vec![0u8; 64 * 1024];
    let mut total: u64 = 0;
    loop {
        let n = reader.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        total += n as u64;
    }
    Ok((hasher.finalize().to_hex().to_string(), total))
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

    /// A fresh, valid bundle in a temp dir, with the identity that signed it.
    fn written(seed: u8) -> Result<(tempfile::TempDir, PathBuf, Identity), String> {
        let tmp = tempfile::tempdir().map_err(|e| e.to_string())?;
        let id = Identity::from_seed(&[seed; 32]).map_err(|e| e.to_string())?;
        let (ev, rule) = fixture();
        let dir = bundle_dir(tmp.path(), &ev, &rule);
        write_bundle(&dir, &ev, &rule, "<html></html>", &id).map_err(|e| e.to_string())?;
        Ok((tmp, dir, id))
    }

    /// Edit a bundle's manifest and re-sign it, as someone crafting a bundle
    /// with their own key would. The signature stays valid throughout.
    fn resign(dir: &Path, id: &Identity, edit: impl FnOnce(&mut Manifest)) -> Result<(), String> {
        let mut m = verify_bundle(dir, None)?;
        edit(&mut m);
        let bytes = serde_json::to_vec_pretty(&m).map_err(|e| e.to_string())?;
        fs::write(dir.join("manifest.sig"), id.sign(&bytes)).map_err(|e| e.to_string())?;
        fs::write(dir.join("manifest.json"), bytes).map_err(|e| e.to_string())
    }

    #[test]
    fn bundle_roundtrips_and_detects_tampering() -> Result<(), String> {
        let (tmp, dir, _id) = written(3)?;
        let (ev, rule) = fixture();
        assert!(dir.ends_with("20260922-040000-test-rule"));
        let second = bundle_dir(tmp.path(), &ev, &rule);
        assert!(second.ends_with("20260922-040000-test-rule-2"), "same second, same rule: never overwrite evidence");
        let m = verify_bundle(&dir, None)?;
        assert_eq!(m.rule_id, "test-rule");
        assert_eq!(m.algorithm, "ML-DSA-87");
        assert_eq!(m.files.len(), 3);
        assert_eq!(fs::read(dir.join("manifest.sig")).map_err(|e| e.to_string())?.len(), 4627);
        assert_eq!(fs::read(dir.join("pubkey.bin")).map_err(|e| e.to_string())?.len(), 2592);
        verify_bundle(&dir, Some(&m.key_fingerprint))?;

        fs::write(dir.join("report.html"), "<html>edited</html>").map_err(|e| e.to_string())?;
        assert!(verify_bundle(&dir, None).is_err(), "edited file must fail verification");
        Ok(())
    }

    #[test]
    fn evidence_is_never_overwritten() -> Result<(), String> {
        let (_tmp, dir, id) = written(7)?;
        let (ev, rule) = fixture();
        let err = write_bundle(&dir, &ev, &rule, "<html>second</html>", &id)
            .err()
            .ok_or("writing into an existing bundle directory succeeded")?;
        assert_eq!(err.kind(), io::ErrorKind::AlreadyExists);
        verify_bundle(&dir, None)?; // the first bundle is untouched
        Ok(())
    }

    #[test]
    fn manifest_naming_anything_else_is_refused_before_any_file_is_read() -> Result<(), String> {
        let tmp = tempfile::tempdir().map_err(|e| e.to_string())?;
        let id = Identity::from_seed(&[4u8; 32]).map_err(|e| e.to_string())?;
        let (ev, rule) = fixture();
        // `.invalid` never resolves (RFC 6761), so even a regression cannot reach a network.
        let crafted: &[&[&str]] = &[
            &[r"..\secret", "event.raw.xml", "report.html"],
            &["../secret", "event.raw.xml", "report.html"],
            &[r"C:\Windows\win.ini", "event.raw.xml", "report.html"],
            &[r"\\witness.invalid\share\x", "event.raw.xml", "report.html"],
            &["event.json:x", "event.raw.xml", "report.html"],
            &["CON", "event.raw.xml", "report.html"],
            &["event.json", "event.json", "report.html"],
            &["event.json", "event.raw.xml"],
        ];
        for names in crafted {
            let dir = bundle_dir(tmp.path(), &ev, &rule);
            write_bundle(&dir, &ev, &rule, "<html></html>", &id).map_err(|e| e.to_string())?;
            resign(&dir, &id, |m| {
                m.files =
                    names.iter().map(|n| FileEntry { name: (*n).into(), blake3: String::new(), bytes: 0 }).collect();
            })?;
            let err = verify_bundle(&dir, None).err().ok_or(format!("{names:?} verified"))?;
            assert!(err.starts_with("manifest lists"), "{names:?} refused too late: {err}");
        }
        Ok(())
    }

    /// A description and the edit that makes a manifest field malformed.
    type Craft = (&'static str, fn(&mut Manifest));

    #[test]
    fn manifest_text_with_control_characters_is_refused_before_it_is_printed() -> Result<(), String> {
        let crafts: &[Craft] = &[
            ("version with an escape sequence", |m| m.witness_version = "0.1.0\u{1b}[30;40m".into()),
            ("rule id with a newline", |m| m.rule_id = "ok\nkey: aaaa-bbbb".into()),
            ("severity that is not one of ours", |m| m.severity = "URGENT!".into()),
            ("created with a carriage return", |m| m.created = "2026\r".into()),
            ("fingerprint that is prose", |m| m.key_fingerprint = "matches, trust it".into()),
        ];
        for (what, craft) in crafts {
            let (_tmp, dir, id) = written(8)?;
            resign(&dir, &id, craft)?;
            let err = verify_bundle(&dir, None).err().ok_or(format!("{what}: verified"))?;
            assert!(err.contains("malformed"), "{what}: wrong error: {err}");
            assert!(!err.contains('\u{1b}') && !err.contains('\n'), "{what}: the error echoed the crafted text");
        }
        Ok(())
    }

    #[test]
    fn expected_fingerprint_mismatch_fails_before_payloads() -> Result<(), String> {
        let (_tmp, dir, _id) = written(9)?;
        // Make the payload unreadable as a directory; a mismatch must fail first.
        fs::remove_file(dir.join("event.json")).map_err(|e| e.to_string())?;
        fs::create_dir(dir.join("event.json")).map_err(|e| e.to_string())?;
        let err = verify_bundle(&dir, Some("0000-0000-0000-0000-0000-0000-0000-0000"))
            .err()
            .ok_or("wrong expected fingerprint verified")?;
        assert!(err.contains("not the expected"), "{err}");
        Ok(())
    }

    #[test]
    fn declared_payload_size_above_the_limit_is_refused_before_reading() -> Result<(), String> {
        let (_tmp, dir, id) = written(10)?;
        resign(&dir, &id, |m| m.files[0].bytes = MAX_PAYLOAD_BYTES + 1)?;
        let err = verify_bundle(&dir, None).err().ok_or("oversized declaration verified")?;
        assert!(err.contains("the limit is"), "{err}");
        Ok(())
    }

    #[test]
    fn a_payload_that_is_not_a_regular_file_is_refused() -> Result<(), String> {
        let (_tmp, dir, _id) = written(11)?;
        fs::remove_file(dir.join("event.json")).map_err(|e| e.to_string())?;
        fs::create_dir(dir.join("event.json")).map_err(|e| e.to_string())?;
        assert!(verify_bundle(&dir, None).is_err(), "a directory in place of a payload verified");
        Ok(())
    }

    #[test]
    fn links_are_not_followed() -> Result<(), String> {
        let (tmp, dir, _id) = written(12)?;
        let outside = tmp.path().join("outside.json");
        fs::copy(dir.join("event.json"), &outside).map_err(|e| e.to_string())?;
        fs::remove_file(dir.join("event.json")).map_err(|e| e.to_string())?;
        #[cfg(windows)]
        let made = std::os::windows::fs::symlink_file(&outside, dir.join("event.json"));
        #[cfg(unix)]
        let made = std::os::unix::fs::symlink(&outside, dir.join("event.json"));
        if let Err(e) = made {
            // Windows needs Developer Mode or a privilege to create symlinks.
            eprintln!("skipped: cannot create a symlink here ({e})");
            return Ok(());
        }
        // The link points at an identical, correctly hashed copy: only the
        // link itself can be the reason for rejection.
        let err = verify_bundle(&dir, None).err().ok_or("a bundle reached through a link verified")?;
        assert!(err.contains("link"), "{err}");
        Ok(())
    }

    #[test]
    fn files_the_signature_does_not_cover_are_reported_not_fatal() -> Result<(), String> {
        let (_tmp, dir, _id) = written(5)?;
        assert!(unsigned_entries(&dir).map_err(|e| e.to_string())?.is_empty());
        fs::write(dir.join("README.txt"), "call this number instead").map_err(|e| e.to_string())?;
        fs::write(dir.join("desktop.ini"), "").map_err(|e| e.to_string())?;
        verify_bundle(&dir, None)?;
        assert_eq!(unsigned_entries(&dir).map_err(|e| e.to_string())?, ["README.txt", "desktop.ini"]);
        Ok(())
    }

    #[test]
    fn oversized_manifest_is_not_read() -> Result<(), String> {
        let (_tmp, dir, _id) = written(6)?;
        fs::write(dir.join("manifest.json"), vec![b' '; 2 * 1024 * 1024]).map_err(|e| e.to_string())?;
        let err = verify_bundle(&dir, None).err().ok_or("2 MiB manifest verified")?;
        assert!(err.contains("a real one is a few KB"), "{err}");
        Ok(())
    }

    #[test]
    fn visible_keeps_only_printable_ascii() {
        assert_eq!(visible("20260922-040000-fastfail-any"), "20260922-040000-fastfail-any");
        assert_eq!(visible("ok\u{1b}[2K\r\nkey: x"), "ok\\u{1b}[2K\\u{d}\\u{a}key: x");
        assert_eq!(visible("r\u{e9}sum\u{e9}.txt"), "r\\u{e9}sum\\u{e9}.txt");
    }

    #[test]
    fn sanitize_handles_odd_timestamps() {
        assert_eq!(sanitize("2026-09-22T04:00:00.123Z"), "20260922-040000");
        assert_eq!(sanitize("garbage"), "");
    }
}

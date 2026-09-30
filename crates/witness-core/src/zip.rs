//! A bundle as one file: `witness export`. Every report says "zip the folder
//! and send it", and many people cannot. This writes a plain ZIP with no
//! compression (a bundle is a few KB; the only thing compression would add
//! is a dependency and its attack surface), only the six bundle files, and
//! fixed timestamps, so the same bundle always gives the same ZIP.

use crate::evidence::{BUNDLE_FILES, SIGNATURE_FILES};
use std::{fs, io, io::Write, path::Path};

/// The largest file this will pack; bundle files are far smaller.
const MAX_FILE_BYTES: u64 = 64 * 1024 * 1024;

/// Write `dir`'s bundle files into the ZIP at `out`. Anything else in `dir`
/// is left out on purpose: the signature does not cover it.
///
/// # Errors
/// A bundle file is missing or too large, or `out` cannot be written.
pub fn write_bundle_zip(dir: &Path, out: &Path) -> io::Result<()> {
    let mut body = Vec::new();
    let mut central = Vec::new();
    for name in BUNDLE_FILES.iter().chain(SIGNATURE_FILES.iter()) {
        let path = dir.join(name);
        if fs::metadata(&path)?.len() > MAX_FILE_BYTES {
            return Err(io::Error::other(format!("{name} is too large to pack")));
        }
        let data = fs::read(&path)?;
        let crc = crc32(&data);
        let size = u32::try_from(data.len()).map_err(io::Error::other)?;
        let offset = u32::try_from(body.len()).map_err(io::Error::other)?;
        // Local file header, then the bytes. Method 0 = stored; time and date
        // 0 = 1980-01-01, deliberately fixed.
        body.extend_from_slice(&0x0403_4b50u32.to_le_bytes());
        body.extend_from_slice(&[20, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        body.extend_from_slice(&crc.to_le_bytes());
        body.extend_from_slice(&size.to_le_bytes());
        body.extend_from_slice(&size.to_le_bytes());
        body.extend_from_slice(&u16::try_from(name.len()).map_err(io::Error::other)?.to_le_bytes());
        body.extend_from_slice(&[0, 0]);
        body.extend_from_slice(name.as_bytes());
        body.extend_from_slice(&data);
        // Central directory entry for the same file.
        central.extend_from_slice(&0x0201_4b50u32.to_le_bytes());
        central.extend_from_slice(&[20, 0, 20, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        central.extend_from_slice(&crc.to_le_bytes());
        central.extend_from_slice(&size.to_le_bytes());
        central.extend_from_slice(&size.to_le_bytes());
        central.extend_from_slice(&u16::try_from(name.len()).map_err(io::Error::other)?.to_le_bytes());
        central.extend_from_slice(&[0; 12]);
        central.extend_from_slice(&offset.to_le_bytes());
        central.extend_from_slice(name.as_bytes());
    }
    let entries = u16::try_from(BUNDLE_FILES.len() + SIGNATURE_FILES.len()).map_err(io::Error::other)?;
    let mut f = fs::File::create(out)?;
    f.write_all(&body)?;
    f.write_all(&central)?;
    f.write_all(&0x0605_4b50u32.to_le_bytes())?;
    f.write_all(&[0, 0, 0, 0])?;
    f.write_all(&entries.to_le_bytes())?;
    f.write_all(&entries.to_le_bytes())?;
    f.write_all(&u32::try_from(central.len()).map_err(io::Error::other)?.to_le_bytes())?;
    f.write_all(&u32::try_from(body.len()).map_err(io::Error::other)?.to_le_bytes())?;
    f.write_all(&[0, 0])?;
    f.flush()
}

/// CRC-32 (IEEE), as ZIP requires. Bytewise; a bundle is a few KB.
fn crc32(data: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for &b in data {
        crc ^= u32::from(b);
        for _ in 0..8 {
            crc = if crc & 1 != 0 { (crc >> 1) ^ 0xEDB8_8320 } else { crc >> 1 };
        }
    }
    !crc
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crc32_matches_the_standard_check_value() {
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
        assert_eq!(crc32(b""), 0);
    }

    #[test]
    fn zip_holds_exactly_the_six_bundle_files_and_is_deterministic() -> Result<(), String> {
        use crate::{
            event::Event,
            evidence,
            rules::{Match, Rule, Severity, Triage},
            signing::Identity,
        };
        let tmp = tempfile::tempdir().map_err(|e| e.to_string())?;
        let ev = Event {
            time: "2026-09-22T04:00:00Z".into(),
            channel: "Application".into(),
            provider: "Application Error".into(),
            event_id: 1000,
            record_id: 0,
            process: Some("signal.exe".into()),
            exception_code: Some(0xC000_0409),
            data: std::collections::BTreeMap::new(),
            raw: "<Event/>".into(),
        };
        let rule = Rule {
            id: "test-rule".into(),
            title: "t".into(),
            severity: Severity::Look,
            matcher: Match { channel: "Application".into(), event_id: 1000, ..Default::default() },
            triage: Triage { what_happened: "a".into(), what_it_might_mean: "b".into(), what_to_do: vec!["c".into()] },
        };
        let id = Identity::from_seed(&[13u8; 32]).map_err(|e| e.to_string())?;
        let dir = evidence::bundle_dir(tmp.path(), &ev, &rule);
        evidence::write_bundle(&dir, &ev, &rule, "<html></html>", &id).map_err(|e| e.to_string())?;
        fs::write(dir.join("README.txt"), "not covered by the signature").map_err(|e| e.to_string())?;

        let out = tmp.path().join("a.zip");
        write_bundle_zip(&dir, &out).map_err(|e| e.to_string())?;
        let bytes = fs::read(&out).map_err(|e| e.to_string())?;
        let text = String::from_utf8_lossy(&bytes);
        for name in BUNDLE_FILES.iter().chain(SIGNATURE_FILES.iter()) {
            // At least a local header and a central directory entry each; the
            // manifest's own text lists the three bundle names as well.
            assert!(text.matches(name).count() >= 2, "{name}: missing a header or directory entry");
        }
        assert!(!text.contains("README.txt"), "files the signature does not cover are not packed");
        assert_eq!(&bytes[..4], &0x0403_4b50u32.to_le_bytes(), "starts with a local file header");
        assert_eq!(
            &bytes[bytes.len() - 22..bytes.len() - 18],
            &0x0605_4b50u32.to_le_bytes(),
            "ends with the end-of-central-directory record"
        );

        let again = tmp.path().join("b.zip");
        write_bundle_zip(&dir, &again).map_err(|e| e.to_string())?;
        assert_eq!(bytes, fs::read(&again).map_err(|e| e.to_string())?, "same bundle, same ZIP");
        Ok(())
    }
}

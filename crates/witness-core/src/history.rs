//! What the evidence folder remembers. Witness keeps no state file: the
//! bundles already on disk answer "has this happened before?", so there is
//! nothing extra to corrupt, tamper with or explain.

use crate::{event::Event, rules::Rule};
use std::{
    fs,
    path::{Path, PathBuf},
};

/// Where a `bug`-severity event's evidence goes: `<root>/quiet/<rule>-<pair>`,
/// where `pair` is a short hash of the process and the refused image. The
/// same pair always maps to the same directory, so the first occurrence is
/// captured and every repeat is skipped by an `exists()` check: Brave refusing
/// its own `vulkan-1.dll` four times per start yields one bundle, ever, while
/// a library never seen before in that program's folder gets its own.
#[must_use]
pub fn quiet_dir(root: &Path, ev: &Event, rule: &Rule) -> PathBuf {
    let image = ["ImageName", "ImagePath"].iter().find_map(|k| ev.data.get(*k)).map_or("", String::as_str);
    let pair = format!("{}|{}", ev.process.as_deref().unwrap_or("").to_ascii_lowercase(), image.to_ascii_lowercase());
    let short = &blake3::hash(pair.as_bytes()).to_hex()[..16];
    root.join("quiet").join(format!("{}-{short}", rule.id))
}

/// How many bundles under `root` the same rule has already written for the
/// same program within `days` of `now` (an RFC 3339 time, the current event's).
/// Read from the folder names (their date) and each candidate's `event.json`
/// (its process). `quiet/` and `selftest/` are not under `root` in the
/// watcher's layout, so neither counts. Anything unreadable does not count.
#[must_use]
pub fn repeats(root: &Path, rule_id: &str, process_basename: &str, now: &str, days: u64) -> usize {
    let Some(today) = day_number(now) else { return 0 };
    let Ok(entries) = fs::read_dir(root) else { return 0 };
    let suffix = format!("-{rule_id}");
    entries
        .flatten()
        .filter(|e| {
            let name = e.file_name().to_string_lossy().into_owned();
            // `YYYYMMDD-HHMMSS-<rule>` or the same with a `-N` collision suffix.
            let stem =
                name.rsplit_once('-').filter(|(_, n)| n.parse::<u32>().is_ok()).map_or(name.as_str(), |(s, _)| s);
            stem.ends_with(&suffix) && day_number(&name).is_some_and(|d| today.saturating_sub(d) <= days)
        })
        .filter(|e| {
            fs::read(e.path().join("event.json"))
                .ok()
                .and_then(|b| serde_json::from_slice::<Event>(&b).ok())
                .is_some_and(|ev| ev.process_basename().as_deref() == Some(process_basename))
        })
        .count()
}

/// Days since 1970-01-01 for the first `YYYYMMDD` (or `YYYY-MM-DD`) in `s`.
fn day_number(s: &str) -> Option<u64> {
    let digits: Vec<u32> =
        s.chars().take_while(|c| c.is_ascii_digit() || *c == '-').filter_map(|c| c.to_digit(10)).collect();
    if digits.len() < 8 {
        return None;
    }
    let num = |from: usize, len: usize| digits[from..from + len].iter().fold(0i64, |a, d| a * 10 + i64::from(*d));
    let (y, m, d) = (num(0, 4), num(4, 2), num(6, 2));
    if !(1..=12).contains(&m) || !(1..=31).contains(&d) {
        return None;
    }
    // Days from civil (Howard Hinnant), valid for every date Windows can write.
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    u64::try_from(era * 146_097 + doe - 719_468).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        evidence::{bundle_dir, write_bundle},
        rules::{Match, Severity, Triage},
        signing::Identity,
    };
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
    fn day_number_counts_civil_days() {
        assert_eq!(day_number("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(day_number("20260922-040000-x"), Some(20_718));
        assert_eq!(day_number("2026-09-29T00:00:00Z").map(|d| d - 20_718), Some(7));
        assert_eq!(day_number("garbage"), None);
        assert_eq!(day_number("20261399"), None);
    }

    #[test]
    fn repeats_counts_the_same_rule_and_program_within_the_window() -> Result<(), String> {
        let tmp = tempfile::tempdir().map_err(|e| e.to_string())?;
        let id = Identity::from_seed(&[14u8; 32]).map_err(|e| e.to_string())?;
        let (mut ev, rule) = fixture();
        // Three for signal.exe on the 22nd, one for notepad.exe, one for signal.exe a month earlier.
        for _ in 0..3 {
            let dir = bundle_dir(tmp.path(), &ev, &rule);
            write_bundle(&dir, &ev, &rule, "<html></html>", &id).map_err(|e| e.to_string())?;
        }
        ev.process = Some(r"C:\Windows\notepad.exe".into());
        let dir = bundle_dir(tmp.path(), &ev, &rule);
        write_bundle(&dir, &ev, &rule, "<html></html>", &id).map_err(|e| e.to_string())?;
        ev.process = Some("signal.exe".into());
        ev.time = "2026-08-20T04:00:00Z".into();
        let dir = bundle_dir(tmp.path(), &ev, &rule);
        write_bundle(&dir, &ev, &rule, "<html></html>", &id).map_err(|e| e.to_string())?;

        assert_eq!(repeats(tmp.path(), "test-rule", "signal.exe", "2026-09-25T10:00:00Z", 7), 3);
        assert_eq!(repeats(tmp.path(), "test-rule", "notepad.exe", "2026-09-25T10:00:00Z", 7), 1);
        assert_eq!(repeats(tmp.path(), "other-rule", "signal.exe", "2026-09-25T10:00:00Z", 7), 0);
        assert_eq!(
            repeats(tmp.path(), "test-rule", "signal.exe", "2026-10-25T10:00:00Z", 7),
            0,
            "all outside the window"
        );
        assert_eq!(
            repeats(tmp.path(), "test-rule", "signal.exe", "2026-09-25T10:00:00Z", 60),
            4,
            "a wider window includes August"
        );
        Ok(())
    }

    #[test]
    fn quiet_dir_is_one_per_program_and_library_pair() {
        let (mut ev, rule) = fixture();
        ev.process = Some(r"\Device\HarddiskVolume3\Program Files\Brave\brave.exe".into());
        ev.data.insert("ImageName".into(), r"\Program Files\Brave\1.0\vulkan-1.dll".into());
        let root = Path::new("root");
        let a = quiet_dir(root, &ev, &rule);
        assert!(
            a.starts_with(root.join("quiet"))
                && a.file_name().is_some_and(|n| n.to_string_lossy().starts_with("test-rule-"))
        );
        ev.time = "2027-01-01T00:00:00Z".into();
        assert_eq!(quiet_dir(root, &ev, &rule), a, "time plays no part: a repeat maps to the same folder");
        ev.data.insert("ImageName".into(), r"\Program Files\Brave\1.0\planted.dll".into());
        assert_ne!(quiet_dir(root, &ev, &rule), a, "a different library is a different capture");
    }
}

//! The triage page. One self-contained HTML file: no scripts, no external
//! resources, no fonts, no tracking. Readable on a phone via a USB cable
//! and printable. Ugly on purpose; boring is trustworthy.

use crate::{
    event::Event,
    rules::{Rule, Severity},
};
use std::fmt::Write as _;

/// Contact block. Loaded from `rules/contacts.toml` by the OS crate; the core
/// has no opinion about which country the user is in.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct Contact {
    /// Organisation name.
    pub name: String,
    /// Who it is for, in plain words ("journalists", "anyone", "human-rights defenders").
    pub for_whom: String,
    /// How to reach them. A URL or phone number, shown as text — never a clickable link
    /// the user might tap in a hurry on the wrong site.
    pub how: String,
    /// When a human last confirmed this contact answers, as `YYYY-MM`. CI fails
    /// if any entry is older than six months (`BUILD_PLAN.md` phase 3).
    #[serde(default)]
    pub checked: String,
}

/// Escape for HTML text and attribute contexts.
#[must_use]
pub fn esc(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(c),
        }
    }
    out
}

/// Shown above everything else when `witness selftest` made the report.
const TEST_BANNER: &str = "<p class=\"box\"><strong>THIS IS A TEST.</strong> Nothing happened on this computer. \
<code>witness selftest</code> made this report so you know what a real one looks like. \
Its folder is safe to delete.</p>";

/// Render the report. `test` is true only for `witness selftest`: it adds a
/// banner, so a practice run can never be mistaken for a finding. It is an
/// explicit flag, never inferred from the event, so a real event can never
/// be labelled a test.
#[must_use]
pub fn render(
    ev: &Event,
    rule: &Rule,
    contacts: &[Contact],
    fingerprint: &str,
    bundle_dir: &str,
    test: bool,
) -> String {
    let mut h = String::with_capacity(4096);
    let tone = match rule.severity {
        Severity::Bug => "This is almost certainly an ordinary software bug.",
        Severity::Look => "This is unusual but usually harmless. It is worth a look.",
        Severity::Urgent => "This pattern is sometimes seen when someone tries to break into a computer. It does not mean that happened to you.",
    };
    let _ = write!(
        h,
        "<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\">\
<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src 'unsafe-inline'\">\
<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\
<title>Witness: {title}</title>\
<style>body{{font-family:system-ui,sans-serif;max-width:40em;margin:2em auto;padding:0 1em;line-height:1.5}}\
h1{{font-size:1.4em}}h2{{font-size:1.1em;margin-top:1.6em}}code{{word-break:break-all}}\
.box{{border:2px solid #444;padding:1em;margin:1em 0}}</style></head><body>\
{banner}<h1>{title}</h1>\
<p class=\"box\"><strong>{tone}</strong></p>\
<h2>What happened</h2><p>{what}</p>\
<h2>What it might mean</h2><p>{mean}</p>\
<h2>What to do</h2><ol>",
        banner = if test { TEST_BANNER } else { "" },
        title = esc(&rule.title),
        tone = esc(tone),
        what = esc(&rule.triage.what_happened),
        mean = esc(&rule.triage.what_it_might_mean),
    );
    for step in &rule.triage.what_to_do {
        let _ = write!(h, "<li>{}</li>", esc(step));
    }
    h.push_str("</ol>");

    if rule.severity >= Severity::Look && !contacts.is_empty() {
        h.push_str("<h2>Who can help</h2><p>These organisations help people for free and will not judge you for asking. Type the address yourself rather than clicking anything.</p><ul>");
        for c in contacts {
            let _ = write!(
                h,
                "<li><strong>{}</strong> ({}): <code>{}</code></li>",
                esc(&c.name),
                esc(&c.for_whom),
                esc(&c.how)
            );
        }
        h.push_str("</ul>");
    }

    let _ = write!(
        h,
        "<h2>For a technical helper</h2>\
<p>Evidence folder: <code>{dir}</code>. Zip that whole folder and send it; do not edit anything in it.</p>\
<p>Witness signing key fingerprint: <code>{fp}</code>. If you wrote this down when Witness was installed, check it matches.</p>\
<table><tr><td>Time</td><td>{time}</td></tr><tr><td>Channel</td><td>{chan}</td></tr>\
<tr><td>Provider</td><td>{prov}</td></tr><tr><td>Event ID</td><td>{eid}</td></tr><tr><td>Record ID</td><td>{rid}</td></tr>\
<tr><td>Process</td><td><code>{proc}</code></td></tr><tr><td>Exception</td><td><code>{exc}</code></td></tr>\
<tr><td>Rule</td><td><code>{rule}</code> ({sev})</td></tr></table>\
<p>Everything the operating system recorded about this event:</p><table>{data}</table>\
<h2>What Witness is not</h2>\
<p>Witness cannot prevent attacks and cannot tell you for certain whether one happened. \
It notices when Windows' own protections fire and explains it in plain language. \
If your computer is already compromised, this report could be wrong. When in doubt, ask a human above.</p>\
</body></html>",
        dir = esc(bundle_dir),
        fp = esc(fingerprint),
        time = esc(&ev.time),
        chan = esc(&ev.channel),
        prov = esc(&ev.provider),
        eid = ev.event_id,
        rid = ev.record_id,
        proc = match (ev.process_basename(), ev.process.as_deref()) {
            (Some(name), Some(full)) => format!("<strong>{}</strong> &nbsp; {}", esc(&name), esc(full)),
            _ => "unknown".to_string(),
        },
        exc = ev.exception_code.map_or_else(|| "none".into(), |c| format!("0x{c:08X}")),
        rule = esc(&rule.id),
        sev = rule.severity,
        data = ev.data.iter().fold(String::new(), |mut acc, (k, v)| {
            let _ = write!(acc, "<tr><td>{}</td><td><code>{}</code></td></tr>", esc(k), esc(v));
            acc
        }),
    );
    h
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::{Match, Triage};
    use std::collections::BTreeMap;

    #[test]
    fn escapes_everything_that_matters() {
        assert_eq!(esc(r#"<a href="x">&'"#), "&lt;a href=&quot;x&quot;&gt;&amp;&#39;");
    }

    #[test]
    fn report_contains_no_script_and_escapes_event_data() {
        let ev = Event {
            time: "t".into(),
            channel: "c".into(),
            provider: "p".into(),
            event_id: 1,
            record_id: 7,
            process: Some("<script>alert(1)</script>".into()),
            exception_code: Some(0xC000_0409),
            data: BTreeMap::from([("ImagePath".to_string(), "\\\\evil\\share\\x.dll<img src=x>".to_string())]),
            raw: String::new(),
        };
        let rule = Rule {
            id: "r".into(),
            title: "T".into(),
            severity: Severity::Urgent,
            matcher: Match::default(),
            triage: Triage { what_happened: "a".into(), what_it_might_mean: "b".into(), what_to_do: vec!["c".into()] },
        };
        let contacts = vec![Contact {
            name: "Helpline".into(),
            for_whom: "anyone".into(),
            how: "help.example".into(),
            checked: "2026-09".into(),
        }];
        let html = render(&ev, &rule, &contacts, "aaaa-bbbb", r"C:\evidence\x", false);
        assert!(!html.contains("THIS IS A TEST"), "a real report must never say it is a test");
        assert!(render(&ev, &rule, &contacts, "aaaa-bbbb", r"C:\evidence\x", true).contains("THIS IS A TEST"));
        assert!(!html.contains("<script"));
        assert!(html.contains("&lt;script&gt;"));
        assert!(html.contains("<strong>script&gt;</strong>"), "basename (after the last slash) shown first, escaped");
        assert!(html.contains("default-src 'none'"));
        assert!(html.contains("Helpline"));
        assert!(html.contains("0xC0000409"));
        assert!(html.contains("ImagePath") && html.contains("&lt;img src=x&gt;") && !html.contains("<img"));
    }

    proptest::proptest! {
        #[test]
        fn escaped_text_never_contains_markup(s in "\\PC{0,256}") {
            let e = esc(&s);
            proptest::prop_assert!(!e.contains(['<', '>', '"', '\'']));
            // `&` may only appear as the start of one of our five entities.
            for piece in e.split('&').skip(1) {
                proptest::prop_assert!(["amp;", "lt;", "gt;", "quot;", "#39;"].iter().any(|ent| piece.starts_with(ent)));
            }
        }
    }
}

//! Rules: human-readable, reviewable, argue-about-it-in-a-PR TOML.
//!
//! There is deliberately no scoring, no ML, no "confidence". A rule either
//! matches or it doesn't, and every rule carries the plain-English text the
//! user will see. If you can't explain a rule in that text, it doesn't ship.

use crate::event::Event;
use serde::{Deserialize, Serialize};
use std::fmt;

/// How worried the user should be. Deliberately only three levels.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    /// Almost certainly an ordinary software bug. Logged, not shown.
    Bug,
    /// Unusual. Worth a look. Show the user, keep the evidence.
    Look,
    /// Pattern strongly associated with exploitation attempts. Show, keep, and
    /// point the user at a helpline. Never says "you have been hacked".
    Urgent,
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Severity::Bug => "bug",
            Severity::Look => "look",
            Severity::Urgent => "urgent",
        })
    }
}

/// What a rule matches on. All present fields must match (AND).
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct Match {
    /// Channel name, case-insensitive exact match.
    pub channel: String,
    /// Event ID.
    pub event_id: u32,
    /// Provider name, case-insensitive, optional.
    #[serde(default)]
    pub provider: Option<String>,
    /// Exception code, optional.
    #[serde(default)]
    pub exception_code: Option<u32>,
    /// Process basenames (lower-case), any of which matches. Empty = any process.
    #[serde(default)]
    pub process_any: Vec<String>,
    /// If set, require [`Event::image_in_process_dir`] to equal this value.
    /// `true` singles out "a program blocked from loading its own bundled
    /// library", which is a bug; `false` singles out everything else.
    #[serde(default)]
    pub image_in_process_dir: Option<bool>,
}

/// The words the user sees. Written for a frightened non-technical person.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Triage {
    /// One sentence. What the computer just did.
    pub what_happened: String,
    /// One short paragraph. Honest about the boring explanation being likely.
    pub what_it_might_mean: String,
    /// Ordered, concrete steps.
    pub what_to_do: Vec<String>,
}

/// One rule.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Rule {
    /// Stable identifier used in evidence bundles and bug reports.
    pub id: String,
    /// Short title shown in the notification.
    pub title: String,
    /// Severity.
    pub severity: Severity,
    /// Match conditions.
    #[serde(rename = "match")]
    pub matcher: Match,
    /// User-facing text.
    pub triage: Triage,
}

/// A loaded rule set.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct RuleSet {
    /// Rules in priority order; the first match wins.
    #[serde(default, rename = "rule")]
    pub rules: Vec<Rule>,
}

/// Errors loading rules.
#[derive(Debug)]
pub enum RuleError {
    /// TOML did not parse.
    Parse(toml::de::Error),
    /// Semantic problem (duplicate id, empty text, ...).
    Invalid(String),
}

impl fmt::Display for RuleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RuleError::Parse(e) => write!(f, "rules parse error: {e}"),
            RuleError::Invalid(s) => write!(f, "rules invalid: {s}"),
        }
    }
}
impl std::error::Error for RuleError {}

impl RuleSet {
    /// Parse and validate a TOML rule set.
    ///
    /// # Errors
    /// Malformed TOML, or a semantic problem (duplicate id, empty text, upper-case process name).
    pub fn parse(text: &str) -> Result<Self, RuleError> {
        let set: RuleSet = toml::from_str(text).map_err(RuleError::Parse)?;
        set.validate()?;
        Ok(set)
    }

    fn validate(&self) -> Result<(), RuleError> {
        let mut seen = std::collections::BTreeSet::new();
        for r in &self.rules {
            if r.id.is_empty() || !r.id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
                return Err(RuleError::Invalid(format!("bad rule id {:?}", r.id)));
            }
            if !seen.insert(r.id.as_str()) {
                return Err(RuleError::Invalid(format!("duplicate rule id {:?}", r.id)));
            }
            if r.matcher.channel.is_empty() {
                return Err(RuleError::Invalid(format!("rule {} has empty channel", r.id)));
            }
            if r.triage.what_happened.is_empty()
                || r.triage.what_it_might_mean.is_empty()
                || r.triage.what_to_do.is_empty()
            {
                return Err(RuleError::Invalid(format!("rule {} is missing triage text", r.id)));
            }
            if r.matcher.process_any.iter().any(|p| p != &p.to_ascii_lowercase()) {
                return Err(RuleError::Invalid(format!("rule {}: process_any must be lower-case", r.id)));
            }
        }
        Ok(())
    }

    /// First matching rule, if any.
    #[must_use]
    pub fn first_match(&self, ev: &Event) -> Option<&Rule> {
        self.rules.iter().find(|r| r.matcher.matches(ev))
    }
}

impl Match {
    /// Does this event satisfy every condition?
    #[must_use]
    pub fn matches(&self, ev: &Event) -> bool {
        if !ev.channel.eq_ignore_ascii_case(&self.channel) || ev.event_id != self.event_id {
            return false;
        }
        if let Some(p) = &self.provider {
            if !ev.provider.eq_ignore_ascii_case(p) {
                return false;
            }
        }
        if let Some(code) = self.exception_code {
            if ev.exception_code != Some(code) {
                return false;
            }
        }
        if !self.process_any.is_empty() {
            match ev.process_basename() {
                Some(name) => {
                    if !self.process_any.iter().any(|p| p == &name) {
                        return false;
                    }
                }
                None => return false,
            }
        }
        if let Some(want) = self.image_in_process_dir {
            if ev.image_in_process_dir() != want {
                return false;
            }
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    const RULES: &str = r#"
[[rule]]
id = "cet-fastfail-messaging"
title = "Hardware stack protection stopped a messaging app"
severity = "urgent"
[rule.match]
channel = "Application"
event_id = 1000
exception_code = 0xC0000409
process_any = ["signal.exe", "whatsapp.exe"]
[rule.triage]
what_happened = "Windows shut down a messaging app because its memory was corrupted."
what_it_might_mean = "Usually a bug. Occasionally an exploit attempt."
what_to_do = ["Don't panic.", "Keep the evidence folder."]

[[rule]]
id = "cet-fastfail-any"
title = "Hardware stack protection stopped a program"
severity = "look"
[rule.match]
channel = "Application"
event_id = 1000
exception_code = 0xC0000409
[rule.triage]
what_happened = "x"
what_it_might_mean = "y"
what_to_do = ["z"]
"#;

    fn ev(process: &str, code: u32) -> Event {
        Event {
            time: "2026-09-22T04:00:00Z".into(),
            channel: "application".into(),
            provider: "Application Error".into(),
            event_id: 1000,
            record_id: 0,
            process: Some(process.into()),
            exception_code: Some(code),
            data: BTreeMap::new(),
            raw: String::new(),
        }
    }

    #[test]
    fn first_match_wins_in_order() {
        let set = RuleSet::parse(RULES).expect("fixture rules parse");
        assert_eq!(set.rules.len(), 2);
        let r = set.first_match(&ev(r"C:\x\Signal.exe", 0xC000_0409));
        assert_eq!(r.map(|r| r.id.as_str()), Some("cet-fastfail-messaging"));
        let r = set.first_match(&ev(r"C:\x\notepad.exe", 0xC000_0409));
        assert_eq!(r.map(|r| r.id.as_str()), Some("cet-fastfail-any"));
        assert!(set.first_match(&ev(r"C:\x\notepad.exe", 0xC000_0005)).is_none());
    }

    #[test]
    fn rejects_duplicate_ids_and_uppercase_process_names() {
        let dup = format!("{RULES}\n{}", RULES.replace("cet-fastfail-any", "cet-fastfail-messaging"));
        assert!(RuleSet::parse(&dup).is_err());
        let upper = RULES.replace("\"signal.exe\"", "\"Signal.exe\"");
        assert!(RuleSet::parse(&upper).is_err());
    }

    #[test]
    fn severity_orders_sensibly() {
        assert!(Severity::Bug < Severity::Look && Severity::Look < Severity::Urgent);
    }
}

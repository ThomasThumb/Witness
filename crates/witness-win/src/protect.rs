//! Is the alarm wired to the doors? Most of what Witness watches only fires
//! for programs someone has opted in to Windows' Exploit Protection, and on a
//! fresh machine none of the high-risk apps are. `check` shows what is on for
//! each high-risk app running now; `protect` prints the admin commands that
//! switch on the protections that are safe for every app on the list.
//! Witness prints; a person runs. Safe glue only: the OS calls live in
//! `processes.rs` and `harden.rs`.

use crate::{harden, processes};
use std::collections::BTreeMap;
use witness_core::rules::RuleSet;

/// Print, for each high-risk app running now, which protections are on.
/// Returns the names found running, for `protect`.
pub fn report(rules: &RuleSet) -> Result<Vec<String>, String> {
    let names = rules.high_risk_processes();
    let running = processes::running(&names)?;
    if running.is_empty() {
        println!(
            "apps:     none of the {} high-risk apps is running; start the ones you use and run check again",
            names.len()
        );
        return Ok(Vec::new());
    }
    // An app is many processes (browsers: a dozen), each with its own
    // policies. Report each protection as on in all, some or none of them.
    let mut by_app: BTreeMap<String, Vec<harden::Protection>> = BTreeMap::new();
    for (name, pid) in running {
        match harden::protection_of(pid) {
            Ok(p) => by_app.entry(name).or_default().push(p),
            Err(e) => println!("apps:     {name} (pid {pid}): could not read protections ({e})"),
        }
    }
    println!("apps:     high-risk apps running now, and what is on for them (all / some / none of their processes)");
    for (name, ps) in &by_app {
        let tally: Vec<String> = harden::Guard::ALL
            .iter()
            .map(|g| {
                let on = ps.iter().filter(|p| p.has(*g)).count();
                let word = if on == 0 {
                    "none"
                } else if on == ps.len() {
                    "all"
                } else {
                    "some"
                };
                format!("{} {word}", g.label())
            })
            .collect();
        println!("          {name} ({}): {}", ps.len(), tally.join(", "));
    }
    println!("          `witness protect` prints the commands that switch on the ones that are safe for every app.");
    Ok(by_app.into_keys().collect())
}

/// Print the commands. Only the two image-load blocks: they never break an
/// app, and they are what the `remote-image-block` (urgent) and
/// `low-integrity-image-block` rules watch. Not ACG, CIG or the child-process
/// block: browsers and messaging apps generate code and start helpers, and
/// each of those would break them outright.
pub fn commands(rules: &RuleSet) -> Result<(), String> {
    let names = rules.high_risk_processes();
    let mut running: Vec<String> = processes::running(&names)?.into_iter().map(|(n, _)| n).collect();
    running.sort_unstable();
    running.dedup();
    if running.is_empty() {
        println!("None of the high-risk apps is running. Start the ones you use, then run `witness protect` again.");
        return Ok(());
    }
    println!("These switch on the two protections that are safe for every app on the list: no code from");
    println!("network shares, no code from untrusted download locations. Run them in PowerShell as administrator.");
    println!("Witness changes nothing itself.");
    println!();
    for name in &running {
        println!("  Set-ProcessMitigation -Name {name} -Enable BlockRemoteImageLoads, BlockLowLabelImageLoads");
    }
    println!();
    println!("Restart each app afterwards; the setting applies when it starts. To undo one:");
    println!("  Set-ProcessMitigation -Name <app.exe> -Disable BlockRemoteImageLoads, BlockLowLabelImageLoads");
    println!();
    println!("Not offered: Arbitrary Code Guard, Code Integrity Guard and the child-process block. They break");
    println!("browsers and messaging apps. A technical helper may switch them on for a specific app that copes.");
    Ok(())
}

//! Self-hardening via `SetProcessMitigationPolicy`. Witness has no JIT, loads no
//! plugins and no non-Microsoft DLLs, so it can afford every policy Windows
//! offers. Anything that can't be applied is reported by `witness check`,
//! never silently skipped.
//!
//! Linker-level flags (CFG, CETCOMPAT, high-entropy ASLR, NX) are in
//! .cargo/config.toml; these are the runtime ones. CET user shadow stacks
//! cannot be turned on from inside a running process, hence /CETCOMPAT there.
//!
//! Signatures checked by hand against `windows` 0.61.3: the policy constants
//! live in `Win32::System::Threading`, the structs in `Win32::System::SystemServices`.

use std::{ffi::c_void, sync::OnceLock};
use windows::Win32::{
    Foundation::{CloseHandle, HANDLE},
    System::{
        SystemServices::{
            PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY, PROCESS_MITIGATION_CHILD_PROCESS_POLICY,
            PROCESS_MITIGATION_CONTROL_FLOW_GUARD_POLICY, PROCESS_MITIGATION_DYNAMIC_CODE_POLICY,
            PROCESS_MITIGATION_EXTENSION_POINT_DISABLE_POLICY, PROCESS_MITIGATION_IMAGE_LOAD_POLICY,
            PROCESS_MITIGATION_USER_SHADOW_STACK_POLICY,
        },
        Threading::{
            GetProcessMitigationPolicy, OpenProcess, ProcessChildProcessPolicy, ProcessControlFlowGuardPolicy,
            ProcessDynamicCodePolicy, ProcessExtensionPointDisablePolicy, ProcessImageLoadPolicy,
            ProcessSignaturePolicy, ProcessUserShadowStackPolicy, SetProcessMitigationPolicy,
            PROCESS_MITIGATION_POLICY, PROCESS_QUERY_LIMITED_INFORMATION,
        },
    },
};

static STATUS: OnceLock<String> = OnceLock::new();

/// Apply all policies. Call first thing in `main`, before any other DLL can
/// be pulled in. Order matters: extension points and image-load rules first
/// (they govern what may load), then signature policy, then ACG.
pub fn apply() {
    let mut ok = Vec::new();
    let mut failed = Vec::new();

    // Disable AppInit DLLs / IME / shims injection points. Bit 0 = DisableExtensionPoints.
    let mut ext = PROCESS_MITIGATION_EXTENSION_POINT_DISABLE_POLICY::default();
    ext.Anonymous.Flags = 1;
    set(ProcessExtensionPointDisablePolicy, &ext, "ExtensionPoints", &mut ok, &mut failed);

    // No images from remote shares (bit 0) or low-integrity locations (bit 1).
    let mut img = PROCESS_MITIGATION_IMAGE_LOAD_POLICY::default();
    img.Anonymous.Flags = 0b11;
    set(ProcessImageLoadPolicy, &img, "ImageLoad", &mut ok, &mut failed);

    // Only Microsoft-signed DLLs may load. Bit 0 = MicrosoftSignedOnly.
    let mut sig = PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY::default();
    sig.Anonymous.Flags = 1;
    set(ProcessSignaturePolicy, &sig, "CIG", &mut ok, &mut failed);

    // Arbitrary Code Guard: no RWX, no W->X flips. Bit 0 = ProhibitDynamicCode.
    let mut dyn_code = PROCESS_MITIGATION_DYNAMIC_CODE_POLICY::default();
    dyn_code.Anonymous.Flags = 1;
    set(ProcessDynamicCodePolicy, &dyn_code, "ACG", &mut ok, &mut failed);

    let s = if failed.is_empty() {
        format!("hardened ({})", ok.join(", "))
    } else {
        format!("hardened ({}); FAILED ({})", ok.join(", "), failed.join(", "))
    };
    let _ = STATUS.set(s);
}

fn set<T>(
    policy: PROCESS_MITIGATION_POLICY,
    value: &T,
    name: &'static str,
    ok: &mut Vec<&'static str>,
    failed: &mut Vec<String>,
) {
    // SAFETY: `value` is a fully-initialised policy struct of the exact type the
    // policy constant expects, and the length matches.
    let r = unsafe {
        SetProcessMitigationPolicy(policy, std::ptr::from_ref::<T>(value).cast::<c_void>(), std::mem::size_of::<T>())
    };
    match r {
        Ok(()) => ok.push(name),
        Err(e) => failed.push(format!("{name}: {e}")),
    }
}

/// Human-readable result for `witness check`.
pub fn status() -> &'static str {
    STATUS.get().map_or("not applied", String::as_str)
}

/// One exploit protection a process can have on. These are the doors the
/// alarm is wired to: a rule for a mitigation that is off for the program
/// it would protect can never fire.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Guard {
    /// Hardware-enforced stack protection (CET user shadow stacks).
    Cet,
    /// Control Flow Guard.
    Cfg,
    /// Arbitrary Code Guard: no new executable memory.
    Acg,
    /// Code Integrity Guard: only Microsoft-signed libraries.
    Cig,
    /// No libraries from network shares.
    NoRemoteImages,
    /// No libraries from untrusted (low-integrity) locations.
    NoLowLabelImages,
    /// May not start other programs.
    NoChildProcesses,
}

impl Guard {
    /// Every guard, in the order `check` prints them.
    pub const ALL: [Guard; 7] = [
        Guard::Cet,
        Guard::Cfg,
        Guard::Acg,
        Guard::Cig,
        Guard::NoRemoteImages,
        Guard::NoLowLabelImages,
        Guard::NoChildProcesses,
    ];

    /// The name a person sees.
    pub fn label(self) -> &'static str {
        match self {
            Guard::Cet => "stack-protection",
            Guard::Cfg => "CFG",
            Guard::Acg => "ACG",
            Guard::Cig => "CIG",
            Guard::NoRemoteImages => "no-remote-images",
            Guard::NoLowLabelImages => "no-untrusted-images",
            Guard::NoChildProcesses => "no-child-processes",
        }
    }
}

/// The set of guards on for one running process.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Protection(u8);

impl Protection {
    /// Is this guard on?
    pub fn has(self, g: Guard) -> bool {
        self.0 & (1 << g as u8) != 0
    }

    fn set(&mut self, g: Guard, on: bool) {
        if on {
            self.0 |= 1 << g as u8;
        }
    }
}

/// Read the protections of a running process by its id. Works for any
/// process of the same user without admin; a process we may not open
/// (another user's, or a protected one) is an error, not a guess.
pub fn protection_of(pid: u32) -> Result<Protection, String> {
    // SAFETY: the handle is closed below, exactly once, whatever happens between.
    let h = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) }.map_err(|e| format!("open: {e}"))?;
    let result = (|| {
        let cet: PROCESS_MITIGATION_USER_SHADOW_STACK_POLICY = get(h, ProcessUserShadowStackPolicy)?;
        let cfg: PROCESS_MITIGATION_CONTROL_FLOW_GUARD_POLICY = get(h, ProcessControlFlowGuardPolicy)?;
        let acg: PROCESS_MITIGATION_DYNAMIC_CODE_POLICY = get(h, ProcessDynamicCodePolicy)?;
        let cig: PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY = get(h, ProcessSignaturePolicy)?;
        let img: PROCESS_MITIGATION_IMAGE_LOAD_POLICY = get(h, ProcessImageLoadPolicy)?;
        let child: PROCESS_MITIGATION_CHILD_PROCESS_POLICY = get(h, ProcessChildProcessPolicy)?;
        // SAFETY: each struct was filled by a successful call; reading the
        // union's `Flags` view is how the bitfields are meant to be read.
        // Bit 0 is the policy's main flag in every struct; ImageLoad bit 1
        // is NoLowMandatoryLabelImages.
        let flags = unsafe {
            [
                (Guard::Cet, cet.Anonymous.Flags & 1),
                (Guard::Cfg, cfg.Anonymous.Flags & 1),
                (Guard::Acg, acg.Anonymous.Flags & 1),
                (Guard::Cig, cig.Anonymous.Flags & 1),
                (Guard::NoRemoteImages, img.Anonymous.Flags & 1),
                (Guard::NoLowLabelImages, img.Anonymous.Flags & 2),
                (Guard::NoChildProcesses, child.Anonymous.Flags & 1),
            ]
        };
        let mut p = Protection::default();
        for (g, bit) in flags {
            p.set(g, bit != 0);
        }
        Ok(p)
    })();
    // SAFETY: closing the handle OpenProcess gave us, once.
    let _ = unsafe { CloseHandle(h) };
    result
}

/// One `GetProcessMitigationPolicy` call into a zeroed policy struct.
fn get<T: Default>(h: HANDLE, policy: PROCESS_MITIGATION_POLICY) -> Result<T, String> {
    let mut value = T::default();
    // SAFETY: `value` is a policy struct of the exact type `policy` fills, and
    // the length passed is its size; it outlives the call.
    unsafe {
        GetProcessMitigationPolicy(
            h,
            policy,
            std::ptr::from_mut::<T>(&mut value).cast::<c_void>(),
            std::mem::size_of::<T>(),
        )
    }
    .map_err(|e| format!("policy {}: {e}", policy.0))?;
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::{apply, protection_of, Guard};

    #[test]
    fn reads_our_own_protections_back() -> Result<(), String> {
        let before = protection_of(std::process::id())?;
        assert!(
            before.has(Guard::Cfg),
            "CFG comes from the linker flags in .cargo/config.toml and applies to tests too"
        );
        apply();
        let after = protection_of(std::process::id())?;
        for g in [Guard::Acg, Guard::Cig, Guard::NoRemoteImages, Guard::NoLowLabelImages] {
            assert!(after.has(g), "{} should be on after apply(): {after:?}", g.label());
        }
        assert!(!after.has(Guard::NoChildProcesses), "Witness may start the browser for the report");
        assert!(protection_of(0).is_err(), "the idle process cannot be opened");
        Ok(())
    }
}

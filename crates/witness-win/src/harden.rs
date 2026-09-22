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
use windows::Win32::System::{
    SystemServices::{
        PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY, PROCESS_MITIGATION_DYNAMIC_CODE_POLICY,
        PROCESS_MITIGATION_EXTENSION_POINT_DISABLE_POLICY, PROCESS_MITIGATION_IMAGE_LOAD_POLICY,
    },
    Threading::{
        ProcessDynamicCodePolicy, ProcessExtensionPointDisablePolicy, ProcessImageLoadPolicy, ProcessSignaturePolicy,
        SetProcessMitigationPolicy, PROCESS_MITIGATION_POLICY,
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

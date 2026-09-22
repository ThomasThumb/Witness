//! Signing-seed storage: 32 random bytes, DPAPI-wrapped to the current user.
//!
//! Honest scope: DPAPI keeps the seed from other users on the machine and from
//! casual file copying. It does NOT protect against code already running as
//! this user. That is the whole machine's problem, not ours (`THREAT_MODEL.md`).
//!
//! Signatures checked by hand against `windows` 0.61.3
//! (`Win32::Security::Cryptography`, `Win32::Foundation::LocalFree`).

use std::{ffi::c_void, fs};
use windows::{
    core::PCWSTR,
    Win32::{
        Foundation::{LocalFree, HLOCAL},
        Security::Cryptography::{CryptProtectData, CryptUnprotectData, CRYPTPROTECT_UI_FORBIDDEN, CRYPT_INTEGER_BLOB},
    },
};
use witness_core::signing::{Identity, SEED_LEN};
use zeroize::Zeroizing;

const FILE: &str = "seed.dpapi";

/// Load the seed, or create and store a new one on first run. The returned
/// buffer is wiped when dropped.
pub fn load_or_create_seed() -> Result<Zeroizing<Vec<u8>>, String> {
    let path = crate::paths::base()?.join(FILE);
    if path.exists() {
        let wrapped = fs::read(&path).map_err(|e| e.to_string())?;
        let seed = dpapi(&wrapped, false)?;
        if seed.len() != SEED_LEN {
            return Err(format!("{FILE} unwrapped to {} bytes, expected {SEED_LEN}; refusing to guess", seed.len()));
        }
        return Ok(seed);
    }
    let seed = Zeroizing::new(Identity::new_seed().map_err(|e| e.to_string())?.to_vec());
    let wrapped = dpapi(&seed, true)?;
    // Write-then-rename so a crash never leaves a half-written key file.
    let tmp = path.with_extension("tmp");
    fs::write(&tmp, &*wrapped).map_err(|e| e.to_string())?;
    fs::rename(&tmp, &path).map_err(|e| e.to_string())?;
    Ok(seed)
}

/// Wrap (`protect = true`) or unwrap bytes with DPAPI, user scope, no UI.
fn dpapi(input: &[u8], protect: bool) -> Result<Zeroizing<Vec<u8>>, String> {
    let len = u32::try_from(input.len()).map_err(|_| "DPAPI input too large".to_string())?;
    let blob_in = CRYPT_INTEGER_BLOB { cbData: len, pbData: input.as_ptr().cast_mut() };
    let mut blob_out = CRYPT_INTEGER_BLOB::default();
    // SAFETY: `blob_in` points at `input`, alive for the call and only read by
    // the OS. `blob_out` is filled by the OS with LocalAlloc memory which we
    // copy and then LocalFree exactly once.
    let r = unsafe {
        if protect {
            CryptProtectData(
                &raw const blob_in,
                PCWSTR::null(),
                None,
                None,
                None,
                CRYPTPROTECT_UI_FORBIDDEN,
                &raw mut blob_out,
            )
        } else {
            CryptUnprotectData(&raw const blob_in, None, None, None, None, CRYPTPROTECT_UI_FORBIDDEN, &raw mut blob_out)
        }
    };
    r.map_err(|e| format!("DPAPI {}: {e}", if protect { "protect" } else { "unprotect" }))?;
    // SAFETY: pbData/cbData were set by a successful call.
    let out = unsafe { Zeroizing::new(std::slice::from_raw_parts(blob_out.pbData, blob_out.cbData as usize).to_vec()) };
    // SAFETY: freeing the buffer DPAPI allocated, once. Zero it first: for the
    // unprotect path it holds the plaintext seed.
    unsafe {
        std::ptr::write_bytes(blob_out.pbData, 0, blob_out.cbData as usize);
        let _ = LocalFree(Some(HLOCAL(blob_out.pbData.cast::<c_void>())));
    }
    Ok(out)
}

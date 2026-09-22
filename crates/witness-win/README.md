# witness-win

The Windows binary. See the workspace README.

Build: `cargo build --release -p witness-win` on Windows with the MSVC
toolchain. The hardening flags in `.cargo/config.toml` require MSVC's `link.exe`.

The four files containing `unsafe` (`eventlog.rs`, `keys.rs`, `harden.rs`,
`notify.rs`) each wrap one OS facility. Every call site has a SAFETY comment
and every signature was checked against the generated bindings in `windows`
0.61.3 (the whole crate type-checks against those bindings; only the final
link and the live-machine tests in BUILD_PLAN.md phase 2 remain).

Two things bit the original scaffold and are worth knowing if you bump the
`windows` crate: `LocalFree` lives in `Win32::Foundation`, and the
`PROCESS_MITIGATION_*_POLICY` structs live in `Win32::System::SystemServices`
(the policy *constants* are in `Win32::System::Threading`).

`witness selftest` pushes a built-in sample event through the exact code path
a real event takes (parse → rules → bundle → sign → toast → open) and then
verifies the bundle. Run it once after install; it is the fastest way to see
that toasts and the browser hand-off work on a given machine.

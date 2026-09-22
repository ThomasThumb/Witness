//! witness-core: everything that does not touch an operating system.
//!
//! Design rules for this crate (enforced by lint and review):
//! * `#![forbid(unsafe_code)]` — there is no reason for unsafe here.
//! * No I/O except through `evidence::Bundle`, which writes to a directory
//!   the caller chooses. No network. Ever. (`deny.toml` bans socket crates.)
//! * Everything is testable on Linux so the security-relevant logic gets
//!   reviewed and fuzzed without a Windows box.
#![forbid(unsafe_code)]
#![warn(clippy::pedantic)]
#![deny(missing_docs, clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

pub mod event;
pub mod evidence;
pub mod report;
pub mod rules;
pub mod signing;
pub mod winevt;

/// Tool version, embedded in every manifest so a reviewer knows what produced it.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

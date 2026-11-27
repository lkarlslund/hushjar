//! Vault logic for Hushjar: cryptography, item models, local storage and
//! server synchronisation. This crate must not depend on any UI toolkit.

#![forbid(unsafe_code)]

pub mod api;
pub mod crypto;
pub mod exchange;
pub mod fingerprint;
pub mod generator;
pub mod notifications;
pub mod policy;
pub mod send;
pub mod session;
pub mod sshkey;
pub mod store;
pub mod totp;
pub mod vault;
pub mod webauthn;
pub mod wordlist;

/// The release identity, `r<commit count>` such as `r0066`, set through
/// `HUSHJAR_VERSION` by the release workflow and the packaging scripts
/// (scripts/build-number). A plain `cargo build` says `dev`.
pub const VERSION: &str = match option_env!("HUSHJAR_VERSION") {
    Some(v) => v,
    None => "dev",
};

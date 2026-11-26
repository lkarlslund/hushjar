//! Vault logic for Hushjar: cryptography, item models, local storage and
//! server synchronisation. This crate must not depend on any UI toolkit.

#![forbid(unsafe_code)]

pub mod api;
pub mod crypto;
pub mod fingerprint;
pub mod generator;
pub mod send;
pub mod session;
pub mod store;
pub mod totp;
pub mod vault;
pub mod wordlist;

//! Vault logic for Hushjar: cryptography, item models, local storage and
//! server synchronisation. This crate must not depend on any UI toolkit.

#![forbid(unsafe_code)]

pub mod crypto;
pub mod totp;

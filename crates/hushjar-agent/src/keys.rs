//! Parsing the app's keys and signing with them.

use std::fmt;

use signature::{Signer, Verifier};
use ssh_key::encoding::Encode;
use ssh_key::private::KeypairData;
use ssh_key::{HashAlg, PrivateKey};

use crate::AgentKey;
use crate::proto::{SSH_AGENT_RSA_SHA2_256, SSH_AGENT_RSA_SHA2_512};

/// Largest private key text accepted (VaultGoblin
/// `internal/sshagent/key.go:22`).
const MAX_PRIVATE_KEY_LEN: usize = 64 << 10;
/// RSA modulus sizes accepted (VaultGoblin `key.go:60`).
const RSA_MIN_BITS: usize = 2048;
const RSA_MAX_BITS: usize = 8192;

/// A key from the [`crate::KeySource`] that parsed and is of a supported type.
pub(crate) struct LoadedKey {
    pub(crate) id: String,
    pub(crate) name: String,
    /// The public key blob, as sent to clients.
    pub(crate) blob: Vec<u8>,
    pub(crate) fingerprint: String,
    private: PrivateKey,
}

impl fmt::Debug for LoadedKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LoadedKey")
            .field("id", &self.id)
            .field("name", &self.name)
            .field("fingerprint", &self.fingerprint)
            .finish_non_exhaustive()
    }
}

/// The signature algorithm chosen for a request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SignAlgorithm {
    /// Ed25519 or ECDSA: the key type decides.
    Native,
    RsaSha256,
    RsaSha512,
}

impl LoadedKey {
    /// Parses a key. Returns `None` for keys that are encrypted, of an
    /// unsupported type or out of the accepted size range.
    pub(crate) fn load(key: &AgentKey) -> Option<LoadedKey> {
        let text = key.private_key_openssh.trim();
        if text.is_empty() || text.len() > MAX_PRIVATE_KEY_LEN {
            return None;
        }
        // from_openssh checks that the public key in the file header matches
        // the one in the private section.
        let private = PrivateKey::from_openssh(text).ok()?;
        if private.is_encrypted() {
            return None;
        }
        match private.key_data() {
            KeypairData::Ed25519(_) | KeypairData::Ecdsa(_) => {}
            KeypairData::Rsa(rsa) => {
                let bits = modulus_bits(rsa.public().n().as_positive_bytes()?);
                if !(RSA_MIN_BITS..=RSA_MAX_BITS).contains(&bits) {
                    return None;
                }
            }
            _ => return None,
        }
        let public = private.public_key();
        let blob = public.key_data().encode_vec().ok()?;
        let fingerprint = public.fingerprint(HashAlg::Sha256).to_string();
        Some(LoadedKey {
            id: key.id.clone(),
            name: key.name.clone(),
            blob,
            fingerprint,
            private,
        })
    }

    /// Picks the signature algorithm for the request's flags, following
    /// VaultGoblin `key.go:77-98`: Ed25519 and ECDSA take no flags, RSA needs
    /// exactly one of the SHA-2 flags. Plain `ssh-rsa` (SHA-1) is refused.
    pub(crate) fn algorithm(&self, flags: u32) -> Option<SignAlgorithm> {
        match self.private.key_data() {
            KeypairData::Ed25519(_) | KeypairData::Ecdsa(_) if flags == 0 => {
                Some(SignAlgorithm::Native)
            }
            KeypairData::Rsa(_) => match flags {
                SSH_AGENT_RSA_SHA2_256 => Some(SignAlgorithm::RsaSha256),
                SSH_AGENT_RSA_SHA2_512 => Some(SignAlgorithm::RsaSha512),
                _ => None,
            },
            _ => None,
        }
    }

    /// Signs `data` and returns the encoded signature (`string algorithm,
    /// string blob`). The signature is checked against the public key before
    /// it is returned, which catches a private key that does not belong to
    /// its public key and faults during signing.
    pub(crate) fn sign(&self, data: &[u8], algorithm: SignAlgorithm) -> Option<Vec<u8>> {
        let signature = match (self.private.key_data(), algorithm) {
            (KeypairData::Rsa(rsa), SignAlgorithm::RsaSha256) => {
                (rsa, Some(HashAlg::Sha256)).try_sign(data).ok()?
            }
            (KeypairData::Rsa(rsa), SignAlgorithm::RsaSha512) => {
                (rsa, Some(HashAlg::Sha512)).try_sign(data).ok()?
            }
            (KeypairData::Ed25519(_) | KeypairData::Ecdsa(_), SignAlgorithm::Native) => {
                self.private.key_data().try_sign(data).ok()?
            }
            _ => return None,
        };
        self.private
            .public_key()
            .key_data()
            .verify(data, &signature)
            .ok()?;
        signature.encode_vec().ok()
    }
}

/// Bit length of a big-endian positive integer without leading zero bytes.
fn modulus_bits(bytes: &[u8]) -> usize {
    match bytes.first() {
        Some(first) => bytes.len() * 8 - first.leading_zeros() as usize,
        None => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn modulus_bit_length() {
        assert_eq!(modulus_bits(&[]), 0);
        assert_eq!(modulus_bits(&[1]), 1);
        assert_eq!(modulus_bits(&[0x80, 0]), 16);
        assert_eq!(modulus_bits(&[0x7f, 0]), 15);
    }

    #[test]
    fn rejects_garbage_and_debug_redacts() {
        let key = AgentKey {
            id: "id".into(),
            name: "name".into(),
            private_key_openssh: String::from("not a key").into(),
        };
        assert!(LoadedKey::load(&key).is_none());
        assert!(!format!("{key:?}").contains("not a key"));
    }
}

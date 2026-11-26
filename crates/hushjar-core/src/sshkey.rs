//! SSH keys for vault items: generating new ones and importing existing ones.
//!
//! The vault stores the private key as an unencrypted OpenSSH PEM, the public
//! key as one `ssh-... AAAA...` line without a comment, and the fingerprint as
//! `SHA256:...` without padding, exactly as `ssh-keygen -l` prints it. This
//! matches what the Bitwarden clients store.

use pkcs8::{DecodePrivateKey, EncryptedPrivateKeyInfoRef, PrivateKeyInfoRef};
use ssh_key::private::{Ed25519Keypair, KeypairData, RsaKeypair};
use ssh_key::rand_core::UnwrapErr;
use ssh_key::{HashAlg, LineEnding, PrivateKey};
use thiserror::Error;
use zeroize::Zeroizing;

use crate::vault;

/// The key types the generator offers. Bitwarden offers Ed25519, RSA 3072 and
/// RSA 4096 (plus ECDSA); 2048-bit RSA is added for older servers that insist
/// on it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Algorithm {
    Ed25519,
    Rsa2048,
    Rsa3072,
    Rsa4096,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum SshKeyError {
    #[error("the key is protected by a passphrase")]
    PassphraseNeeded,
    #[error("the passphrase is wrong")]
    WrongPassphrase,
    #[error("this is a public key; a private key is needed")]
    PublicKey,
    #[error("the key type is not supported (use Ed25519 or RSA, as OpenSSH or PKCS#8 PEM)")]
    Unsupported,
    #[error("this is not a private key in a format Hushjar can read")]
    Unreadable,
    #[error("could not generate a key")]
    Generate,
}

/// Generates a new unencrypted key pair.
pub fn generate(algorithm: Algorithm) -> Result<vault::SshKey, SshKeyError> {
    let mut rng = UnwrapErr(getrandom::SysRng);
    let data = match algorithm {
        Algorithm::Ed25519 => KeypairData::from(Ed25519Keypair::random(&mut rng)),
        Algorithm::Rsa2048 => rsa_data(&mut rng, 2048)?,
        Algorithm::Rsa3072 => rsa_data(&mut rng, 3072)?,
        Algorithm::Rsa4096 => rsa_data(&mut rng, 4096)?,
    };
    let key = PrivateKey::new(data, "").map_err(|_| SshKeyError::Generate)?;
    to_vault(&key)
}

fn rsa_data(
    rng: &mut UnwrapErr<getrandom::SysRng>,
    bits: usize,
) -> Result<KeypairData, SshKeyError> {
    RsaKeypair::random(rng, bits)
        .map(KeypairData::from)
        .map_err(|_| SshKeyError::Generate)
}

/// Reads a private key in OpenSSH or PKCS#8 PEM form (encrypted or not) and
/// returns it as an unencrypted OpenSSH key. The passphrase is ignored for
/// keys that are not encrypted.
pub fn import(text: &str, passphrase: Option<&str>) -> Result<vault::SshKey, SshKeyError> {
    let text = text.trim();
    let first = text.lines().next().unwrap_or("").trim();
    let key = match first {
        "-----BEGIN OPENSSH PRIVATE KEY-----" => openssh(text, passphrase)?, // privacy:allow (PEM format marker, not a key)
        "-----BEGIN PRIVATE KEY-----" => pkcs8_plain(text)?, // privacy:allow (PEM format marker, not a key)
        "-----BEGIN ENCRYPTED PRIVATE KEY-----" => pkcs8_encrypted(text, passphrase)?, // privacy:allow (PEM format marker, not a key)
        "-----BEGIN RSA PRIVATE KEY-----" => return Err(SshKeyError::Unsupported), // privacy:allow (PEM marker)
        "-----BEGIN EC PRIVATE KEY-----" => return Err(SshKeyError::Unsupported), // privacy:allow (PEM marker)
        _ if first.starts_with("ssh-")
            || first.starts_with("ecdsa-")
            || first.starts_with("sk-")
            || first.starts_with("-----BEGIN PUBLIC KEY-----")
            || first.starts_with("---- BEGIN SSH2 PUBLIC KEY") =>
        {
            return Err(SshKeyError::PublicKey);
        }
        _ => return Err(SshKeyError::Unreadable),
    };
    to_vault(&key)
}

/// Recomputes the public key and fingerprint from an unencrypted OpenSSH
/// private key, for when the user pastes or edits the private key.
pub fn from_private(private_openssh: &str) -> Result<vault::SshKey, SshKeyError> {
    import(private_openssh, None)
}

fn openssh(text: &str, passphrase: Option<&str>) -> Result<PrivateKey, SshKeyError> {
    let key = PrivateKey::from_openssh(text).map_err(|e| match e {
        ssh_key::Error::AlgorithmUnknown | ssh_key::Error::AlgorithmUnsupported { .. } => {
            SshKeyError::Unsupported
        }
        _ => SshKeyError::Unreadable,
    })?;
    let key = if key.is_encrypted() {
        let pass = passphrase.ok_or(SshKeyError::PassphraseNeeded)?;
        key.decrypt(pass)
            .map_err(|_| SshKeyError::WrongPassphrase)?
    } else {
        key
    };
    supported(key)
}

fn pkcs8_plain(text: &str) -> Result<PrivateKey, SshKeyError> {
    let der = pem_to_der(text, "PRIVATE KEY")?;
    from_pkcs8_der(&der)
}

fn pkcs8_encrypted(text: &str, passphrase: Option<&str>) -> Result<PrivateKey, SshKeyError> {
    let pass = passphrase.ok_or(SshKeyError::PassphraseNeeded)?;
    let der = pem_to_der(text, "ENCRYPTED PRIVATE KEY")?;
    let info = EncryptedPrivateKeyInfoRef::try_from(der.as_slice())
        .map_err(|_| SshKeyError::Unreadable)?;
    let plain = info.decrypt(pass).map_err(|e| match e {
        pkcs8::Error::EncryptedPrivateKey(_) => SshKeyError::WrongPassphrase,
        _ => SshKeyError::Unreadable,
    })?;
    from_pkcs8_der(plain.as_bytes())
}

/// Decodes the PEM armour with the given label into DER.
fn pem_to_der(text: &str, label: &str) -> Result<Zeroizing<Vec<u8>>, SshKeyError> {
    let (found, der) =
        pkcs8::der::pem::decode_vec(text.as_bytes()).map_err(|_| SshKeyError::Unreadable)?;
    if found != label {
        return Err(SshKeyError::Unreadable);
    }
    Ok(Zeroizing::new(der))
}

fn from_pkcs8_der(der: &[u8]) -> Result<PrivateKey, SshKeyError> {
    /// OIDs of the algorithms OpenSSH can carry that we accept.
    const ED25519: &str = "1.3.101.112";
    const RSA: &str = "1.2.840.113549.1.1.1";
    let info = PrivateKeyInfoRef::try_from(der).map_err(|_| SshKeyError::Unreadable)?;
    let data = match info.algorithm.oid.to_string().as_str() {
        ED25519 => {
            let signing = ed25519_dalek::SigningKey::from_pkcs8_der(der)
                .map_err(|_| SshKeyError::Unreadable)?;
            KeypairData::from(Ed25519Keypair::from(signing))
        }
        RSA => {
            let rsa = rsa::PrivateKey::from_pkcs8_der(der).map_err(|_| SshKeyError::Unreadable)?;
            KeypairData::from(RsaKeypair::try_from(rsa).map_err(|_| SshKeyError::Unreadable)?)
        }
        _ => return Err(SshKeyError::Unsupported),
    };
    PrivateKey::new(data, "").map_err(|_| SshKeyError::Unreadable)
}

/// Accepts only the algorithms the generator and the agent handle.
fn supported(key: PrivateKey) -> Result<PrivateKey, SshKeyError> {
    match key.key_data() {
        KeypairData::Ed25519(_) | KeypairData::Rsa(_) => Ok(key),
        _ => Err(SshKeyError::Unsupported),
    }
}

/// Builds the stored form of a decrypted key. The comment is dropped, as
/// Bitwarden does.
fn to_vault(key: &PrivateKey) -> Result<vault::SshKey, SshKeyError> {
    let mut key = key.clone();
    key.set_comment("");
    let private = key
        .to_openssh(LineEnding::LF)
        .map_err(|_| SshKeyError::Unreadable)?;
    let public = key
        .public_key()
        .to_openssh()
        .map_err(|_| SshKeyError::Unreadable)?;
    Ok(vault::SshKey {
        private_key: private.to_string(),
        public_key: public.trim_end().to_string(),
        fingerprint: key.fingerprint(HashAlg::Sha256).to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_keys_round_trip() {
        for alg in [Algorithm::Ed25519, Algorithm::Rsa2048] {
            let k = generate(alg).unwrap();
            assert!(
                k.private_key
                    .starts_with("-----BEGIN OPENSSH PRIVATE KEY-----\n") // privacy:allow (PEM format marker, not a key)
            );
            assert!(!k.private_key.contains('\r'));
            assert!(k.fingerprint.starts_with("SHA256:") && !k.fingerprint.ends_with('='));
            let prefix = if alg == Algorithm::Ed25519 {
                "ssh-ed25519 "
            } else {
                "ssh-rsa "
            };
            assert!(k.public_key.starts_with(prefix));
            assert_eq!(k.public_key.split(' ').count(), 2, "no comment");
            let again = from_private(&k.private_key).unwrap();
            assert_eq!(again.public_key, k.public_key);
            assert_eq!(again.fingerprint, k.fingerprint);
        }
    }

    #[test]
    fn generated_keys_differ() {
        let a = generate(Algorithm::Ed25519).unwrap();
        let b = generate(Algorithm::Ed25519).unwrap();
        assert_ne!(a.fingerprint, b.fingerprint);
    }

    #[test]
    fn import_rejects_public_keys_and_garbage() {
        let k = generate(Algorithm::Ed25519).unwrap();
        assert_eq!(import(&k.public_key, None), Err(SshKeyError::PublicKey));
        assert_eq!(import("hello world", None), Err(SshKeyError::Unreadable));
        assert_eq!(import("", None), Err(SshKeyError::Unreadable));
        let broken = "-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n-----END OPENSSH PRIVATE KEY-----"; // privacy:allow (PEM format marker, not a key)
        assert_eq!(import(broken, None), Err(SshKeyError::Unreadable));
        assert_eq!(
            import(
                "-----BEGIN RSA PRIVATE KEY-----\nAAAA\n-----END RSA PRIVATE KEY-----", // privacy:allow (PEM format marker, not a key)
                None
            ),
            Err(SshKeyError::Unsupported)
        );
    }

    #[test]
    fn import_tolerates_surrounding_whitespace_and_crlf() {
        let k = generate(Algorithm::Ed25519).unwrap();
        let text = format!("\n  {}\n\n", k.private_key.replace('\n', "\r\n"));
        assert_eq!(import(&text, None).unwrap().fingerprint, k.fingerprint);
    }
}

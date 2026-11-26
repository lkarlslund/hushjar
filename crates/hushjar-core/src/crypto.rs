//! Bitwarden-compatible cryptography: master key derivation, key stretching,
//! encrypted strings, and a separate AES-GCM format for Hushjar's own cache.
//!
//! Secrets are held in zeroising buffers. `Debug` output never shows key bytes.

use std::fmt;
use std::str::FromStr;

use aes::Aes256;
use aes::cipher::{BlockModeDecrypt, BlockModeEncrypt, KeyIvInit, block_padding::Pkcs7};
use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

type HmacSha256 = Hmac<Sha256>;

/// Largest decoded encrypted string accepted, for fields and keys.
pub const MAX_ENCRYPTED_BYTES: usize = 16 << 20;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum CryptoError {
    #[error("unsupported key derivation settings")]
    UnsupportedKdf,
    #[error("malformed encrypted value")]
    Malformed,
    #[error("unsupported encryption type {0}")]
    UnsupportedType(u8),
    #[error("encrypted value failed authentication")]
    Authentication,
    #[error("wrong key size")]
    KeySize,
    #[error("RSA operation failed")]
    Rsa,
}

pub fn random_bytes<const N: usize>() -> [u8; N] {
    let mut out = [0u8; N];
    getrandom::fill(&mut out).expect("operating system random source");
    out
}

/// A Bitwarden symmetric key: a 32-byte AES-256 key and a 32-byte HMAC key.
#[derive(Clone)]
pub struct SymmetricKey {
    enc: Zeroizing<[u8; 32]>,
    mac: Zeroizing<[u8; 32]>,
}

impl fmt::Debug for SymmetricKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SymmetricKey([redacted])")
    }
}

impl SymmetricKey {
    /// Builds a key from 64 bytes: encryption key first, then MAC key.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() != 64 {
            return Err(CryptoError::KeySize);
        }
        let mut enc = Zeroizing::new([0u8; 32]);
        let mut mac = Zeroizing::new([0u8; 32]);
        enc.copy_from_slice(&bytes[..32]);
        mac.copy_from_slice(&bytes[32..]);
        Ok(Self { enc, mac })
    }

    pub fn generate() -> Self {
        let mut bytes = Zeroizing::new(random_bytes::<64>());
        let key = Self::from_bytes(&bytes[..]).expect("64 bytes");
        bytes.zeroize();
        key
    }

    pub fn to_bytes(&self) -> Zeroizing<Vec<u8>> {
        let mut out = Zeroizing::new(Vec::with_capacity(64));
        out.extend_from_slice(&self.enc[..]);
        out.extend_from_slice(&self.mac[..]);
        out
    }

    /// Encrypts with a fresh random IV as a type 2 encrypted string.
    pub fn encrypt(&self, plaintext: &[u8]) -> EncString {
        let iv = random_bytes::<16>();
        let ct = cbc::Encryptor::<Aes256>::new_from_slices(&self.enc[..], &iv)
            .expect("32-byte key and 16-byte IV")
            .encrypt_padded_vec::<Pkcs7>(plaintext);
        let mac = self.mac_for(&iv, &ct);
        EncString::AesCbcHmac { iv, ct, mac }
    }

    pub fn encrypt_str(&self, plaintext: &str) -> String {
        self.encrypt(plaintext.as_bytes()).to_string()
    }

    fn mac_for(&self, iv: &[u8; 16], ct: &[u8]) -> [u8; 32] {
        let mut mac =
            <HmacSha256 as hmac::KeyInit>::new_from_slice(&self.mac[..]).expect("any key length");
        mac.update(iv);
        mac.update(ct);
        mac.finalize().into_bytes().into()
    }

    fn decrypt_cbc(
        &self,
        iv: &[u8; 16],
        ct: &[u8],
        tag: &[u8; 32],
    ) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
        let mut mac =
            <HmacSha256 as hmac::KeyInit>::new_from_slice(&self.mac[..]).expect("any key length");
        mac.update(iv);
        mac.update(ct);
        mac.verify_slice(tag)
            .map_err(|_| CryptoError::Authentication)?;
        let plain = cbc::Decryptor::<Aes256>::new_from_slices(&self.enc[..], iv)
            .expect("32-byte key and 16-byte IV")
            .decrypt_padded_vec::<Pkcs7>(ct)
            .map_err(|_| CryptoError::Authentication)?;
        Ok(Zeroizing::new(plain))
    }

    /// Decrypts a type 2 encrypted string. Other types are rejected.
    pub fn decrypt(&self, value: &EncString) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
        match value {
            EncString::AesCbcHmac { iv, ct, mac } => self.decrypt_cbc(iv, ct, mac),
            EncString::Rsa { kind, .. } => Err(CryptoError::UnsupportedType(*kind)),
        }
    }

    pub fn decrypt_str(&self, value: &str) -> Result<Zeroizing<String>, CryptoError> {
        let plain = self.decrypt(&value.parse()?)?;
        String::from_utf8(plain.to_vec())
            .map(Zeroizing::new)
            .map_err(|_| CryptoError::Malformed)
    }

    /// Decrypts a wrapped 64-byte key, such as an item or organisation key.
    pub fn unwrap_key(&self, wrapped: &str) -> Result<SymmetricKey, CryptoError> {
        let plain = self.decrypt(&wrapped.parse()?)?;
        SymmetricKey::from_bytes(&plain)
    }

    pub fn wrap_key(&self, key: &SymmetricKey) -> String {
        self.encrypt(&key.to_bytes()).to_string()
    }

    /// Derives a 32-byte subkey for Hushjar's own local formats.
    pub fn derive_local(&self, salt: &[u8], info: &str) -> Zeroizing<[u8; 32]> {
        let ikm = self.to_bytes();
        let hk = Hkdf::<Sha256>::new(Some(salt), &ikm);
        let mut out = Zeroizing::new([0u8; 32]);
        hk.expand(info.as_bytes(), &mut out[..])
            .expect("32 bytes is a valid HKDF length");
        out
    }
}

/// A parsed Bitwarden encrypted string.
#[derive(Clone, PartialEq, Eq)]
pub enum EncString {
    /// Type 2: AES-256-CBC with HMAC-SHA256 over IV and ciphertext.
    AesCbcHmac {
        iv: [u8; 16],
        ct: Vec<u8>,
        mac: [u8; 32],
    },
    /// Types 3 to 6: RSA-OAEP, used to share organisation keys.
    Rsa { kind: u8, ct: Vec<u8> },
}

impl fmt::Debug for EncString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EncString::AesCbcHmac { ct, .. } => {
                write!(f, "EncString::AesCbcHmac({} bytes)", ct.len())
            }
            EncString::Rsa { kind, ct } => {
                write!(f, "EncString::Rsa(type {kind}, {} bytes)", ct.len())
            }
        }
    }
}

fn decode_b64(part: &str) -> Result<Vec<u8>, CryptoError> {
    if part.len() > MAX_ENCRYPTED_BYTES / 3 * 4 + 4 {
        return Err(CryptoError::Malformed);
    }
    B64.decode(part).map_err(|_| CryptoError::Malformed)
}

impl FromStr for EncString {
    type Err = CryptoError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (kind, rest) = s.split_once('.').ok_or(CryptoError::Malformed)?;
        let kind: u8 = kind.parse().map_err(|_| CryptoError::Malformed)?;
        let parts: Vec<&str> = rest.split('|').collect();
        match kind {
            2 => {
                let [iv, ct, mac] = parts[..] else {
                    return Err(CryptoError::Malformed);
                };
                let iv: [u8; 16] = decode_b64(iv)?
                    .try_into()
                    .map_err(|_| CryptoError::Malformed)?;
                let ct = decode_b64(ct)?;
                let mac: [u8; 32] = decode_b64(mac)?
                    .try_into()
                    .map_err(|_| CryptoError::Malformed)?;
                if ct.is_empty() || ct.len() % 16 != 0 {
                    return Err(CryptoError::Malformed);
                }
                Ok(EncString::AesCbcHmac { iv, ct, mac })
            }
            // Type 4 is RSA-2048-OAEP-SHA1 without a MAC, which Bitwarden uses
            // for organisation keys. Types 3, 5 and 6 are deprecated.
            4 => {
                let [ct] = parts[..] else {
                    return Err(CryptoError::Malformed);
                };
                Ok(EncString::Rsa {
                    kind,
                    ct: decode_b64(ct)?,
                })
            }
            other => Err(CryptoError::UnsupportedType(other)),
        }
    }
}

impl fmt::Display for EncString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EncString::AesCbcHmac { iv, ct, mac } => {
                write!(
                    f,
                    "2.{}|{}|{}",
                    B64.encode(iv),
                    B64.encode(ct),
                    B64.encode(mac)
                )
            }
            EncString::Rsa { kind, ct } => write!(f, "{kind}.{}", B64.encode(ct)),
        }
    }
}

/// Key derivation settings, as reported by the server at prelogin.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "type")]
pub enum Kdf {
    Pbkdf2 {
        iterations: u32,
    },
    Argon2id {
        iterations: u32,
        memory_mib: u32,
        parallelism: u32,
    },
}

impl Kdf {
    /// Builds settings from Bitwarden's numeric fields, checking the ranges
    /// Hushjar supports. Out-of-range settings are refused, never adjusted.
    pub fn from_server(
        kind: u8,
        iterations: u32,
        memory: Option<u32>,
        parallelism: Option<u32>,
    ) -> Result<Self, CryptoError> {
        let kdf = match kind {
            0 => Kdf::Pbkdf2 { iterations },
            1 => Kdf::Argon2id {
                iterations,
                memory_mib: memory.ok_or(CryptoError::UnsupportedKdf)?,
                parallelism: parallelism.ok_or(CryptoError::UnsupportedKdf)?,
            },
            _ => return Err(CryptoError::UnsupportedKdf),
        };
        kdf.validate()?;
        Ok(kdf)
    }

    pub fn validate(&self) -> Result<(), CryptoError> {
        let ok = match *self {
            Kdf::Pbkdf2 { iterations } => (5_000..=2_000_000).contains(&iterations),
            Kdf::Argon2id {
                iterations,
                memory_mib,
                parallelism,
            } => {
                (2..=10).contains(&iterations)
                    && (16..=1024).contains(&memory_mib)
                    && (1..=16).contains(&parallelism)
            }
        };
        if ok {
            Ok(())
        } else {
            Err(CryptoError::UnsupportedKdf)
        }
    }
}

/// Bitwarden normalises the email address before using it as a salt.
pub fn normalize_email(email: &str) -> String {
    email.trim().to_lowercase()
}

/// Derives the 32-byte master key from the master password.
pub fn master_key(
    password: &str,
    email: &str,
    kdf: Kdf,
) -> Result<Zeroizing<[u8; 32]>, CryptoError> {
    derive_kdf(password, normalize_email(email).as_bytes(), kdf)
}

/// Runs the account's key derivation over a password and a salt. For
/// PBKDF2 the salt is used as given; for Argon2id Bitwarden hashes it with
/// SHA-256 first. Used with the email as salt for master keys, and with a
/// random salt for password-protected exports.
pub fn derive_kdf(
    password: &str,
    salt: &[u8],
    kdf: Kdf,
) -> Result<Zeroizing<[u8; 32]>, CryptoError> {
    kdf.validate()?;
    let mut out = Zeroizing::new([0u8; 32]);
    match kdf {
        Kdf::Pbkdf2 { iterations } => {
            pbkdf2::pbkdf2_hmac::<Sha256>(password.as_bytes(), salt, iterations, &mut out[..]);
        }
        Kdf::Argon2id {
            iterations,
            memory_mib,
            parallelism,
        } => {
            let salt = Sha256::digest(salt);
            let params = argon2::Params::new(memory_mib * 1024, iterations, parallelism, Some(32))
                .map_err(|_| CryptoError::UnsupportedKdf)?;
            argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params)
                .hash_password_into(password.as_bytes(), &salt, &mut out[..])
                .map_err(|_| CryptoError::UnsupportedKdf)?;
        }
    }
    Ok(out)
}

/// What a password hash proves. The server hash is sent at login; the local
/// hash is never sent anywhere.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HashPurpose {
    Server = 1,
    Local = 2,
}

/// The master password hash: one or two PBKDF2-SHA256 rounds keyed by the
/// master key and salted with the password, base64 encoded.
pub fn password_hash(master: &[u8; 32], password: &str, purpose: HashPurpose) -> Zeroizing<String> {
    let mut out = Zeroizing::new([0u8; 32]);
    pbkdf2::pbkdf2_hmac::<Sha256>(
        &master[..],
        password.as_bytes(),
        purpose as u32,
        &mut out[..],
    );
    Zeroizing::new(B64.encode(&out[..]))
}

/// Stretches the master key into a full symmetric key with HKDF-Expand.
pub fn stretch(master: &[u8; 32]) -> SymmetricKey {
    let hk = Hkdf::<Sha256>::from_prk(&master[..]).expect("32-byte PRK is valid");
    let mut both = Zeroizing::new([0u8; 64]);
    hk.expand(b"enc", &mut both[..32]).expect("valid length");
    hk.expand(b"mac", &mut both[32..]).expect("valid length");
    SymmetricKey::from_bytes(&both[..]).expect("64 bytes")
}

/// An account's RSA private key, used to open organisation keys.
pub struct PrivateKey(rsa::PrivateKey);

impl fmt::Debug for PrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PrivateKey([redacted])")
    }
}

impl PrivateKey {
    /// Decrypts the account's private key (PKCS#8 DER) with the user key.
    pub fn unwrap(user_key: &SymmetricKey, wrapped: &str) -> Result<Self, CryptoError> {
        use rsa::pkcs8::DecodePrivateKey;
        let der = user_key.decrypt(&wrapped.parse()?)?;
        rsa::PrivateKey::from_pkcs8_der(&der)
            .map(Self)
            .map_err(|_| CryptoError::Rsa)
    }

    /// Opens an organisation key shared with this account (type 4).
    pub fn unwrap_key(&self, wrapped: &str) -> Result<SymmetricKey, CryptoError> {
        match wrapped.parse()? {
            EncString::Rsa { kind: 4, ct } => {
                let plain = Zeroizing::new(
                    self.0
                        .oaep_decrypt::<sha1::Sha1>(&ct)
                        .map_err(|_| CryptoError::Rsa)?,
                );
                SymmetricKey::from_bytes(&plain)
            }
            EncString::Rsa { kind, .. } => Err(CryptoError::UnsupportedType(kind)),
            EncString::AesCbcHmac { .. } => Err(CryptoError::UnsupportedType(2)),
        }
    }
}

/// Hushjar's own local format: AES-256-GCM with a random 12-byte nonce.
/// Layout: version byte 1, nonce, ciphertext with tag. `aad` binds the
/// envelope to where it is stored.
pub fn seal(key: &[u8; 32], aad: &[u8], plaintext: &[u8]) -> Vec<u8> {
    let cipher = Aes256Gcm::new(key.into());
    let nonce_bytes = random_bytes::<12>();
    let nonce = Nonce::from(nonce_bytes);
    let ct = cipher
        .encrypt(
            &nonce,
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .expect("AES-GCM encryption of in-memory data");
    let mut out = Vec::with_capacity(1 + 12 + ct.len());
    out.push(1);
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ct);
    out
}

pub fn open(
    key: &[u8; 32],
    aad: &[u8],
    envelope: &[u8],
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    if envelope.len() < 1 + 12 + 16 || envelope[0] != 1 {
        return Err(CryptoError::Malformed);
    }
    let cipher = Aes256Gcm::new(key.into());
    let nonce_bytes: [u8; 12] = envelope[1..13].try_into().expect("12 bytes");
    let nonce = Nonce::from(nonce_bytes);
    cipher
        .decrypt(
            &nonce,
            Payload {
                msg: &envelope[13..],
                aad,
            },
        )
        .map(Zeroizing::new)
        .map_err(|_| CryptoError::Authentication)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_and_tamper() {
        let key = SymmetricKey::generate();
        let enc = key.encrypt(b"hello hushjar");
        let text = enc.to_string();
        assert_eq!(
            &key.decrypt(&text.parse().unwrap()).unwrap()[..],
            b"hello hushjar"
        );
        let EncString::AesCbcHmac { iv, mut ct, mac } = enc else {
            unreachable!()
        };
        ct[0] ^= 1;
        let tampered = EncString::AesCbcHmac { iv, ct, mac };
        assert_eq!(key.decrypt(&tampered), Err(CryptoError::Authentication));
        let other = SymmetricKey::generate();
        assert_eq!(
            other.decrypt(&text.parse().unwrap()),
            Err(CryptoError::Authentication)
        );
    }

    #[test]
    fn rejects_malformed_and_unknown_types() {
        for bad in [
            "",
            "2.",
            "2.AAAA|BBBB",
            "x.AAAA",
            "2.!!|!!|!!",
            "0.AAAA|AAAA",
        ] {
            assert!(bad.parse::<EncString>().is_err(), "{bad}");
        }
        assert_eq!(
            "7.AAAA".parse::<EncString>(),
            Err(CryptoError::UnsupportedType(7))
        );
    }

    #[test]
    fn local_envelope_binds_context() {
        let key = random_bytes::<32>();
        let sealed = seal(&key, b"account-a", b"cache");
        assert_eq!(&open(&key, b"account-a", &sealed).unwrap()[..], b"cache");
        assert!(open(&key, b"account-b", &sealed).is_err());
    }

    #[test]
    fn debug_redacts_keys() {
        assert_eq!(
            format!("{:?}", SymmetricKey::generate()),
            "SymmetricKey([redacted])"
        );
    }

    #[test]
    fn kdf_ranges() {
        assert!(Kdf::from_server(0, 600_000, None, None).is_ok());
        assert!(Kdf::from_server(0, 100, None, None).is_err());
        assert!(Kdf::from_server(1, 3, Some(64), Some(4)).is_ok());
        assert!(Kdf::from_server(1, 3, Some(4096), Some(4)).is_err());
        assert!(Kdf::from_server(1, 3, None, Some(4)).is_err());
        assert!(Kdf::from_server(9, 3, None, None).is_err());
    }
}

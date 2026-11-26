//! Bitwarden fingerprint phrases: five words from the EFF long list that
//! stand in for an account's identity key or a login request.
//!
//! Bitwarden shows the same phrase wherever two parties must confirm a key
//! out of band. The algorithm follows Bitwarden's Rust SDK,
//! <https://raw.githubusercontent.com/bitwarden/sdk-internal/main/crates/bitwarden-crypto/src/fingerprint.rs>:
//! HKDF-Expand (SHA-256) with the key as PRK and the fingerprint material as
//! info, then five base-7776 digits of the result read off the EFF list.
//!
//! The SDK feeds the raw SubjectPublicKeyInfo DER straight to `from_prk`;
//! the TypeScript clients hash it first. HMAC-SHA256 pre-hashes any key
//! longer than its 64-byte block, and an RSA SPKI DER is always longer, so
//! the two agree — Hushjar hashes first, as the clients do.

use hkdf::Hkdf;
use sha2::{Digest, Sha256};

use crate::wordlist::eff_long;

/// Turns the 32-byte hash into `ceil(64 / log2(list))` = 5 words: each word
/// is the remainder of the hash read as a big-endian integer divided by the
/// list size, like the SDK's `hash_word`.
fn hash_word(hash: [u8; 32]) -> String {
    const MINIMUM_ENTROPY_BITS: f64 = 64.0;

    let list = eff_long();
    let entropy_per_word = (list.len() as f64).log2();
    let num_words = (MINIMUM_ENTROPY_BITS / entropy_per_word).ceil() as usize;
    // The SDK's EntropyTooSmall check: a 32-byte hash holds 128 bits.
    assert!(
        num_words as f64 * entropy_per_word <= 128.0,
        "word list too small to show {num_words} words from a 32-byte hash"
    );

    let mut digits = hash;
    let mut words = Vec::with_capacity(num_words);
    for _ in 0..num_words {
        let remainder = div_rem_by(list.len() as u64, &mut digits);
        words.push(list[remainder as usize]);
    }
    words.join("-")
}

/// Divides the big-endian number in `digits` in place by `divisor`,
/// returning the remainder. Long division by hand; `carry * 256 + byte`
/// fits in `u64` for any divisor below 2^56.
fn div_rem_by(divisor: u64, digits: &mut [u8]) -> u64 {
    let mut carry: u64 = 0;
    for digit in digits.iter_mut() {
        let current = carry * 256 + u64::from(*digit);
        *digit = (current / divisor) as u8;
        carry = current % divisor;
    }
    carry
}

/// The fingerprint phrase for `fingerprint_material` and an RSA public key
/// in SubjectPublicKeyInfo DER form. The material is the user's id for an
/// account fingerprint, or the email for a login request.
pub fn phrase(fingerprint_material: &str, public_key_der: &[u8]) -> String {
    let key_fingerprint = Sha256::digest(public_key_der);
    let hk = Hkdf::<Sha256>::from_prk(&key_fingerprint[..]).expect("32-byte PRK is valid");
    let mut hash = [0u8; 32];
    hk.expand(fingerprint_material.as_bytes(), &mut hash)
        .expect("32 bytes is a valid HKDF-Expand output length");
    hash_word(hash)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Vector copied verbatim from the SDK's own test in
    // crates/bitwarden-crypto/src/fingerprint.rs of
    // <https://github.com/bitwarden/sdk-internal> (test_fingerprint).
    const USER_ID: &str = "a09726a0-9590-49d1-a5f5-afe300b6a515";
    const PUBLIC_KEY_DER: &[u8] = &[
        48, 130, 1, 34, 48, 13, 6, 9, 42, 134, 72, 134, 247, 13, 1, 1, 1, 5, 0, 3, 130, 1, 15, 0,
        48, 130, 1, 10, 2, 130, 1, 1, 0, 187, 38, 44, 241, 110, 205, 89, 253, 25, 191, 126, 84,
        121, 202, 61, 223, 189, 244, 118, 212, 74, 139, 130, 97, 115, 164, 167, 106, 191, 188, 233,
        218, 196, 250, 187, 146, 125, 160, 150, 49, 198, 224, 176, 10, 0, 143, 99, 230, 232, 160,
        51, 104, 154, 211, 33, 80, 170, 4, 68, 80, 219, 115, 167, 114, 156, 227, 125, 193, 128,
        123, 39, 254, 191, 124, 63, 129, 44, 63, 18, 56, 161, 48, 158, 0, 27, 146, 2, 99, 136, 75,
        21, 135, 6, 118, 12, 26, 251, 184, 172, 249, 53, 78, 210, 46, 143, 17, 104, 202, 65, 173,
        229, 219, 233, 144, 163, 101, 216, 238, 152, 54, 158, 1, 195, 50, 203, 21, 226, 12, 82,
        170, 175, 170, 160, 21, 247, 248, 80, 97, 123, 0, 152, 116, 229, 126, 221, 199, 155, 194,
        192, 51, 207, 177, 240, 160, 84, 241, 41, 88, 176, 53, 111, 28, 173, 177, 232, 158, 22, 79,
        133, 152, 31, 32, 12, 196, 147, 58, 57, 50, 252, 208, 131, 150, 179, 132, 178, 150, 234,
        251, 143, 125, 163, 144, 20, 46, 71, 168, 252, 164, 86, 120, 124, 56, 252, 206, 210, 236,
        212, 139, 127, 189, 236, 40, 46, 2, 238, 13, 216, 40, 48, 85, 133, 229, 181, 155, 176, 217,
        241, 154, 153, 213, 112, 222, 72, 219, 197, 3, 219, 56, 77, 109, 47, 72, 251, 131, 36, 240,
        96, 169, 31, 82, 93, 166, 242, 3, 33, 213, 2, 3, 1, 0, 1,
    ];

    #[test]
    fn matches_the_sdk_vector() {
        assert_eq!(
            "turban-deftly-anime-chatroom-unselfish",
            phrase(USER_ID, PUBLIC_KEY_DER)
        );
    }

    #[test]
    fn five_words_from_the_eff_list() {
        let phrase = phrase("someone@example.com", PUBLIC_KEY_DER);
        let words: Vec<&str> = phrase.split('-').collect();
        assert_eq!(words.len(), 5);
        let list = eff_long();
        for word in words {
            assert!(list.contains(&word), "{word} not in the EFF list");
        }
    }

    #[test]
    fn long_division_matches_the_naive_way() {
        let value: u64 = 0x00_00_07_DD_05; // 515333
        let mut digits = value.to_be_bytes();
        let remainder = div_rem_by(7776, &mut digits);
        assert_eq!(remainder, value % 7776);
        assert_eq!(digits, (value / 7776).to_be_bytes());
    }
}

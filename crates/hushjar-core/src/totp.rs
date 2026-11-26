//! Time-based one-time passwords (RFC 6238) for verification codes.
//!
//! Accepts a bare base32 secret, an `otpauth://totp/...` URI, or a
//! `steam://` secret for Steam Guard. Validation follows VaultGoblin's
//! generator: 6 to 8 digits, a period of 1 to 300 seconds, SHA1, SHA256 or
//! SHA512, and exactly one value per query parameter.

use std::fmt;

use hmac::{Hmac, KeyInit, Mac};
use zeroize::Zeroizing;

const STEAM_CHARS: &[u8; 26] = b"23456789BCDFGHJKMNPQRTVWXY";

#[derive(Clone, PartialEq, Eq)]
pub struct Code {
    pub value: String,
    /// When this code stops being valid, in Unix seconds.
    pub expires_unix: u64,
    pub period: u64,
}

impl fmt::Debug for Code {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Code {{ value: [redacted], expires_unix: {}, period: {} }}",
            self.expires_unix, self.period
        )
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum TotpError {
    #[error("the verification code secret is empty or too long")]
    Length,
    #[error("the verification code address is not a valid otpauth URI")]
    Uri,
    #[error("unsupported number of digits or period")]
    Parameters,
    #[error("unsupported verification code algorithm")]
    Algorithm,
    #[error("the verification code secret is not valid base32")]
    Secret,
}

#[derive(Clone, Copy)]
enum Algorithm {
    Sha1,
    Sha256,
    Sha512,
}

/// Generates the code for `input` at `now_unix`.
pub fn generate(input: &str, now_unix: u64) -> Result<Code, TotpError> {
    if input.is_empty() || input.len() > 4096 {
        return Err(TotpError::Length);
    }
    let input = input.trim();
    let mut digits = 6u32;
    let mut period = 30u64;
    let mut algorithm = Algorithm::Sha1;
    let mut steam = false;
    let secret: String;

    if input.len() > 8 && input.is_char_boundary(8) && input[..8].eq_ignore_ascii_case("steam://") {
        steam = true;
        digits = 5;
        secret = input[8..].to_string();
    } else if input.contains("://") {
        let query = parse_otpauth(input)?;
        let get = |name: &str| {
            query
                .iter()
                .find(|(k, _)| k == name)
                .map(|(_, v)| v.as_str())
        };
        secret = get("secret").unwrap_or_default().to_string();
        if let Some(value) = get("digits") {
            digits = value.parse().map_err(|_| TotpError::Parameters)?;
        }
        if let Some(value) = get("period") {
            period = value.parse().map_err(|_| TotpError::Parameters)?;
        }
        if let Some(value) = get("algorithm") {
            algorithm = match value.to_ascii_uppercase().as_str() {
                "SHA1" => Algorithm::Sha1,
                "SHA256" => Algorithm::Sha256,
                "SHA512" => Algorithm::Sha512,
                _ => return Err(TotpError::Algorithm),
            };
        }
    } else {
        secret = input.to_string();
    }
    if !steam && (!(6..=8).contains(&digits) || !(1..=300).contains(&period)) {
        return Err(TotpError::Parameters);
    }

    let key = decode_base32(&secret).ok_or(TotpError::Secret)?;
    let counter = (now_unix / period).to_be_bytes();
    let sum = Zeroizing::new(match algorithm {
        Algorithm::Sha1 => hmac_bytes::<Hmac<sha1::Sha1>>(&key, &counter),
        Algorithm::Sha256 => hmac_bytes::<Hmac<sha2::Sha256>>(&key, &counter),
        Algorithm::Sha512 => hmac_bytes::<Hmac<sha2::Sha512>>(&key, &counter),
    });
    let offset = (sum[sum.len() - 1] & 15) as usize;
    let mut number =
        u32::from_be_bytes(sum[offset..offset + 4].try_into().expect("4 bytes")) & 0x7fff_ffff;

    let value = if steam {
        let mut out = String::with_capacity(5);
        for _ in 0..5 {
            out.push(STEAM_CHARS[(number % 26) as usize] as char);
            number /= 26;
        }
        out
    } else {
        let modulus = 10u32.pow(digits);
        format!("{:0width$}", number % modulus, width = digits as usize)
    };
    Ok(Code {
        value,
        expires_unix: now_unix - now_unix % period + period,
        period,
    })
}

fn hmac_bytes<M: Mac + KeyInit>(key: &[u8], message: &[u8]) -> Vec<u8> {
    let mut mac = <M as KeyInit>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(message);
    mac.finalize().into_bytes().to_vec()
}

/// Parses an `otpauth://totp/label?query` URI into its query pairs.
fn parse_otpauth(uri: &str) -> Result<Vec<(String, String)>, TotpError> {
    let rest = uri.strip_prefix("otpauth://").ok_or(TotpError::Uri)?;
    if rest.contains('#') {
        return Err(TotpError::Uri);
    }
    let (authority_and_path, query) = rest.split_once('?').unwrap_or((rest, ""));
    let authority = authority_and_path.split('/').next().unwrap_or_default();
    if authority.contains('@') || !authority.eq_ignore_ascii_case("totp") {
        return Err(TotpError::Uri);
    }
    let mut pairs: Vec<(String, String)> = Vec::new();
    for part in query.split('&').filter(|p| !p.is_empty()) {
        let (key, value) = part.split_once('=').unwrap_or((part, ""));
        let key = percent_decode(key).ok_or(TotpError::Uri)?;
        let value = percent_decode(value).ok_or(TotpError::Uri)?;
        if pairs.iter().any(|(k, _)| *k == key) {
            return Err(TotpError::Uri);
        }
        pairs.push((key, value));
    }
    Ok(pairs)
}

fn percent_decode(text: &str) -> Option<String> {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' => {
                let hex = std::str::from_utf8(bytes.get(i + 1..i + 3)?).ok()?;
                out.push(u8::from_str_radix(hex, 16).ok()?);
                i += 3;
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8(out).ok()
}

/// Decodes RFC 4648 base32, ignoring spaces, case and trailing padding.
fn decode_base32(text: &str) -> Option<Zeroizing<Vec<u8>>> {
    let cleaned: String = text
        .chars()
        .filter(|c| *c != ' ')
        .collect::<String>()
        .to_ascii_uppercase();
    let cleaned = cleaned.trim_end_matches('=');
    let mut out = Zeroizing::new(Vec::with_capacity(cleaned.len() * 5 / 8));
    let mut buffer = 0u64;
    let mut bits = 0u32;
    for c in cleaned.bytes() {
        let value = match c {
            b'A'..=b'Z' => c - b'A',
            b'2'..=b'7' => c - b'2' + 26,
            _ => return None,
        };
        buffer = (buffer << 5) | value as u64;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((buffer >> bits) as u8);
            buffer &= (1 << bits) - 1;
        }
    }
    // Leftover bits must be zero padding, and fewer than five.
    if bits >= 5 || buffer != 0 || out.is_empty() {
        return None;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Expected values computed independently with Python's hmac and hashlib
    // for the RFC 6238 Appendix B secrets and times.
    const SHA1: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
    const SHA256: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA";
    const SHA512: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNA";
    const TIMES: [u64; 6] = [
        59,
        1111111109,
        1111111111,
        1234567890,
        2000000000,
        20000000000,
    ];

    fn check(secret: &str, algorithm: &str, expected: [&str; 6]) {
        let uri = format!("otpauth://totp/Test?secret={secret}&digits=8&algorithm={algorithm}");
        for (t, want) in TIMES.iter().zip(expected) {
            assert_eq!(
                generate(&uri, *t).unwrap().value,
                want,
                "{algorithm} at {t}"
            );
        }
    }

    #[test]
    fn rfc6238_vectors() {
        check(
            SHA1,
            "SHA1",
            [
                "94287082", "07081804", "14050471", "89005924", "69279037", "65353130",
            ],
        );
        check(
            SHA256,
            "SHA256",
            [
                "46119246", "68084774", "67062674", "91819424", "90698825", "77737706",
            ],
        );
        check(
            SHA512,
            "SHA512",
            [
                "90693936", "25091201", "99943326", "93441116", "38618901", "47863826",
            ],
        );
    }

    #[test]
    fn bare_secret_defaults() {
        let code = generate("jbsw y3dp ehpk 3pxp", 1_700_000_000).unwrap();
        assert_eq!(code.value, "324550");
        assert_eq!(code.period, 30);
        assert_eq!(code.expires_unix, 1_700_000_010);
    }

    #[test]
    fn steam_codes() {
        assert_eq!(
            generate("steam://JBSWY3DPEHPK3PXP", 1_700_000_000)
                .unwrap()
                .value,
            "2KM2P"
        );
    }

    #[test]
    fn rejects_bad_input() {
        let bad = [
            ("", TotpError::Length),
            ("not base32!", TotpError::Secret),
            ("otpauth://hotp/x?secret=JBSWY3DP", TotpError::Uri),
            ("otpauth://user@totp/x?secret=JBSWY3DP", TotpError::Uri),
            ("otpauth://totp/x?secret=JBSWY3DP#frag", TotpError::Uri),
            (
                "otpauth://totp/x?secret=JBSWY3DP&secret=JBSWY3DP",
                TotpError::Uri,
            ),
            (
                "otpauth://totp/x?secret=JBSWY3DP&digits=9",
                TotpError::Parameters,
            ),
            (
                "otpauth://totp/x?secret=JBSWY3DP&period=0",
                TotpError::Parameters,
            ),
            (
                "otpauth://totp/x?secret=JBSWY3DP&algorithm=MD5",
                TotpError::Algorithm,
            ),
            ("otpauth://totp/x?digits=6", TotpError::Secret),
        ];
        for (input, error) in bad {
            assert_eq!(generate(input, 0).unwrap_err(), error, "{input}");
        }
    }

    #[test]
    fn debug_hides_the_code() {
        let code = generate("JBSWY3DPEHPK3PXP", 1_700_000_000).unwrap();
        assert!(!format!("{code:?}").contains(&code.value));
    }
}

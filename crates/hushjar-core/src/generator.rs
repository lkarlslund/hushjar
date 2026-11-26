//! Bitwarden-compatible password, passphrase and username generation.
//!
//! Options, defaults, character sets and validation mirror Bitwarden's Rust
//! SDK in <https://github.com/bitwarden/sdk-internal>, crate
//! `bitwarden-generators`: `src/password.rs`, `src/passphrase.rs` and
//! `src/username.rs`. Random numbers come from the operating system via
//! rejection sampling, and the guaranteed characters are shuffled with
//! Fisher–Yates.
//!
//! One deliberate difference from the SDK: its minimum counts are `Option`
//! and an enabled character set without a user-set minimum gets one
//! character; here a minimum of `0` means "no guarantee", and
//! `PasswordOptions::default` puts a `1` in each enabled set's minimum so
//! the default behaviour still matches.

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::wordlist::eff_long;

/// Smallest password length accepted by Bitwarden clients
/// (`MINIMUM_PASSWORD_LENGTH` in the SDK's `password.rs`).
pub const MINIMUM_PASSWORD_LENGTH: u8 = 5;
/// Largest password length accepted by Bitwarden clients
/// (`MAXIMUM_PASSWORD_LENGTH` in the SDK's `password.rs`).
pub const MAXIMUM_PASSWORD_LENGTH: u8 = 128;
/// Smallest word count for a passphrase
/// (`MINIMUM_PASSPHRASE_NUM_WORDS` in the SDK's `passphrase.rs`).
pub const MINIMUM_PASSPHRASE_NUM_WORDS: u8 = 3;
/// Largest word count for a passphrase
/// (`MAXIMUM_PASSPHRASE_NUM_WORDS` in the SDK's `passphrase.rs`).
pub const MAXIMUM_PASSPHRASE_NUM_WORDS: u8 = 20;

/// Default password length (`DEFAULT_PASSWORD_LENGTH` in the SDK).
const DEFAULT_PASSWORD_LENGTH: u8 = 16;
/// Special characters, exactly as in the SDK's `SPECIAL_CHARS`.
const SPECIAL_CHARS: [char; 8] = ['!', '@', '#', '$', '%', '^', '&', '*'];
/// Ambiguous characters dropped when `avoid_ambiguous` is set: `I`, `O` in
/// uppercase, `l` in lowercase, `0` and `1` in numbers (SDK `password.rs`).
const AMBIGUOUS_UPPER: [char; 2] = ['I', 'O'];
const AMBIGUOUS_LOWER: [char; 1] = ['l'];
const AMBIGUOUS_NUMBER: [char; 2] = ['0', '1'];
/// Alphabet for the random part of plus-addressed and catch-all usernames,
/// the SDK's `random_lowercase_string`.
const USERNAME_ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyz1234567890";

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum GeneratorError {
    #[error("no character set is enabled")]
    NoCharacterSetEnabled,
    #[error(
        "password length must be between {MINIMUM_PASSWORD_LENGTH} and {MAXIMUM_PASSWORD_LENGTH}"
    )]
    InvalidLength,
    #[error("the minimum character counts add up to more than the password length")]
    MinimumsExceedLength,
    #[error(
        "word count must be between {MINIMUM_PASSPHRASE_NUM_WORDS} and {MAXIMUM_PASSPHRASE_NUM_WORDS}"
    )]
    InvalidNumWords,
}

/// Options for [`password`]. The `Default` mirrors Bitwarden's: length 16,
/// lowercase, uppercase and numbers on, special off, ambiguous allowed, and
/// one guaranteed character per enabled set.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct PasswordOptions {
    pub length: u8,
    pub lowercase: bool,
    pub uppercase: bool,
    pub numbers: bool,
    pub special: bool,
    pub min_lowercase: u8,
    pub min_uppercase: u8,
    pub min_number: u8,
    pub min_special: u8,
    pub avoid_ambiguous: bool,
}

impl Default for PasswordOptions {
    fn default() -> Self {
        Self {
            length: DEFAULT_PASSWORD_LENGTH,
            lowercase: true,
            uppercase: true,
            numbers: true,
            special: false,
            min_lowercase: 1,
            min_uppercase: 1,
            min_number: 1,
            min_special: 0,
            avoid_ambiguous: false,
        }
    }
}

/// Options for [`passphrase`]. The `Default` mirrors the SDK's: three words
/// joined by single spaces, no capitalisation, no number.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct PassphraseOptions {
    pub num_words: u8,
    pub word_separator: String,
    pub capitalize: bool,
    pub include_number: bool,
}

impl Default for PassphraseOptions {
    fn default() -> Self {
        Self {
            num_words: 3,
            word_separator: " ".to_string(),
            capitalize: false,
            include_number: false,
        }
    }
}

/// Options for [`username`], the three locally generated types from the
/// SDK's `username.rs`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum UsernameOptions {
    /// A single EFF word, optionally capitalised and with a four-digit
    /// number appended.
    Word {
        capitalize: bool,
        include_number: bool,
    },
    /// `local+<8 random chars>@domain`, for providers with subaddressing.
    /// A malformed email is returned unchanged, as the SDK does.
    PlusAddressed { email: String },
    /// `<8 random chars>@domain`, for a catch-all domain. An empty domain
    /// is returned unchanged, as the SDK does.
    CatchAll { domain: String },
}

/// Generates a password. The guaranteed minimum characters are drawn first
/// from their own sets, the rest from the union, then everything is
/// shuffled; the result is zeroised on drop.
pub fn password(options: &PasswordOptions) -> Result<Zeroizing<String>, GeneratorError> {
    if !(options.lowercase || options.uppercase || options.numbers || options.special) {
        return Err(GeneratorError::NoCharacterSetEnabled);
    }
    if !(MINIMUM_PASSWORD_LENGTH..=MAXIMUM_PASSWORD_LENGTH).contains(&options.length) {
        return Err(GeneratorError::InvalidLength);
    }

    let lower = alphabet(
        options.lowercase,
        'a'..='z',
        &AMBIGUOUS_LOWER,
        options.avoid_ambiguous,
    );
    let upper = alphabet(
        options.uppercase,
        'A'..='Z',
        &AMBIGUOUS_UPPER,
        options.avoid_ambiguous,
    );
    let number = alphabet(
        options.numbers,
        '0'..='9',
        &AMBIGUOUS_NUMBER,
        options.avoid_ambiguous,
    );
    let special = alphabet(options.special, SPECIAL_CHARS, &[], options.avoid_ambiguous);

    // Minimums for disabled sets are ignored, like the SDK's get_minimum.
    let mins = [
        (
            &lower,
            if options.lowercase {
                options.min_lowercase
            } else {
                0
            },
        ),
        (
            &upper,
            if options.uppercase {
                options.min_uppercase
            } else {
                0
            },
        ),
        (
            &number,
            if options.numbers {
                options.min_number
            } else {
                0
            },
        ),
        (
            &special,
            if options.special {
                options.min_special
            } else {
                0
            },
        ),
    ];
    let length = usize::from(options.length);
    if mins.iter().map(|(_, n)| usize::from(*n)).sum::<usize>() > length {
        return Err(GeneratorError::MinimumsExceedLength);
    }

    let mut chars: Vec<char> = Vec::with_capacity(length);
    for (set, count) in &mins {
        for _ in 0..*count {
            chars.push(set[random_below(set.len() as u32) as usize]);
        }
    }
    let all: Vec<char> = lower
        .iter()
        .chain(&upper)
        .chain(&number)
        .chain(&special)
        .copied()
        .collect();
    while chars.len() < length {
        chars.push(all[random_below(all.len() as u32) as usize]);
    }
    shuffle(&mut chars);
    Ok(Zeroizing::new(chars.into_iter().collect()))
}

/// Generates a passphrase from the EFF long list. Words that contain a
/// hyphen are skipped so the separator stays unambiguous, as in the SDK's
/// `gen_words`. With `include_number` a single digit is appended to one
/// random word, then capitalisation runs, then the join — the SDK's order.
pub fn passphrase(options: &PassphraseOptions) -> Result<Zeroizing<String>, GeneratorError> {
    if !(MINIMUM_PASSPHRASE_NUM_WORDS..=MAXIMUM_PASSPHRASE_NUM_WORDS).contains(&options.num_words) {
        return Err(GeneratorError::InvalidNumWords);
    }
    let list: Vec<&'static str> = eff_long()
        .iter()
        .copied()
        .filter(|w| !w.contains('-'))
        .collect();
    let mut words: Vec<String> = (0..options.num_words)
        .map(|_| list[random_below(list.len() as u32) as usize].to_string())
        .collect();
    if options.include_number {
        let index = random_below(words.len() as u32) as usize;
        words[index].push(char::from(b'0' + random_below(10) as u8));
    }
    if options.capitalize {
        for word in &mut words {
            *word = capitalize_first_letter(word);
        }
    }
    Ok(Zeroizing::new(words.join(&options.word_separator)))
}

/// Generates a username. Local generation cannot fail, so the `Result` is
/// always `Ok`; it exists to keep the API of the three generators uniform.
pub fn username(options: &UsernameOptions) -> Result<String, GeneratorError> {
    Ok(match options {
        UsernameOptions::Word {
            capitalize,
            include_number,
        } => {
            let list = eff_long();
            let mut word = list[random_below(list.len() as u32) as usize].to_string();
            if *capitalize {
                word = capitalize_first_letter(&word);
            }
            if *include_number {
                // A four-digit number with leading zeros, the SDK's random_number.
                word.push_str(&format!("{:04}", random_below(10_000)));
            }
            word
        }
        UsernameOptions::PlusAddressed { email } => {
            if email.len() < 3 {
                email.clone()
            } else {
                match email.find('@') {
                    Some(at) if at > 0 && at < email.len() - 1 => {
                        let (local, domain) = email.split_once('@').expect("checked for '@'");
                        format!("{local}+{}@{domain}", random_username_part(8))
                    }
                    _ => email.clone(),
                }
            }
        }
        UsernameOptions::CatchAll { domain } => {
            if domain.is_empty() {
                domain.clone()
            } else {
                format!("{}@{domain}", random_username_part(8))
            }
        }
    })
}

/// Characters of one set: `base` with the ambiguous ones dropped when
/// `avoid_ambiguous` is set, empty when the set is disabled.
fn alphabet(
    enabled: bool,
    base: impl IntoIterator<Item = char>,
    ambiguous: &[char],
    avoid_ambiguous: bool,
) -> Vec<char> {
    if !enabled {
        return Vec::new();
    }
    base.into_iter()
        .filter(|c| !(avoid_ambiguous && ambiguous.contains(c)))
        .collect()
}

/// The SDK's `capitalize_first_letter`: uppercasing can change length, so
/// rebuild from the first character rather than editing in place.
fn capitalize_first_letter(word: &str) -> String {
    let mut chars = word.chars();
    match chars.next() {
        None => String::new(),
        Some(first) => first.to_uppercase().collect::<String>() + chars.as_str(),
    }
}

fn random_username_part(length: usize) -> String {
    (0..length)
        .map(|_| USERNAME_ALPHABET[random_below(USERNAME_ALPHABET.len() as u32) as usize] as char)
        .collect()
}

/// A uniform value in `0..bound`, free of modulo bias: values from the
/// incomplete last residue class of the 2^32 outputs are rejected and
/// drawn again. `bound` must not be zero.
fn random_below(bound: u32) -> u32 {
    debug_assert!(bound > 0, "random_below called with bound 0");
    if bound == 1 {
        return 0;
    }
    // Largest multiple of `bound` not exceeding u32::MAX.
    let limit = u32::MAX - u32::MAX % bound;
    let mut buf = [0u8; 4];
    loop {
        getrandom::fill(&mut buf).expect("operating system random source");
        let value = u32::from_be_bytes(buf);
        if value < limit {
            return value % bound;
        }
    }
}

/// Fisher–Yates: swap each position with a uniformly chosen earlier one.
fn shuffle<T>(items: &mut [T]) {
    for i in (1..items.len()).rev() {
        let j = random_below(i as u32 + 1) as usize;
        items.swap(i, j);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    fn all_sets(length: u8) -> PasswordOptions {
        PasswordOptions {
            length,
            lowercase: true,
            uppercase: true,
            numbers: true,
            special: true,
            ..Default::default()
        }
    }

    fn count(password: &str, set: impl Fn(char) -> bool) -> usize {
        password.chars().filter(|c| set(*c)).count()
    }

    #[test]
    fn defaults_match_bitwarden() {
        let options = PasswordOptions::default();
        assert_eq!(options.length, 16);
        assert!(options.lowercase && options.uppercase && options.numbers);
        assert!(!options.special && !options.avoid_ambiguous);
        assert_eq!(options.min_lowercase, 1);
        assert_eq!(options.min_uppercase, 1);
        assert_eq!(options.min_number, 1);
        let pass = password(&options).unwrap();
        assert_eq!(pass.chars().count(), 16);
        assert!(count(&pass, |c| c.is_ascii_lowercase()) >= 1);
        assert!(count(&pass, |c| c.is_ascii_uppercase()) >= 1);
        assert!(count(&pass, |c| c.is_ascii_digit()) >= 1);
    }

    #[test]
    fn lengths_across_the_allowed_range() {
        for length in [MINIMUM_PASSWORD_LENGTH, 8, 16, 64, MAXIMUM_PASSWORD_LENGTH] {
            let pass = password(&all_sets(length)).unwrap();
            assert_eq!(pass.chars().count(), usize::from(length), "length {length}");
        }
    }

    #[test]
    fn pools_hold_only_the_enabled_characters() {
        let pass = password(&PasswordOptions {
            lowercase: false,
            uppercase: false,
            numbers: true,
            special: false,
            length: 32,
            ..Default::default()
        })
        .unwrap();
        assert!(pass.chars().all(|c| c.is_ascii_digit()));
        assert_eq!(count(&pass, |c| !c.is_ascii_digit()), 0);
    }

    #[test]
    fn minimums_are_respected_over_200_runs() {
        let options = PasswordOptions {
            length: 20,
            lowercase: true,
            uppercase: true,
            numbers: true,
            special: true,
            min_lowercase: 3,
            min_uppercase: 4,
            min_number: 5,
            min_special: 6,
            avoid_ambiguous: false,
        };
        for _ in 0..200 {
            let secret = password(&options).unwrap();
            let pass = secret.as_str();
            assert_eq!(pass.chars().count(), 20);
            assert!(count(pass, |c| c.is_ascii_lowercase()) >= 3, "{pass}");
            assert!(count(pass, |c| c.is_ascii_uppercase()) >= 4, "{pass}");
            assert!(count(pass, |c| c.is_ascii_digit()) >= 5, "{pass}");
            assert!(count(pass, |c| "|@#$%^&*!".contains(c)) >= 6, "{pass}");
        }
    }

    #[test]
    fn ambiguous_characters_are_absent_when_avoided() {
        let options = PasswordOptions {
            avoid_ambiguous: true,
            ..all_sets(16)
        };
        for _ in 0..200 {
            let secret = password(&options).unwrap();
            let pass = secret.as_str();
            for c in ['I', 'O', 'l', '0', '1'] {
                assert!(!pass.contains(c), "{c} in {pass}");
            }
        }
    }

    #[test]
    fn minimums_of_disabled_sets_are_ignored() {
        // Like the SDK: a minimum on a disabled set counts for nothing.
        let options = PasswordOptions {
            min_number: 9,
            min_special: 9,
            ..Default::default()
        };
        assert!(password(&options).is_ok());
    }

    #[test]
    fn error_cases() {
        let no_sets = PasswordOptions {
            lowercase: false,
            uppercase: false,
            numbers: false,
            special: false,
            ..Default::default()
        };
        assert_eq!(
            password(&no_sets).unwrap_err(),
            GeneratorError::NoCharacterSetEnabled
        );
        assert_eq!(
            password(&all_sets(MINIMUM_PASSWORD_LENGTH - 1)).unwrap_err(),
            GeneratorError::InvalidLength
        );
        assert_eq!(
            password(&all_sets(MAXIMUM_PASSWORD_LENGTH + 1)).unwrap_err(),
            GeneratorError::InvalidLength
        );
        let too_many_minimums = PasswordOptions {
            length: 5,
            min_lowercase: 3,
            min_uppercase: 3,
            ..Default::default()
        };
        assert_eq!(
            password(&too_many_minimums).unwrap_err(),
            GeneratorError::MinimumsExceedLength
        );
    }

    #[test]
    fn passphrase_shape() {
        let options = PassphraseOptions {
            num_words: 4,
            word_separator: "-".to_string(),
            capitalize: false,
            include_number: false,
        };
        for _ in 0..50 {
            let secret = passphrase(&options).unwrap();
            let phrase = secret.as_str();
            let words: Vec<&str> = phrase.split('-').collect();
            assert_eq!(words.len(), 4, "{phrase}");
            for word in words {
                assert!(eff_long().contains(&word), "{word} not in the list");
            }
        }
        // Default separator is a single space.
        let phrase = passphrase(&PassphraseOptions::default()).unwrap();
        assert_eq!(phrase.split(' ').count(), 3);
        // A multi-character separator works, as in the SDK's tests.
        let phrase = passphrase(&PassphraseOptions {
            word_separator: "::".to_string(),
            ..Default::default()
        })
        .unwrap();
        assert_eq!(phrase.split("::").count(), 3);
    }

    #[test]
    fn passphrase_uses_no_hyphenated_words() {
        // Words with hyphens would make a hyphen separator ambiguous.
        let options = PassphraseOptions {
            num_words: 20,
            word_separator: "-".to_string(),
            ..Default::default()
        };
        let phrase = passphrase(&options).unwrap();
        assert_eq!(phrase.split('-').count(), 20);
    }

    #[test]
    fn passphrase_capitalize_and_number() {
        let options = PassphraseOptions {
            num_words: 5,
            word_separator: ".".to_string(),
            capitalize: true,
            include_number: true,
        };
        for _ in 0..50 {
            let secret = passphrase(&options).unwrap();
            let phrase = secret.as_str();
            let words: Vec<&str> = phrase.split('.').collect();
            assert_eq!(words.len(), 5, "{phrase}");
            for word in &words {
                assert!(
                    word.starts_with(char::is_uppercase),
                    "{word} not capitalized"
                );
            }
            // Exactly one digit across the whole phrase: the SDK appends a
            // single digit to one random word.
            let digits: Vec<char> = phrase.chars().filter(|c| c.is_ascii_digit()).collect();
            assert_eq!(digits.len(), 1, "{phrase}");
            // Stripping it leaves plain list words.
            let stripped: Vec<String> = words
                .iter()
                .map(|w| {
                    w.trim_end_matches(|c: char| c.is_ascii_digit())
                        .to_lowercase()
                })
                .collect();
            for word in stripped {
                assert!(eff_long().contains(&word.as_str()), "{word}");
            }
        }
    }

    #[test]
    fn passphrase_error_cases() {
        assert_eq!(
            passphrase(&PassphraseOptions {
                num_words: MINIMUM_PASSPHRASE_NUM_WORDS - 1,
                ..Default::default()
            })
            .unwrap_err(),
            GeneratorError::InvalidNumWords
        );
        assert_eq!(
            passphrase(&PassphraseOptions {
                num_words: MAXIMUM_PASSPHRASE_NUM_WORDS + 1,
                ..Default::default()
            })
            .unwrap_err(),
            GeneratorError::InvalidNumWords
        );
    }

    #[test]
    fn username_word_shape() {
        let word = username(&UsernameOptions::Word {
            capitalize: false,
            include_number: false,
        })
        .unwrap();
        assert!(eff_long().contains(&word.as_str()), "{word}");

        let word = username(&UsernameOptions::Word {
            capitalize: true,
            include_number: false,
        })
        .unwrap();
        assert!(word.starts_with(char::is_uppercase));
        assert!(eff_long().contains(&word.to_lowercase().as_str()));

        let word = username(&UsernameOptions::Word {
            capitalize: false,
            include_number: true,
        })
        .unwrap();
        assert!(word.len() > 4);
        let (stem, digits) = word.split_at(word.len() - 4);
        assert!(digits.chars().all(|c| c.is_ascii_digit()), "{word}");
        assert!(eff_long().contains(&stem), "{stem}");
    }

    #[test]
    fn plus_addressed_shape() {
        let user = username(&UsernameOptions::PlusAddressed {
            email: "someone@example.com".to_string(),
        })
        .unwrap();
        assert!(user.starts_with("someone+"), "{user}");
        assert!(user.ends_with("@example.com"), "{user}");
        let middle = user
            .strip_prefix("someone+")
            .and_then(|s| s.strip_suffix("@example.com"))
            .expect("shape checked above");
        assert_eq!(middle.len(), 8);
        assert!(
            middle
                .chars()
                .all(|c| USERNAME_ALPHABET.contains(&(c as u32 as u8))),
            "{middle}"
        );
        // Malformed addresses pass through unchanged, as in the SDK.
        assert_eq!(
            username(&UsernameOptions::PlusAddressed {
                email: "no-at-sign".to_string()
            })
            .unwrap(),
            "no-at-sign"
        );
        assert_eq!(
            username(&UsernameOptions::PlusAddressed {
                email: "@example.com".to_string()
            })
            .unwrap(),
            "@example.com"
        );
    }

    #[test]
    fn catch_all_shape() {
        let user = username(&UsernameOptions::CatchAll {
            domain: "example.com".to_string(),
        })
        .unwrap();
        let (local, domain) = user.split_once('@').expect("has '@'");
        assert_eq!(domain, "example.com");
        assert_eq!(local.len(), 8);
        assert!(
            local
                .chars()
                .all(|c| USERNAME_ALPHABET.contains(&(c as u32 as u8))),
            "{local}"
        );
        assert_eq!(
            username(&UsernameOptions::CatchAll {
                domain: String::new()
            })
            .unwrap(),
            ""
        );
    }

    #[test]
    fn random_below_stays_in_range() {
        let mut seen = BTreeSet::new();
        for _ in 0..1000 {
            let value = random_below(7);
            assert!(value < 7);
            seen.insert(value);
        }
        // All seven residues after 1000 draws: a biased or broken sampler
        // would strand some of them.
        assert_eq!(seen.len(), 7);
        assert_eq!(random_below(1), 0);
    }

    #[test]
    fn options_round_trip_through_json() {
        let password_options = all_sets(20);
        let json = serde_json::to_string(&password_options).unwrap();
        assert_eq!(
            serde_json::from_str::<PasswordOptions>(&json).unwrap(),
            password_options
        );
        // #[serde(default)] fills in what the app left out.
        let sparse: PasswordOptions = serde_json::from_str(r#"{"length": 30}"#).unwrap();
        assert_eq!(
            sparse,
            PasswordOptions {
                length: 30,
                ..Default::default()
            }
        );
        let passphrase_options = PassphraseOptions {
            num_words: 6,
            word_separator: "-".to_string(),
            capitalize: true,
            include_number: true,
        };
        let json = serde_json::to_string(&passphrase_options).unwrap();
        assert_eq!(
            serde_json::from_str::<PassphraseOptions>(&json).unwrap(),
            passphrase_options
        );
        let username_options = UsernameOptions::PlusAddressed {
            email: "a@b.co".to_string(),
        };
        let json = serde_json::to_string(&username_options).unwrap();
        assert_eq!(
            serde_json::from_str::<UsernameOptions>(&json).unwrap(),
            username_options
        );
    }
}

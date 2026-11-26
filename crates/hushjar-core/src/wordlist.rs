//! The EFF long word list: 7776 words for passphrases and fingerprint
//! phrases, as used by Bitwarden.
//!
//! The list is the Electronic Frontier Foundation's
//! `eff_large_wordlist.txt` (<https://www.eff.org/dice>), stored in
//! `wordlist/eff_large_wordlist.txt` as plain words, one per line, and
//! attributed in `wordlist/NOTICE.md`.
//!
//! Provenance (fetched 2026-11-26): EFF's canonical URL
//! <https://www.eff.org/files/2016-07-18/eff_large_wordlist.txt> returned
//! HTTP 404 (the live `/dice` page still links it), so the dice-keyed file
//! (sha256 `addd35536511597a02fa0a9ff1e5284677b8883b83e986e43f15a3db996b903e`)
//! was taken byte-for-byte from three public mirrors listed in
//! `wordlist/NOTICE.md`. The words-only file kept here has sha256
//! `6d557f0693958fb5e650b68b5bee585eb82cf4da32965505c789e924743bc522` and
//! equals Bitwarden's bundled copy, `crates/bitwarden-crypto/src/wordlist.rs`
//! in <https://github.com/bitwarden/sdk-internal>.

use std::sync::LazyLock;

const EFF_LARGE: &str = include_str!("wordlist/eff_large_wordlist.txt");

static EFF_LONG: LazyLock<Vec<&'static str>> = LazyLock::new(|| EFF_LARGE.lines().collect());

/// The EFF long word list: 7776 words, ordered as the published file.
pub fn eff_long() -> &'static [&'static str] {
    &EFF_LONG
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn eff_long_is_the_published_list() {
        let words = eff_long();
        // Counts and boundary words checked against the downloaded file
        // (scratch/refs/icco_pw.txt) and Bitwarden's bundled copy.
        assert_eq!(words.len(), 7776);
        assert_eq!(words[0], "abacus");
        assert_eq!(words[7775], "zoom");
        assert!(words.iter().all(|w| !w.is_empty()));
    }
}

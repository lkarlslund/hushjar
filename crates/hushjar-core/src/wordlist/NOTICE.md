# Attribution for `eff_large_wordlist.txt`

- Work: the EFF large word list, 7776 words created and published by the
  Electronic Frontier Foundation as part of its dice-based passphrase
  guidance: <https://www.eff.org/dice>.
- License: Creative Commons Attribution 3.0 United States (CC BY 3.0 US),
  the licence the 2016 EFF word list pages were published under. EFF's
  current site-wide policy (<https://www.eff.org/copyright>) is Creative
  Commons Attribution (CC BY 4.0); both are permissive attribution licences.
- Original source file:
  <https://www.eff.org/files/2016-07-18/eff_large_wordlist.txt>, in dice-keyed
  format (`11111<TAB>abacus` .. `66666<TAB>zoom`). That URL returned HTTP 404
  when this copy was fetched on 2026-11-26 (the live /dice page still links
  it), so the bytes were taken from three public mirrors that are identical
  to each other:
  <https://raw.githubusercontent.com/icco/pw/master/eff_large_wordlist.txt>,
  <https://raw.githubusercontent.com/wadetb/dicebook/master/eff_large_wordlist.txt>
  and
  <https://raw.githubusercontent.com/ChristopherA/iambic-mnemonic/master/word-lists/eff_large_wordlist-7776.txt>,
  all sha256
  `addd35536511597a02fa0a9ff1e5284677b8883b83e986e43f15a3db996b903e`.
- The copy stored in this directory is that file with the dice keys removed,
  one word per line: sha256
  `6d557f0693958fb5e650b68b5bee585eb82cf4da32965505c789e924743bc522`. It
  matches Bitwarden's own bundled copy of the list,
  `crates/bitwarden-crypto/src/wordlist.rs` in
  <https://github.com/bitwarden/sdk-internal>, word for word.

# Hushjar

A desktop app for your secrets, written in Rust with [Slint](https://slint.dev).
It targets Linux on Wayland first, with Windows, macOS and Android to follow.

Hushjar replaces VaultGoblin, an earlier Go and Wails client for Bitwarden and
Vaultwarden. This is an early skeleton and does not handle secrets yet.

## Layout

- `crates/hushjar-core`: vault logic with no UI dependency.
- `crates/hushjar`: the Slint desktop app. UI files live in `crates/hushjar/ui`.

## Development

Requires Rust 1.95 or newer.

```sh
cargo run -p hushjar
cargo clippy --workspace --all-targets
cargo test --workspace
```

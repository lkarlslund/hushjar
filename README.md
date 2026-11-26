# Hushjar

A desktop app for your secrets, written in Rust with [Slint](https://slint.dev).
It targets Linux on Wayland first, with Windows, macOS and Android to follow.

Hushjar replaces VaultGoblin, an earlier Go and Wails client for Bitwarden and
Vaultwarden. It is currently a UI prototype with dummy data and does not
handle real secrets yet. The plan is in [docs/ui-plan.md](docs/ui-plan.md).

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

To save screenshots of the prototype's main states (only Hushjar's own window
is captured) and quit:

```sh
HUSHJAR_SNAPSHOT_DIR=/tmp/hushjar-shots cargo run -p hushjar --features snapshot
```

Set `HUSHJAR_COLOR_SCHEME=light` or `dark` to override the system theme.

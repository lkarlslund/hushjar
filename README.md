# Hushjar

A desktop app for your secrets, written in Rust with [Slint](https://slint.dev).
It works with Bitwarden and self-hosted Vaultwarden accounts, targets Linux on
Wayland first, and is meant to reach Windows, macOS and Android later. It
replaces VaultGoblin, an earlier Go and Wails client.

The plan, including a checklist of Bitwarden features, is in
[docs/ui-plan.md](docs/ui-plan.md).

## What works

- Several accounts at once, each on its own server (bitwarden.com, bitwarden.eu
  or self-hosted), with two-step login by authenticator app or email.
- Unlocking from an encrypted offline copy, then syncing in the background.
- A filterable tree grouped by folders, collections or types, and a details
  pane that switches to editing in place.
- Viewing and editing logins, cards, identities, notes and SSH keys, with
  custom fields, websites, password history, favourites, folders, trash and
  restore. Data Hushjar does not edit, such as passkeys and attachments, is
  kept unchanged.
- Verification codes, copying that is hidden from clipboard managers and
  cleared after 30 seconds, and locking after 15 minutes without activity.
- An SSH agent serving the vault's SSH keys, asking the first time or every
  time a key is used.

Not yet: the generator, Send, attachments, import and export, settings, and
organisation management. See the plan for the milestones.

## Layout

- `crates/hushjar-core`: crypto, API client, vault model, offline storage.
- `crates/hushjar-agent`: the OpenSSH agent.
- `crates/hushjar`: the Slint desktop app. UI files live in `crates/hushjar/ui`.

## Development

Requires Rust 1.95 or newer.

```sh
cargo run -p hushjar
cargo clippy --workspace --all-targets
cargo test --workspace
```

`HUSHJAR_DATA_DIR` overrides where accounts are stored (by default
`~/.local/share/hushjar` on Linux).

To show Hushjar with its name and icon in Linux desktops, build a release and
install its desktop entry for your user:

```sh
cargo build --release -p hushjar
scripts/install-desktop.sh            # --uninstall removes it
```

The SSH agent listens on `$XDG_RUNTIME_DIR/hushjar/ssh-agent.sock`. Click the
terminal icon in the top bar to copy the `SSH_AUTH_SOCK` line.

### Testing against Vaultwarden

`tests/interop` has a pinned Vaultwarden for end-to-end tests with invented
accounts; see its README. To try the app with sample data, seed a demo account
into a separate data folder and run against it:

```sh
HUSHJAR_INTEROP=http://127.0.0.1:18281 HUSHJAR_SEED_DIR=/tmp/hushjar-demo \
  cargo test -p hushjar-core --test interop seed_demo_account -- --ignored --nocapture
HUSHJAR_DATA_DIR=/tmp/hushjar-demo cargo run -p hushjar
```

The demo password is printed by the seeding test. To save screenshots of the
main states (only Hushjar's own window is captured):

```sh
HUSHJAR_DATA_DIR=/tmp/hushjar-demo HUSHJAR_SNAPSHOT_DIR=/tmp/hushjar-shots \
  HUSHJAR_SNAPSHOT_PASSWORD='hushjar demo password' cargo run -p hushjar --features snapshot
```

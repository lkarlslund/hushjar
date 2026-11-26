# Hushjar

A desktop app for your secrets, written in Rust with [Slint](https://slint.dev).
It works with Bitwarden and self-hosted Vaultwarden accounts. Linux on Wayland
is the primary target; Windows and macOS builds are set up and checked by CI
but have had little hands-on testing, and an early Android build runs. It
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

`HUSHJAR_DATA_DIR` overrides where accounts are stored. By default that is
`~/.local/share/hushjar` on Linux, `~/Library/Application Support/Hushjar` on
macOS, `%APPDATA%\Hushjar` on Windows and the app's private folder on
Android.

Windows narrower than 640 pixels, such as phones, show one pane at a time:
the tree, or the details with a back button, and the secondary top-bar
buttons move into a menu.

### Building on each system

- **Linux:** needs the usual Slint libraries (fontconfig, xkbcommon, Wayland or
  X11, OpenGL/EGL headers; see `.github/workflows/ci.yml` for the Debian
  package names). `scripts/package-linux.sh` builds a release and writes
  `dist/hushjar-<version>-linux-<arch>.tar.gz`, laid out as a prefix.
- **Windows:** needs the MSVC build tools (Visual Studio Build Tools with the
  C++ workload). `scripts/package-windows.ps1` writes
  `dist\hushjar-<version>-windows-x86_64.zip`; the icon is embedded in
  `hushjar.exe` by the build.
- **macOS:** needs the Xcode command line tools. `scripts/package-macos.sh`
  writes `dist/Hushjar-<version>-macos-<arch>.zip` containing `Hushjar.app`,
  signed ad hoc only (Gatekeeper asks on first launch).
- **Android:** needs the Rust targets (`rustup target add aarch64-linux-android
  x86_64-linux-android`), an Android SDK with a platform and build tools, the
  NDK and a JDK. `scripts/build-android.sh` builds the app as a shared library
  for arm64-v8a and x86_64 (or the ABIs named) and writes
  `dist/hushjar-<version>-android-debug.apk`, without Gradle; `--release`
  makes an optimised build, signed with `$ANDROID_KEYSTORE` when set. Install
  it with `adb install -r <apk>`. Not on Android yet: the SSH agent, file
  dialogs (so import, export and file Sends), the tray and other desktop
  services. To reach a Vaultwarden on the computer from the emulator, run
  `adb reverse tcp:18281 tcp:18281` and sign in to `http://127.0.0.1:18281`.
- `scripts/make-icons.sh` regenerates the committed `.ico`, `.icns` and Android
  launcher icons from `packaging/linux/io.github.lkarlslund.Hushjar.svg`.

Pushing a tag `v*` makes the release workflow build all three packages and
attach them to a draft GitHub release.

To show Hushjar with its name and icon in Linux desktops, build a release and
install its desktop entry for your user:

```sh
cargo build --release -p hushjar
scripts/install-desktop.sh            # --uninstall removes it
```

The SSH agent listens on `$XDG_RUNTIME_DIR/hushjar/ssh-agent.sock` (macOS:
under `$TMPDIR`). Click the terminal icon in the top bar to copy the
`SSH_AUTH_SOCK` line. On Windows it serves the named pipe
`\\.\pipe\openssh-ssh-agent`, which Windows OpenSSH uses without any setting;
stop the "OpenSSH Authentication Agent" service first, or set
`HUSHJAR_SSH_AGENT_PIPE` to another pipe name.

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

# Hushjar UI plan

Hushjar is a desktop app for secrets stored in Bitwarden or Vaultwarden. This
plan covers the main window, multiple accounts, how viewing and editing work,
and a checklist of the Bitwarden desktop features Hushjar must match.

The feature list is based on the official Bitwarden desktop client as of late
2026. Check it against the Bitwarden help centre before calling parity done.

## Principles

- **One window, two panes.** The left pane finds things, the right pane shows
  them. There are no modal dialogs for everyday work.
- **Viewing is safe, editing is one step away.** Items open read-only. Editing
  happens in place, in the same layout, so nothing jumps around.
- **Every account is visible at once.** Accounts are top-level branches of the
  tree. Each one locks, unlocks and syncs on its own, and search covers every
  unlocked account.
- **The keyboard is enough.** Every action has a shortcut, and the tree can be
  driven entirely with the arrow keys.
- **It fits small screens.** The layout must work down to roughly 1000×400
  logical pixels, and collapse to a single pane on phones later.
- **Secrets stay hidden until asked for.** Passwords, card numbers and other
  hidden fields are masked until revealed, and copying is preferred to revealing.

## Window layout

```
┌──────────────────────────────────────────────────────────────────────────────┐
│ ◉ Hushjar                     Synced 2 min ago ⟳   + New   ⚄   ✈   ⚙   🔒  │  top bar
├──────────────────────────┬───────────────────────────────────────────────────┤
│ 🔍 Filter          (12)  │ [🔑]  GitHub                         ☆   ✎ Edit  │
│ Folders ▾                │       Personal › Work › Code                      │
│ ▾ ● lars@personal        │ ┌ Login ────────────────────────────────────────┐ │
│   ▸ ★ Favorites      4   │ │ Username   lars                          ⧉   │ │
│   ▾ 📁 Work          7   │ │ Password   ••••••••••••                ◉ ⧉   │ │
│     ▾ 📁 Code        3   │ │ Code       482 913      ◔ 17 s           ⧉   │ │
│        🔑 GitHub   ◀sel  │ └───────────────────────────────────────────────┘ │
│        🔑 GitLab         │ ┌ Websites ─────────────────────────────────────┐ │
│        ⌘ deploy key      │ │ https://github.com                      ↗ ⧉   │ │
│   ▸ 📁 Home          5   │ └───────────────────────────────────────────────┘ │
│   ▸ 🗑 Trash         2   │ ┌ Notes ┐ ┌ Custom fields ┐ ┌ History ┐          │
│ ▸ ● lars@work (EU)       │                                                   │
│ ▸ 🔒 family vault        │                                                   │
│ + Add account            │                                                   │
└──────────────────────────┴───────────────────────────────────────────────────┘
```

The divider between the panes can be dragged, and the left pane can be
collapsed to give the details the whole window.

### Top bar

The top bar holds global actions: sync status and **Sync now**, **New item**,
the **Generator**, **Send**, **Settings** and **Lock all**. Actions that apply
to a single account live in that account's context menu in the tree.

### Left pane: filter and tree

- **Filter box** at the top. Ctrl+F focuses it. It matches as you type,
  ignoring case, on item names, usernames, websites, card brands and the
  visible text of notes and custom fields. It never matches secret values.
  The number of matches appears in the box. Esc clears it. Down moves into
  the results, and Enter opens the first match.
- **Group by** switch under the filter: **Folders**, **Collections** or
  **Types**. Each account keeps the same grouping.
- **Tree.** Each account is a root node with a coloured avatar, the email
  address and the server. Under each unlocked account:
  - **Favorites**
  - the chosen grouping (folders, which nest using `/` in names as in
    Bitwarden; organisations and their collections; or item types)
  - **Sends**
  - **Archive** and **Trash**

  Items are leaves under their group. Branches show item counts.
- **While filtering**, only matching items and their parent branches are shown,
  and those branches open automatically. Clearing the filter restores what
  was open before.
- **Locked accounts** show a padlock and have no children. Selecting one shows
  an unlock form on the right.
- **Keyboard:** Up/Down move, Right opens a branch or steps into it, Left
  closes it or steps out to the parent, Enter opens an item or toggles a
  branch. Typing a letter jumps to the next row starting with it.
- **Context menu** on items: copy username, password or code; open website;
  edit; clone; favourite; move to folder or organisation; archive; delete.
  On accounts: sync, lock, log out, account settings, remove from this device.
- **Add account** at the bottom of the tree starts the sign-in flow.

### Right pane: details

- **Header:** a type icon, the name, the path (account › folder) and actions:
  favourite, **Edit** and a menu (clone, move, archive, delete).
- **Sections as cards**, matching how Bitwarden groups fields:
  - **Login:** username, password, verification code (TOTP), passkey
  - **Card:** cardholder, brand, number, expiry, security code
  - **Identity:** name, contact details, address, ID numbers
  - **SSH key:** public key, fingerprint, private key
  - **Websites:** each address and how it is matched
  - **Notes**
  - **Custom fields:** text, hidden, checkbox or linked
  - **Attachments**
  - **History:** created, last edited, password last changed, password history
- Each field has buttons for **copy**, **show or hide** (hidden fields) and
  **open** (websites), visible on hover and focus. The verification code shows
  a countdown ring.
- Long values wrap. Monospace is used for passwords, codes and keys.
- **Empty states** for no selection, empty folders, and filters with no
  matches.

### Editing

- **Getting into edit mode:** the **Edit** button, Ctrl+E, or double-clicking
  any field (which also puts the cursor in that field).
- **The layout stays the same.** Values turn into inputs, and the header shows
  an "Editing" badge. Hidden fields get **Generate** next to **Show**. Each
  section gains **Add** where relevant (websites, custom fields, attachments).
  Name, folder, favourite and owner become editable in the header.
- **Bottom bar** while editing: **Cancel** and **Save**, with the hint "Ctrl+S to
  save · Esc to cancel". Save is disabled until something changes.
- **Leaving with unsaved changes** (selecting another item, locking, closing)
  shows an inline bar instead of a dialog: **Save**, **Discard** or **Keep
  editing**.
- **New item:** opens the same details pane in edit mode, filled from the
  current selection (the folder or account, and the type chosen in the New
  menu).
- **Saving** uses the existing VaultGoblin approach: drafts are written to the
  encrypted local store before submitting, a POST is never retried, and an
  uncertain result is resolved before anything else is sent. Conflicts with a
  newer server version show both versions instead of overwriting.

### Locking and unlocking

- **Locked account selected:** the right pane shows the avatar, email, server
  and an unlock form (master password, PIN or biometric, whichever is set up).
- **Lock all** (Ctrl+L) locks every account and clears secrets from memory.
- **Timeouts:** each account has its own vault timeout. When one fires, that
  account's branch collapses to its locked state, and any edits are kept as an
  encrypted draft.

### SSH agent

Hushjar includes an SSH agent that serves SSH key items from the vault, like
the Bitwarden desktop app and VaultGoblin's existing agent
(`internal/sshagent`, to be ported).

- **Where it listens:** a Unix socket at
  `$XDG_RUNTIME_DIR/hushjar/ssh-agent.sock` on Linux and macOS, and the
  OpenSSH named pipe on Windows. Settings show the line to set
  `SSH_AUTH_SOCK`, and can install it in `~/.config/environment.d`.
- **Which keys:** each SSH key item has a **Use in SSH agent** switch. Only
  switched-on keys from unlocked accounts are listed. Ed25519, ECDSA and RSA
  (SHA-2 signatures) are supported.
- **Approval setting:** each key has **Ask: every time** or **Ask: first time**.
  The default is **first time**, with a global default in Settings.
  - **First time:** the first signing request after the account is unlocked
    needs approval. After that, any program can use the key without asking
    until the account locks or Hushjar quits. The approval belongs to the key,
    not to the program that asked.
  - **Every time:** every signing request needs approval.
- **The approval prompt** appears as a banner in the right pane and as a
  desktop notification, raising the window. It names the key, the process
  asking (from the socket's peer credentials) and, when the client sends it, the
  host being logged in to (OpenSSH's `session-bind` extension). The choices are
  **Allow** and **Deny**. Unanswered requests are denied after a timeout.
- **Revoking:** locking the account, or **Forget approvals** in the agent
  status menu, puts every first-time key back to asking.
- **Locked vault:** listing keys returns none. A signing request offers to
  unlock the account first.
- **Status:** a key icon in the top bar shows whether the agent is running and
  how many requests are waiting. Clicking it lists the keys on offer and recent
  requests.
- **Refused requests:** `ssh-add` (adding and removing keys) and the agent's
  own lock are refused, because keys are managed in the vault and Hushjar's
  lock covers it. Later, `ssh-add` of a key file could offer to import it.

### Browsers and other apps

No browser has a standard API for plugging in an outside password manager on
desktop Linux. The options, in order:

1. **The official Bitwarden browser extension works today.** Hushjar talks to
   the same Bitwarden or Vaultwarden server, so the extension already fills
   from the same vault. Nothing is needed for first release.
2. **Hushjar's own browser extension, later.** WebExtensions run in Chromium
   browsers and Firefox with one codebase. Native Messaging connects the
   extension to a small Hushjar helper registered in each browser's
   native-messaging folder, and the helper talks to the running app over a
   local socket. KeePassXC-Browser and Bitwarden's biometric unlock both work
   this way. It would let the browser use Hushjar's unlocked accounts, approval
   prompts and biometrics instead of a separate login. This is the only route
   that is generic across browsers and desktop systems.
3. **Operating system credential providers, per platform.** Android has the
   Autofill framework and Credential Manager. macOS and iOS have credential
   provider extensions, and Windows 11 has a passkey provider plugin API.
   Browsers on those systems ask the system, so Hushjar can fill passwords or
   passkeys there without an extension. Linux has no equivalent yet; work on a
   desktop portal for credentials and passkeys is under way and worth tracking.
4. **Secret Service provider.** Hushjar could serve the freedesktop Secret
   Service D-Bus API, as KeePassXC does, so apps that use libsecret (git
   credential helpers, NetworkManager, many desktop apps) read secrets from the
   vault. Browsers only keep their own storage key there, so this does not give
   browser autofill.

A command-line tool and a git credential helper fit the same local socket as
the browser helper.

### Other screens in the right pane

The **Generator**, **Send**, **Settings** and **sign-in** all open in the right
pane, in the same card style, rather than as separate windows. The generator
also opens as a small popup from the Generate button on hidden fields.

## Keyboard shortcuts

| Keys | Action |
| --- | --- |
| Ctrl+F | Focus the filter |
| Esc | Clear the filter, or cancel editing |
| Ctrl+E | Edit the selected item |
| Ctrl+S | Save |
| Ctrl+N | New item |
| Ctrl+U | Copy username |
| Ctrl+P | Copy password |
| Ctrl+T | Copy verification code |
| Ctrl+G | Open the generator |
| Ctrl+L | Lock all accounts |
| Ctrl+R | Sync all unlocked accounts |
| Ctrl+B | Show or hide the left pane |

## Multiple accounts

- Any number of accounts, each on its own server (bitwarden.com US or EU, or
  any self-hosted Vaultwarden or Bitwarden server). The official desktop app
  allows five and shows one at a time. Hushjar shows them all at once.
- Each account has its own colour, timeout settings, unlock methods,
  encrypted local store and sync schedule.
- Search and the copy shortcuts work across all unlocked accounts. Results
  show which account they belong to.
- Later: copy or move an item between accounts, by re-creating it in the
  target account and then deleting or keeping the original.

## Bitwarden desktop feature checklist

**Phase** says when each feature is planned (see the milestones below).
"Later" means after first release, and "maybe" means it is undecided.

### Signing in and accounts

| Feature | Phase |
| --- | --- |
| Email and master password sign-in | M1 |
| Self-hosted server URL, bitwarden.com US and EU regions | M1 |
| Two-step login: authenticator app, email, YubiKey OTP, FIDO2/WebAuthn key | M1 |
| Two-step login: Duo | Later |
| New-device verification code | M1 |
| Remember two-step login on this device | M1 |
| Log in with a device (approve from another device) | M3 |
| Approve login requests from other devices | M3 |
| Single sign-on and trusted devices (enterprise) | Later |
| Several accounts, switching, log out, remove | M3 |
| Account fingerprint phrase | M3 |

### Unlocking and security

| Feature | Phase |
| --- | --- |
| Lock and unlock with master password | M1 |
| Unlock with PIN | M3 |
| Unlock with biometrics (Linux: polkit or fingerprint; Windows Hello; Touch ID) | M3 |
| Vault timeout: time, on system lock, on sleep, on restart, never | M3 |
| Timeout action: lock or log out | M3 |
| Master password re-prompt for chosen items | M2 |
| Clear clipboard after a delay, and mark copies as secret for clipboard managers | M3 |
| Block screenshots of the window (where the platform allows it) | Later |

### Vault items

| Feature | Phase |
| --- | --- |
| View all item types: login, card, identity, secure note, SSH key | M1 |
| Create, edit, clone, delete, restore and permanently delete | M2 |
| Archive and unarchive | M2 |
| Favourites | M2 |
| Folders: create, rename, delete, nesting with `/` | M2 |
| Custom fields: text, hidden, checkbox, linked | M2 |
| Website addresses with match detection (domain, host, starts with, exact, regex, never) | M2 |
| Verification codes (TOTP) with countdown | M1 |
| Passkeys stored on logins: show, remove | M2 |
| Password history per item | M2 |
| Attachments: view, download, add, delete | M4 |
| SSH keys: generate, import, edit | M2 |
| Organisation items: view by collection, item permissions (can edit, hide passwords) | M1 |
| Move item to an organisation, change collections | M4 |
| Organisation policies that affect the client (generator, timeout, personal ownership, Send) | M4 |

### Finding and copying

| Feature | Phase |
| --- | --- |
| Search | M0 |
| Filters: all, favourites, types, folders, collections, my vault or organisation, archive, trash | M0 |
| Copy username, password, code, card number, security code, any field | M1 |
| Open website in the browser | M1 |
| Website icons (favicons), with an option to turn them off | Later |

### Tools

| Feature | Phase |
| --- | --- |
| Password generator: length, character sets, minimum numbers and symbols, avoid ambiguous | M4 |
| Passphrase generator: words, separator, capitals, number | M4 |
| Username generator: random word, plus-addressed email, catch-all email | M4 |
| Forwarded email aliases: SimpleLogin, addy.io, Firefox Relay, Fastmail, DuckDuckGo, Forward Email | Later |
| Generator history | M4 |
| Send: text and file, deletion and expiry dates, access limit, password, hide email, disable | M4 |
| Import from other password managers and Bitwarden formats | M4 |
| Export: JSON, CSV, encrypted JSON (account-locked or password-protected) | M4 |

### Sync

| Feature | Phase |
| --- | --- |
| Full sync on unlock and on demand | M1 |
| Live updates from the server's notification connection | M3 |
| Last-sync time | M1 |

### Desktop integration

| Feature | Phase |
| --- | --- |
| SSH agent: vault keys, per-key switch, approval every time or first time, status in the top bar | M3 |
| System tray: minimise, close or start to tray | M3 |
| Start on login | M3 |
| Light, dark and system theme | M0 |
| Languages | Later |
| Browser filling through the official Bitwarden extension (same server) | Works already |
| Hushjar browser extension with a Native Messaging helper | Later |
| Android, macOS, iOS and Windows credential providers | M5 |
| Secret Service provider for other apps | Maybe |
| Command-line tool and git credential helper | Maybe |
| Auto-type | Maybe; not possible on Wayland in general |

### Web vault features (not in the Bitwarden desktop app)

| Feature | Phase |
| --- | --- |
| Reports: exposed, reused and weak passwords, unsecured websites, missing two-step login | Maybe |
| Change master password, KDF settings, two-step login setup, emergency access | Maybe |

## Milestones

- **M0 – UI prototype.** The layout above with dummy data: filter, tree,
  grouping, details, editing, locked accounts, keyboard shortcuts, light and
  dark theme. No real secrets.
- **M1 – Read-only vault.** Port VaultGoblin's crypto and sync to
  `hushjar-core`: sign-in and two-step login, key derivation, decryption,
  encrypted offline store, sync, viewing every item type, copying, codes.
- **M2 – Editing.** Create, edit and delete for every item type, folders,
  custom fields, history and safe saving.
- **M3 – Everyday desktop use.** Multiple accounts, timeouts, PIN and
  biometric unlock, clipboard clearing, SSH agent, tray, start on login, live
  sync.
- **M4 – Tools.** Generator, Send, attachments, import and export,
  organisation moves and policies.
- **M5 – Other platforms.** Windows and macOS packaging, then Android with a
  single-pane layout.

## Platform notes

- **Wayland:** windows cannot place themselves, so position and size are left
  to the compositor. Clipboard clearing needs the data-control protocol, which
  KDE and wlroots compositors offer and GNOME does not; there, Hushjar replaces
  the clipboard contents while it still owns them. Global shortcuts go through
  the desktop portal.
- **Secrets in memory:** decrypted values are held in zeroising buffers in the
  core and passed to the UI only when shown or copied.

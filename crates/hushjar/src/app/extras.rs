//! Item and folder actions beyond plain editing: the item's "more" menu
//! (clone, archive, organisation moves, the master password re-prompt
//! setting), the re-prompt itself, attachments, passkeys, folder rename and
//! delete, and generating or importing SSH keys.
//!
//! Network work goes to the account worker (`worker/items.rs`); file
//! dialogs and key generation run on their own threads and come back with
//! [`on_ui`].

use std::path::{Path, PathBuf};

use hushjar_core::sshkey::{self, Algorithm, SshKeyError};
use hushjar_core::vault::SshKey;

use super::*;
use crate::{AttachmentRow, CollectionChoice, ItemExtras, MenuEntry, PasskeyRow};

/// Shown instead of a hidden value until the master password is entered.
pub(super) const REPROMPT_MASK: &str = "Enter your master password to see this";

/// The largest attachment the server takes.
const MAX_ATTACHMENT: u64 = hushjar_core::api::MAX_FILE_BYTES as u64;

/// The largest file read as an SSH private key.
const MAX_KEY_FILE: u64 = 64 * 1024;

/// The key types in the order the SSH key tools list them.
const ALGORITHMS: [Algorithm; 4] = [
    Algorithm::Ed25519,
    Algorithm::Rsa3072,
    Algorithm::Rsa4096,
    Algorithm::Rsa2048,
];

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum MoveMode {
    #[default]
    Closed,
    ToOrganization,
    Collections,
}

#[derive(Default)]
pub(super) struct Extras {
    /// What the right pane showed when the extras were last drawn, so
    /// per-view state is reset when it changes.
    shown_key: String,
    /// The item whose master password re-prompt was answered, as
    /// (account ID, item ID).
    verified: Option<(String, String)>,
    /// The item waiting for the worker to check a re-prompt password.
    verifying: Option<(String, String)>,
    reprompt_error: String,
    /// What the attachments are busy with; empty when idle.
    attachment_busy: String,
    /// Attachments saved to temporary files to open them, with the
    /// account they came from. Deleted when it locks and when the app quits.
    opened: Vec<(String, PathBuf)>,
    next_open: usize,
    move_mode: MoveMode,
    move_org: usize,
    move_checked: Vec<String>,
    move_busy: bool,
    folder_busy: bool,
    /// The tree row to show once a folder rename or delete is done.
    folder_after: Option<String>,
    ssh_busy: bool,
    /// A protected private key waiting for its passphrase.
    ssh_pending: Option<Zeroizing<String>>,
    ssh_error: String,
}

/// Runs `f` on the UI thread, with the window and state, from any thread.
fn on_ui(f: impl FnOnce(&AppWindow, &Shared) + Send + 'static) {
    let _ = slint::invoke_from_event_loop(move || {
        CONTEXT.with(|c| {
            if let Some((weak, st)) = &*c.borrow()
                && let Some(win) = weak.upgrade()
            {
                f(&win, st);
            }
        });
    });
}

fn rows_model<T: Clone + 'static>(rows: Vec<T>) -> ModelRc<T> {
    ModelRc::new(VecModel::from(rows))
}

// ---------------------------------------------------------------- pure rules

/// Whether a field's value stays hidden behind the master password re-prompt.
fn hidden_by_reprompt(field: &Field) -> bool {
    matches!(field.kind, FieldKind::Secret | FieldKind::Totp) || field.path == FieldPath::SshPrivate
}

/// A field as shown: like [`to_detail`], but with hidden values replaced
/// by a note while the item waits for the master password.
pub(super) fn shown_detail(field: &Field, view: bool, locked: bool) -> DetailField {
    if locked && hidden_by_reprompt(field) {
        return DetailField {
            label: s(&field.label),
            value: s(REPROMPT_MASK),
            kind: FieldKind::Info,
            ..Default::default()
        };
    }
    to_detail(field, view)
}

/// Whether an item can be copied into a new one. Not when its type cannot
/// be edited here, values could not be decrypted, or its organisation hides
/// its passwords (a copy would show them).
fn can_clone(item: &core::Item) -> bool {
    item.kind.editable() && item.unreadable == 0 && item.view_password && !item.deleted
}

fn copy_name(name: &str) -> String {
    if name.trim().is_empty() {
        "Copy".into()
    } else {
        format!("{name} (copy)")
    }
}

/// A new item with the same type, values, folder and owner as `item`,
/// named "<name> (copy)". Attachments, passkeys and password history are
/// not copied, and nothing of the original JSON is reused.
fn clone_item(item: &core::Item) -> Option<core::Item> {
    if !can_clone(item) {
        return None;
    }
    let mut copy = core::Item::new(
        item.kind,
        item.organization_id.clone(),
        item.folder_id.clone(),
    );
    copy.collection_ids = item.collection_ids.clone();
    copy.name = copy_name(&item.name);
    copy.notes = item.notes.clone();
    copy.favorite = item.favorite;
    copy.reprompt = item.reprompt;
    copy.login = core::Login {
        username: item.login.username.clone(),
        password: item.login.password.clone(),
        totp: item.login.totp.clone(),
        uris: item.login.uris.clone(),
        ..Default::default()
    };
    copy.card = item.card.clone();
    copy.identity = item.identity.clone();
    copy.ssh_key = item.ssh_key.clone();
    copy.fields = item.fields.clone();
    Some(copy)
}

/// A size for people: "820 bytes", "1.2 KB", "500 MB" (1024-based, as the
/// Bitwarden clients count).
pub(super) fn format_size(bytes: u64) -> String {
    const UNITS: [&str; 4] = ["KB", "MB", "GB", "TB"];
    if bytes < 1024 {
        return if bytes == 1 {
            "1 byte".into()
        } else {
            format!("{bytes} bytes")
        };
    }
    let mut value = bytes as f64 / 1024.0;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    let rounded = (value * 10.0).round() / 10.0;
    if rounded >= 100.0 || rounded.fract() == 0.0 {
        format!("{:.0} {}", value.round(), UNITS[unit])
    } else {
        format!("{rounded:.1} {}", UNITS[unit])
    }
}

fn too_large(name: &str, size: u64) -> String {
    format!(
        "“{name}” is {}. Attachments can be at most {}.",
        format_size(size),
        format_size(MAX_ATTACHMENT)
    )
}

/// A file name safe to create in our own folder: no folders, no control
/// characters, never empty.
fn safe_file_name(name: &str) -> String {
    let base = name.rsplit(['/', '\\']).next().unwrap_or("");
    let clean: String = base.chars().filter(|c| !c.is_control()).collect();
    let clean = clean.trim();
    if clean.is_empty() || clean == "." || clean == ".." {
        "attachment".into()
    } else {
        clean.to_string()
    }
}

/// Trims each part of a nested folder name and drops empty parts.
fn clean_folder_name(name: &str) -> String {
    name.split('/')
        .map(str::trim)
        .filter(|p| !p.is_empty())
        .collect::<Vec<_>>()
        .join("/")
}

fn folder_delete_note(name: &str, items: usize, nested: bool) -> String {
    let mut note = format!("Delete the folder “{name}”?");
    match items {
        0 => note.push_str(" It has no items."),
        1 => note.push_str(" Its item is kept and moves to No folder."),
        n => note.push_str(&format!(" Its {n} items are kept and move to No folder.")),
    }
    if nested {
        note.push_str(" The folders inside it are kept too.");
    }
    note
}

/// What the item menu offers for a saved item.
fn menu_entries(item: &core::Item, online: bool, has_organizations: bool) -> Vec<MenuEntry> {
    if item.deleted {
        return vec![];
    }
    let editable = item.editable && item.kind.editable() && item.unreadable == 0;
    let entry = |id: &str, label: &str| MenuEntry {
        id: s(id),
        label: s(label),
        toggle: false,
        checked: false,
        enabled: online,
    };
    let mut out = Vec::new();
    if can_clone(item) {
        out.push(entry("clone", "Clone"));
    }
    if editable {
        out.push(if item.archived {
            entry("archive", "Take out of archive")
        } else {
            entry("archive", "Archive")
        });
    }
    if editable && item.organization_id.is_none() && has_organizations {
        out.push(entry("move", "Move to organisation…"));
    }
    if editable && item.organization_id.is_some() {
        out.push(entry("collections", "Collections…"));
    }
    if editable {
        out.push(MenuEntry {
            toggle: true,
            checked: item.reprompt,
            ..entry("reprompt", "Ask for master password")
        });
    }
    out
}

// ---------------------------------------------------------------- state

impl State {
    fn online(&self, account: usize) -> bool {
        self.accounts
            .get(account)
            .is_some_and(|a| a.vault.is_some() && !a.needs_sign_in)
    }

    fn shown_item(&self) -> Option<(usize, String)> {
        match &self.shown {
            Shown::Item { account, id } => Some((*account, id.clone())),
            _ => None,
        }
    }

    /// Whether the saved item asks for the master password and it has not
    /// been entered since the item was selected.
    pub(super) fn reprompt_locked(&self, account: usize, id: &str) -> bool {
        let Some(profile) = self.accounts.get(account).map(|a| &a.profile.id) else {
            return false;
        };
        self.core_item(account, id).is_some_and(|i| i.reprompt)
            && self.extras.verified.as_ref() != Some(&(profile.clone(), id.to_string()))
    }

    /// Whether copying the value at `path` of the shown item must wait for
    /// the master password.
    pub(super) fn copy_blocked(&self, path: FieldPath) -> bool {
        path != FieldPath::Username
            && self
                .shown_item()
                .is_some_and(|(account, id)| self.reprompt_locked(account, &id))
    }

    fn mark_verified(&mut self, account: usize, id: &str) {
        let profile = self.accounts[account].profile.id.clone();
        self.extras.verified = Some((profile, id.to_string()));
    }

    /// A key for what the right pane shows, to notice when it changes.
    fn extras_key(&self) -> String {
        match &self.shown {
            Shown::Item { account, id } => format!(
                "item:{}:{id}",
                self.accounts
                    .get(*account)
                    .map_or("", |a| a.profile.id.as_str())
            ),
            Shown::Group(key) => format!("group:{key}"),
            other => format!("{other:?}"),
        }
    }

    /// The writable collections of an organisation, by name.
    fn writable_collections(&self, account: usize, organization: &str) -> Vec<core::Collection> {
        let Some(vault) = self.accounts.get(account).and_then(|a| a.vault.as_ref()) else {
            return vec![];
        };
        let mut list: Vec<core::Collection> = vault
            .collections
            .iter()
            .filter(|c| c.organization_id == organization && !c.read_only)
            .cloned()
            .collect();
        list.sort_by_key(|c| c.name.to_lowercase());
        list
    }

    /// The organisation the move card is about, for the shown item.
    fn move_organization(&self, account: usize, item: &core::Item) -> Option<String> {
        match self.extras.move_mode {
            MoveMode::Closed => None,
            MoveMode::Collections => item.organization_id.clone(),
            MoveMode::ToOrganization => self.accounts[account]
                .vault
                .as_ref()?
                .organizations
                .get(self.extras.move_org)
                .map(|o| o.id.clone()),
        }
    }
}

/// The folder behind a tree row, for rename and delete.
struct FolderTarget {
    account: usize,
    /// The full name, with `/` between nested parts.
    path: String,
    /// `None` for a parent that exists only through nested names.
    id: Option<String>,
    nested: bool,
    items: usize,
}

fn folder_target(state: &State, key: &str) -> Option<FolderTarget> {
    let row = state.row(key)?;
    let a = state.accounts.get(row.account)?;
    let path = key
        .strip_prefix(&format!("{}/f/", a.profile.id))?
        .to_string();
    let prefix = format!("{path}/");
    let nested = a.view.folders.iter().any(|f| f.name.starts_with(&prefix));
    let items = row.folder.as_ref().map_or(0, |id| {
        a.view
            .items
            .iter()
            .filter(|i| !i.deleted && i.folder.as_deref() == Some(id))
            .count()
    });
    Some(FolderTarget {
        account: row.account,
        path,
        id: row.folder.clone(),
        nested,
        items,
    })
}

// ---------------------------------------------------------------- rendering

/// Fills [`ItemExtras`] for what the right pane shows. Called from
/// `render`, and after changes that only touch the extras.
pub(super) fn render_extras(win: &AppWindow, st: &Shared) {
    let data = win.global::<ItemExtras>();
    let changed = {
        let mut state = st.borrow_mut();
        let key = state.extras_key();
        let changed = state.extras.shown_key != key;
        if changed {
            let x = &mut state.extras;
            x.shown_key = key;
            x.verified = None;
            x.reprompt_error.clear();
            x.move_mode = MoveMode::Closed;
            x.move_checked.clear();
            x.ssh_pending = None;
            x.ssh_error.clear();
            x.folder_after = None;
        }
        changed
    };
    if changed {
        data.set_folder_mode(0);
    }
    data.set_confirm_attachment(-1);
    data.set_confirm_passkey(-1);
    let state = st.borrow();
    render_item_extras(&data, &state);
    render_move(&data, &state);
    render_folder_extras(&data, &state);
}

fn render_item_extras(data: &ItemExtras, state: &State) {
    let x = &state.extras;
    let editing = state.editing_shown();
    let shown = state.shown_item();
    let saved = shown
        .as_ref()
        .and_then(|(a, id)| Some((*a, state.core_item(*a, id)?)));
    let locked = shown
        .as_ref()
        .is_some_and(|(a, id)| state.reprompt_locked(*a, id));
    let has_orgs = |a: usize| {
        state.accounts[a]
            .vault
            .as_ref()
            .is_some_and(|v| !v.organizations.is_empty())
    };
    let menu = saved
        .map(|(a, item)| menu_entries(item, state.online(a), has_orgs(a)))
        .unwrap_or_default();
    data.set_menu(rows_model(menu));
    data.set_reprompt_locked(locked);
    data.set_reprompt_busy(x.verifying.is_some());
    data.set_reprompt_error(s(&x.reprompt_error));
    data.set_reprompt(
        shown
            .as_ref()
            .and_then(|(a, id)| state.item(*a, id))
            .is_some_and(|i| i.reprompt),
    );

    let (attachments, passkeys, can_change, online) = match saved {
        Some((a, item)) => {
            let attachments = item
                .attachments
                .iter()
                .map(|f| AttachmentRow {
                    name: s(&f.file_name),
                    size: s(&format_size(f.size)),
                })
                .collect();
            let passkeys = item.login.passkey_details.iter().map(passkey_row).collect();
            let can_change = item.editable && !item.deleted && state.online(a);
            (attachments, passkeys, can_change, state.online(a))
        }
        None => (vec![], vec![], false, false),
    };
    let attachments: Vec<AttachmentRow> = attachments;
    data.set_attachments_visible(!attachments.is_empty() || can_change);
    data.set_attachments(rows_model(attachments));
    data.set_attachments_open(online && !locked);
    data.set_can_add_attachment(can_change);
    data.set_can_delete_attachment(can_change && !locked);
    data.set_attachment_busy(s(&x.attachment_busy));
    data.set_passkeys(rows_model(passkeys));
    data.set_can_remove_passkey(can_change && !locked && !editing);

    let ssh_draft = state
        .draft
        .as_ref()
        .is_some_and(|d| d.item.kind == ItemType::SshKey);
    data.set_ssh_tools(editing && ssh_draft);
    data.set_ssh_busy(x.ssh_busy);
    data.set_ssh_passphrase_needed(x.ssh_pending.is_some());
    data.set_ssh_error(s(&x.ssh_error));
}

fn passkey_row(p: &core::Passkey) -> PasskeyRow {
    let first = |a: &str, b: &str, fallback: &str| {
        if !a.trim().is_empty() {
            a.to_string()
        } else if !b.trim().is_empty() {
            b.to_string()
        } else {
            fallback.to_string()
        }
    };
    PasskeyRow {
        site: first(&p.rp_name, &p.rp_id, "Passkey").into(),
        user: first(&p.user_name, &p.user_display_name, "No user name").into(),
        created: if p.created.is_empty() {
            SharedString::new()
        } else {
            model::format_time(&p.created).into()
        },
    }
}

fn render_move(data: &ItemExtras, state: &State) {
    let x = &state.extras;
    let target = state
        .shown_item()
        .and_then(|(a, id)| Some((a, state.core_item(a, &id)?)));
    let mode = match (x.move_mode, target) {
        (MoveMode::Closed, _) | (_, None) => 0,
        (MoveMode::ToOrganization, Some(_)) => 1,
        (MoveMode::Collections, Some(_)) => 2,
    };
    data.set_move_mode(mode);
    data.set_move_busy(x.move_busy);
    let Some((account, item)) = target.filter(|_| mode != 0) else {
        data.set_collections(rows_model(vec![]));
        data.set_move_ready(false);
        return;
    };
    let organizations: Vec<SharedString> = state.accounts[account]
        .vault
        .as_ref()
        .map(|v| v.organizations.iter().map(|o| s(&o.name)).collect())
        .unwrap_or_default();
    data.set_organizations(rows_model(organizations));
    data.set_organization_index(x.move_org as i32);
    let choices = state
        .move_organization(account, item)
        .map(|org| state.writable_collections(account, &org))
        .unwrap_or_default();
    let rows: Vec<CollectionChoice> = choices
        .iter()
        .map(|c| CollectionChoice {
            name: s(&c.name),
            checked: x.move_checked.contains(&c.id),
        })
        .collect();
    data.set_move_ready(!move_selection(state, account, item).is_empty());
    data.set_collections(rows_model(rows));
}

/// The collections to send: the ticked ones, plus (when changing an
/// organisation item's collections) the read-only ones it is already in,
/// which are not offered and must not be dropped.
fn move_selection(state: &State, account: usize, item: &core::Item) -> Vec<String> {
    let Some(org) = state.move_organization(account, item) else {
        return vec![];
    };
    let writable = state.writable_collections(account, &org);
    let mut ids: Vec<String> = writable
        .iter()
        .filter(|c| state.extras.move_checked.contains(&c.id))
        .map(|c| c.id.clone())
        .collect();
    if state.extras.move_mode == MoveMode::Collections {
        ids.extend(
            item.collection_ids
                .iter()
                .filter(|id| !writable.iter().any(|c| &c.id == *id))
                .cloned(),
        );
    }
    ids
}

fn render_folder_extras(data: &ItemExtras, state: &State) {
    let target = match &state.shown {
        Shown::Group(key) => folder_target(state, key),
        _ => None,
    };
    data.set_folder_busy(state.extras.folder_busy);
    match target.filter(|t| state.online(t.account)) {
        Some(t) => {
            data.set_folder_actions(true);
            data.set_folder_name(s(&t.path));
            data.set_folder_can_delete(t.id.is_some());
            data.set_folder_delete_note(folder_delete_note(&t.path, t.items, t.nested).into());
        }
        None => data.set_folder_actions(false),
    }
}

// ---------------------------------------------------------------- menu

fn menu_picked(win: &AppWindow, st: &Shared, id: &str) {
    let Some((account, item)) = st.borrow().shown_item() else {
        return;
    };
    if !st.borrow().online(account) {
        toast(win, st, "Sign in again to change items in this account");
        return;
    }
    match id {
        "clone" => clone_shown(win, st, account, &item),
        "archive" => toggle_archive(win, st, account, &item),
        "move" => open_move(win, st, MoveMode::ToOrganization),
        "collections" => open_move(win, st, MoveMode::Collections),
        "reprompt" => toggle_saved_reprompt(win, st, account, &item),
        _ => {}
    }
}

fn send(st: &Shared, account: usize, command: Command) {
    if let Some(a) = st.borrow().accounts.get(account) {
        let _ = a.worker.tx.send(command);
    }
}

/// Opens a new draft that copies the shown item.
fn clone_shown(win: &AppWindow, st: &Shared, account: usize, id: &str) {
    if st.borrow().reprompt_locked(account, id) {
        toast(win, st, "Enter your master password first");
        return;
    }
    let copy = st.borrow().core_item(account, id).and_then(clone_item);
    let Some(copy) = copy else {
        toast(win, st, "This item cannot be cloned");
        return;
    };
    let kind = ItemType::from_kind(copy.kind);
    {
        let mut state = st.borrow_mut();
        let new_id = format!("new-{}", state.next_id);
        state.next_id += 1;
        let mut item = model::from_core(&copy);
        item.id = new_id.clone();
        add_blank_website(&mut item);
        state.draft = Some(Draft {
            account,
            original: item.clone(),
            item,
            core: copy,
            is_new: true,
            saving: false,
        });
        state.shown = Shown::Item {
            account,
            id: new_id,
        };
    }
    let type_index = ItemType::CREATABLE
        .iter()
        .position(|t| *t == kind)
        .unwrap_or(0);
    win.set_type_index(type_index as i32);
    render(win, st);
    toast(win, st, "This is a copy. Save it to keep it.");
}

fn toggle_archive(win: &AppWindow, st: &Shared, account: usize, id: &str) {
    let archived = st
        .borrow()
        .core_item(account, id)
        .is_some_and(|i| i.archived);
    let command = if archived {
        Command::Unarchive(id.to_string())
    } else {
        Command::Archive(id.to_string())
    };
    send(st, account, command);
    toast(
        win,
        st,
        if archived {
            "Taking out of the archive…"
        } else {
            "Archiving…"
        },
    );
}

fn toggle_saved_reprompt(win: &AppWindow, st: &Shared, account: usize, id: &str) {
    let on = st
        .borrow()
        .core_item(account, id)
        .is_some_and(|i| i.reprompt);
    if on && st.borrow().reprompt_locked(account, id) {
        toast(win, st, "Enter your master password first");
        return;
    }
    // Whoever turns it on has just seen the item; keep it open for them.
    st.borrow_mut().mark_verified(account, id);
    quick_save(win, st, |item| item.reprompt = !on);
}

fn open_move(win: &AppWindow, st: &Shared, mode: MoveMode) {
    {
        let mut state = st.borrow_mut();
        let current = state
            .shown_item()
            .and_then(|(a, id)| state.core_item(a, &id))
            .map(|i| i.collection_ids.clone())
            .unwrap_or_default();
        let x = &mut state.extras;
        x.move_mode = mode;
        x.move_org = 0;
        x.move_checked = if mode == MoveMode::Collections {
            current
        } else {
            vec![]
        };
    }
    render_extras(win, st);
}

fn pick_organization(win: &AppWindow, st: &Shared, index: i32) {
    {
        let mut state = st.borrow_mut();
        state.extras.move_org = index.max(0) as usize;
        state.extras.move_checked.clear();
    }
    render_extras(win, st);
}

fn toggle_collection(win: &AppWindow, st: &Shared, index: i32, on: bool) {
    {
        let mut state = st.borrow_mut();
        let Some((account, id)) = state.shown_item() else {
            return;
        };
        let Some(org) = state
            .core_item(account, &id)
            .and_then(|item| state.move_organization(account, item))
        else {
            return;
        };
        let Some(collection) = state
            .writable_collections(account, &org)
            .get(index.max(0) as usize)
            .map(|c| c.id.clone())
        else {
            return;
        };
        let checked = &mut state.extras.move_checked;
        checked.retain(|c| *c != collection);
        if on {
            checked.push(collection);
        }
    }
    render_extras(win, st);
}

fn confirm_move(win: &AppWindow, st: &Shared) {
    let command = {
        let state = st.borrow();
        let Some((account, id)) = state.shown_item() else {
            return;
        };
        let Some(item) = state.core_item(account, &id) else {
            return;
        };
        let collections = move_selection(&state, account, item);
        if collections.is_empty() || state.extras.move_busy {
            return;
        }
        let command = match (
            state.extras.move_mode,
            state.move_organization(account, item),
        ) {
            (MoveMode::ToOrganization, Some(organization)) => Command::MoveToOrganization {
                item: id,
                organization,
                collections,
            },
            (MoveMode::Collections, Some(_)) => Command::SetCollections {
                item: id,
                collections,
            },
            _ => return,
        };
        (account, command)
    };
    st.borrow_mut().extras.move_busy = true;
    send(st, command.0, command.1);
    render_extras(win, st);
}

// ---------------------------------------------------------------- re-prompt

fn verify(win: &AppWindow, st: &Shared, password: SharedString) {
    let password = Zeroizing::new(password.to_string());
    {
        let mut state = st.borrow_mut();
        let Some((account, id)) = state.shown_item() else {
            return;
        };
        if state.extras.verifying.is_some() {
            return;
        }
        if password.is_empty() {
            state.extras.reprompt_error = "Enter your master password".into();
        } else {
            let profile = state.accounts[account].profile.id.clone();
            state.extras.verifying = Some((profile, id));
            state.extras.reprompt_error.clear();
            let _ = state.accounts[account]
                .worker
                .tx
                .send(Command::VerifyPassword { password });
        }
    }
    render_extras(win, st);
}

/// Whether the account's password check is for the re-prompt.
pub(super) fn waiting_for_reprompt(st: &Shared, account: usize) -> bool {
    let state = st.borrow();
    let Some(a) = state.accounts.get(account) else {
        return false;
    };
    state
        .extras
        .verifying
        .as_ref()
        .is_some_and(|(profile, _)| *profile == a.profile.id)
}

fn set_draft_reprompt(win: &AppWindow, st: &Shared, on: bool) {
    edit_draft(win, st, |item| item.reprompt = on);
    if on && let Some((account, id)) = st.borrow().shown_item() {
        st.borrow_mut().mark_verified(account, &id);
    }
}

// ---------------------------------------------------------------- attachments

/// The shown item's attachment at `index`, when it may be opened or saved:
/// (account, item ID, attachment ID, file name).
fn usable_attachment(
    win: &AppWindow,
    st: &Shared,
    index: i32,
) -> Option<(usize, String, String, String)> {
    let found = {
        let state = st.borrow();
        let (account, id) = state.shown_item()?;
        if state.reprompt_locked(account, &id) {
            Err("Enter your master password first")
        } else if !state.online(account) {
            Err("Sign in again to open attachments")
        } else if !state.extras.attachment_busy.is_empty() {
            return None;
        } else {
            let file = state
                .core_item(account, &id)?
                .attachments
                .get(index.max(0) as usize)?;
            Ok((account, id, file.id.clone(), file.file_name.clone()))
        }
    };
    match found {
        Ok(found) => Some(found),
        Err(message) => {
            toast(win, st, message);
            None
        }
    }
}

fn save_attachment(win: &AppWindow, st: &Shared, index: i32) {
    let Some((account, item, attachment, name)) = usable_attachment(win, st, index) else {
        return;
    };
    let profile = st.borrow().accounts[account].profile.id.clone();
    let suggested = safe_file_name(&name);
    std::thread::spawn(move || {
        let path = rfd::FileDialog::new()
            .set_title("Save attachment")
            .set_file_name(suggested)
            .save_file();
        on_ui(move |win, st| {
            if let Some(path) = path {
                start_download(win, st, &profile, item, attachment, &name, path, false);
            }
        });
    });
}

#[allow(clippy::too_many_arguments)]
fn start_download(
    win: &AppWindow,
    st: &Shared,
    profile: &str,
    item: String,
    attachment: String,
    name: &str,
    path: PathBuf,
    open: bool,
) {
    {
        let mut state = st.borrow_mut();
        let Some(account) = state.account_index(profile) else {
            return;
        };
        if !state.extras.attachment_busy.is_empty() {
            return;
        }
        state.extras.attachment_busy = if open {
            format!("Opening “{name}”…")
        } else {
            format!("Saving “{name}”…")
        };
        let _ = state.accounts[account]
            .worker
            .tx
            .send(Command::DownloadAttachment {
                item,
                attachment,
                path,
                open,
            });
    }
    render_extras(win, st);
}

/// A folder only this user can read, for attachments being opened. Linux
/// uses the session's runtime folder, which only the user can enter.
fn open_dir() -> Result<PathBuf, String> {
    #[cfg(all(unix, not(target_os = "macos")))]
    let base = std::env::var_os("XDG_RUNTIME_DIR")
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
        .ok_or("There is no private folder to open files from; save the file instead")?;
    #[cfg(not(all(unix, not(target_os = "macos"))))]
    let base = std::env::temp_dir();
    Ok(base
        .join("hushjar")
        .join(format!("open-{}", std::process::id())))
}

fn create_private_dir(dir: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)?;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
    }
    #[cfg(not(unix))]
    {
        std::fs::create_dir_all(dir)
    }
}

fn open_attachment(win: &AppWindow, st: &Shared, index: i32) {
    let Some((account, item, attachment, name)) = usable_attachment(win, st, index) else {
        return;
    };
    let path = {
        let mut state = st.borrow_mut();
        state.extras.next_open += 1;
        let n = state.extras.next_open;
        open_dir().and_then(|dir| {
            let dir = dir.join(n.to_string());
            create_private_dir(&dir)
                .map_err(|e| format!("Could not make a private folder to open the file: {e}"))?;
            Ok(dir.join(safe_file_name(&name)))
        })
    };
    let path = match path {
        Ok(path) => path,
        Err(message) => {
            toast(win, st, &message);
            return;
        }
    };
    let profile = st.borrow().accounts[account].profile.id.clone();
    st.borrow_mut()
        .extras
        .opened
        .push((profile.clone(), path.clone()));
    start_download(win, st, &profile, item, attachment, &name, path, true);
}

/// Opens a file with the desktop's default program.
fn open_file(win: &AppWindow, st: &Shared, path: &Path) {
    let program = if cfg!(target_os = "macos") {
        "open"
    } else if cfg!(windows) {
        "explorer"
    } else {
        "xdg-open"
    };
    if let Err(err) = std::process::Command::new(program).arg(path).spawn() {
        toast(win, st, &format!("Could not open the file: {err}"));
    }
}

fn remove_opened(path: &Path) {
    let _ = std::fs::remove_file(path);
    if let Some(dir) = path.parent() {
        let _ = std::fs::remove_dir(dir);
    }
}

/// Deletes the temporary copies of opened attachments; all of them, or
/// those of one account.
fn delete_opened(state: &mut State, profile: Option<&str>) {
    let (gone, kept): (Vec<_>, Vec<_>) = std::mem::take(&mut state.extras.opened)
        .into_iter()
        .partition(|(p, _)| profile.is_none_or(|profile| p == profile));
    state.extras.opened = kept;
    for (_, path) in gone {
        remove_opened(&path);
    }
    if state.extras.opened.is_empty()
        && let Ok(dir) = open_dir()
    {
        let _ = std::fs::remove_dir(dir);
    }
}

fn add_attachment(win: &AppWindow, st: &Shared) {
    let target = {
        let state = st.borrow();
        state
            .shown_item()
            .filter(|(a, id)| {
                state.online(*a)
                    && state
                        .core_item(*a, id)
                        .is_some_and(|i| i.editable && !i.deleted)
            })
            .map(|(a, id)| (state.accounts[a].profile.id.clone(), id))
    };
    let Some((profile, item)) = target else {
        toast(win, st, "Files cannot be added to this item right now");
        return;
    };
    if !st.borrow().extras.attachment_busy.is_empty() {
        return;
    }
    std::thread::spawn(move || {
        let Some(path) = rfd::FileDialog::new()
            .set_title("Choose a file to attach")
            .pick_file()
        else {
            return;
        };
        let size = std::fs::metadata(&path).map(|m| m.len());
        on_ui(move |win, st| attach_chosen(win, st, &profile, item, path, size));
    });
}

fn attach_chosen(
    win: &AppWindow,
    st: &Shared,
    profile: &str,
    item: String,
    path: PathBuf,
    size: std::io::Result<u64>,
) {
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    match size {
        Err(e) => toast(win, st, &format!("Could not read the file: {e}")),
        Ok(size) if size > MAX_ATTACHMENT => toast(win, st, &too_large(&name, size)),
        Ok(_) => {
            {
                let mut state = st.borrow_mut();
                let Some(account) = state.account_index(profile) else {
                    return;
                };
                if !state.extras.attachment_busy.is_empty() {
                    return;
                }
                state.extras.attachment_busy = format!("Adding “{name}”…");
                let _ = state.accounts[account]
                    .worker
                    .tx
                    .send(Command::AddAttachment { item, path });
            }
            render_extras(win, st);
        }
    }
}

fn delete_attachment(win: &AppWindow, st: &Shared, index: i32) {
    {
        let mut state = st.borrow_mut();
        let Some((account, id)) = state.shown_item() else {
            return;
        };
        if !state.extras.attachment_busy.is_empty() || state.reprompt_locked(account, &id) {
            return;
        }
        let Some(file) = state
            .core_item(account, &id)
            .and_then(|i| i.attachments.get(index.max(0) as usize))
            .cloned()
        else {
            return;
        };
        state.extras.attachment_busy = format!("Deleting “{}”…", file.file_name);
        let _ = state.accounts[account]
            .worker
            .tx
            .send(Command::DeleteAttachment {
                item: id,
                attachment: file.id.clone(),
            });
    }
    render_extras(win, st);
}

fn remove_passkey(win: &AppWindow, st: &Shared, index: i32) {
    let target = {
        let state = st.borrow();
        state.shown_item().and_then(|(account, id)| {
            if state.reprompt_locked(account, &id) {
                return None;
            }
            let credential = state
                .core_item(account, &id)?
                .login
                .passkey_details
                .get(index.max(0) as usize)?
                .credential_id
                .clone();
            Some((account, id, credential))
        })
    };
    if let Some((account, item, credential)) = target {
        send(st, account, Command::RemovePasskey { item, credential });
        toast(win, st, "Removing the passkey…");
    }
}

// ---------------------------------------------------------------- folders

fn rename_folder(win: &AppWindow, st: &Shared, name: &str) {
    let new = clean_folder_name(name);
    if new.is_empty() {
        toast(win, st, "Give the folder a name");
        return;
    }
    let command = {
        let mut state = st.borrow_mut();
        let Shown::Group(key) = state.shown.clone() else {
            return;
        };
        let Some(t) = folder_target(&state, &key) else {
            return;
        };
        if new == t.path {
            drop(state);
            win.global::<ItemExtras>().set_folder_mode(0);
            return;
        }
        let profile = state.accounts[t.account].profile.id.clone();
        let new_key = format!("{profile}/f/{new}");
        if state.expanded.contains(&key) {
            state.expanded.insert(new_key.clone());
        }
        // Open the folders it now sits in, so it can be shown afterwards.
        if let Some((parents, _)) = new.rsplit_once('/') {
            let mut prefix = String::new();
            for part in parents.split('/') {
                if !prefix.is_empty() {
                    prefix.push('/');
                }
                prefix.push_str(part);
                state.expanded.insert(format!("{profile}/f/{prefix}"));
            }
        }
        state.extras.folder_after = Some(new_key);
        state.extras.folder_busy = true;
        // A parent with nested folders (or one that exists only through
        // them) is renamed with everything under it.
        let command = match t.id {
            Some(id) if !t.nested => Command::RenameFolder { id, name: new },
            _ => Command::RenameFolderTree { old: t.path, new },
        };
        (t.account, command)
    };
    send(st, command.0, command.1);
    render_extras(win, st);
}

fn delete_folder(win: &AppWindow, st: &Shared) {
    let command = {
        let mut state = st.borrow_mut();
        let Shown::Group(key) = state.shown.clone() else {
            return;
        };
        let Some(t) = folder_target(&state, &key) else {
            return;
        };
        let Some(id) = t.id else { return };
        let profile = state.accounts[t.account].profile.id.clone();
        state.extras.folder_after = Some(format!("{profile}/nofolder"));
        state.extras.folder_busy = true;
        (t.account, Command::DeleteFolder(id))
    };
    send(st, command.0, command.1);
    render_extras(win, st);
}

// ---------------------------------------------------------------- SSH keys

/// The ID of the SSH key draft being edited, if that is what is shown.
fn ssh_draft(state: &State) -> Option<String> {
    let d = state.draft.as_ref()?;
    (state.editing_shown() && d.item.kind == ItemType::SshKey).then(|| d.item.id.clone())
}

fn generate_ssh_key(win: &AppWindow, st: &Shared, index: i32) {
    let Some(algorithm) = ALGORITHMS.get(index.max(0) as usize).copied() else {
        return;
    };
    let Some(target) = ssh_draft(&st.borrow()) else {
        return;
    };
    {
        let mut state = st.borrow_mut();
        if state.extras.ssh_busy {
            return;
        }
        state.extras.ssh_busy = true;
        state.extras.ssh_error.clear();
        state.extras.ssh_pending = None;
    }
    render_extras(win, st);
    std::thread::spawn(move || {
        let result = sshkey::generate(algorithm);
        on_ui(move |win, st| ssh_key_ready(win, st, &target, None, result, "Generated a new key"));
    });
}

fn read_key_file(path: &Path) -> Result<Zeroizing<String>, String> {
    use std::io::Read;
    let file = std::fs::File::open(path).map_err(|e| format!("Could not open the file: {e}"))?;
    let mut bytes = Zeroizing::new(Vec::new());
    file.take(MAX_KEY_FILE + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| format!("Could not read the file: {e}"))?;
    if bytes.len() as u64 > MAX_KEY_FILE {
        return Err("This file is too large to be a private key".into());
    }
    match std::str::from_utf8(&bytes) {
        Ok(text) => Ok(Zeroizing::new(text.to_string())),
        Err(_) => Err("This is not a private key file".into()),
    }
}

fn import_ssh_key(win: &AppWindow, st: &Shared) {
    let Some(target) = ssh_draft(&st.borrow()) else {
        return;
    };
    {
        let mut state = st.borrow_mut();
        if state.extras.ssh_busy {
            return;
        }
        state.extras.ssh_busy = true;
    }
    render_extras(win, st);
    std::thread::spawn(move || {
        let picked = rfd::FileDialog::new()
            .set_title("Choose a private key")
            .pick_file();
        let Some(path) = picked else {
            on_ui(|win, st| {
                st.borrow_mut().extras.ssh_busy = false;
                render_extras(win, st);
            });
            return;
        };
        match read_key_file(&path) {
            Ok(text) => {
                let result = sshkey::import(&text, None);
                on_ui(move |win, st| {
                    ssh_key_ready(win, st, &target, Some(text), result, "Imported the key")
                });
            }
            Err(message) => on_ui(move |win, st| {
                {
                    let mut state = st.borrow_mut();
                    state.extras.ssh_busy = false;
                    state.extras.ssh_error = message;
                }
                render_extras(win, st);
            }),
        }
    });
}

fn ssh_passphrase(win: &AppWindow, st: &Shared, passphrase: SharedString) {
    let passphrase = Zeroizing::new(passphrase.to_string());
    let Some(target) = ssh_draft(&st.borrow()) else {
        return;
    };
    let text = {
        let mut state = st.borrow_mut();
        let Some(text) = state.extras.ssh_pending.clone() else {
            return;
        };
        if state.extras.ssh_busy {
            return;
        }
        state.extras.ssh_busy = true;
        state.extras.ssh_error.clear();
        text
    };
    render_extras(win, st);
    std::thread::spawn(move || {
        let result = sshkey::import(&text, Some(&passphrase));
        on_ui(move |win, st| {
            ssh_key_ready(win, st, &target, Some(text), result, "Unlocked the key")
        });
    });
}

fn cancel_ssh_import(win: &AppWindow, st: &Shared) {
    {
        let mut state = st.borrow_mut();
        state.extras.ssh_pending = None;
        state.extras.ssh_error = "A key with a passphrase cannot be used until it is unlocked. Import it again, or paste a key without one.".into();
    }
    render_extras(win, st);
}

/// Puts a generated or imported key into the draft, or asks for its
/// passphrase. `text` is the key as read, kept for the passphrase.
fn ssh_key_ready(
    win: &AppWindow,
    st: &Shared,
    target: &str,
    text: Option<Zeroizing<String>>,
    result: Result<SshKey, SshKeyError>,
    done: &str,
) {
    let still_editing = {
        let mut state = st.borrow_mut();
        state.extras.ssh_busy = false;
        ssh_draft(&state).as_deref() == Some(target)
    };
    if !still_editing {
        render_extras(win, st);
        return;
    }
    match result {
        Ok(key) => {
            {
                let mut state = st.borrow_mut();
                state.extras.ssh_pending = None;
                state.extras.ssh_error.clear();
                if let Some(d) = state.draft.as_mut() {
                    set_key_fields(&mut d.item, &key);
                }
            }
            render(win, st);
            toast(win, st, done);
        }
        Err(SshKeyError::PassphraseNeeded) => {
            st.borrow_mut().extras.ssh_pending = text;
            render_extras(win, st);
        }
        Err(SshKeyError::WrongPassphrase) => {
            {
                let mut state = st.borrow_mut();
                state.extras.ssh_pending = text;
                state.extras.ssh_error = "That passphrase did not unlock the key".into();
            }
            render_extras(win, st);
        }
        Err(e) => {
            {
                let mut state = st.borrow_mut();
                state.extras.ssh_pending = None;
                state.extras.ssh_error = sentence(&e.to_string());
            }
            render_extras(win, st);
        }
    }
}

fn sentence(text: &str) -> String {
    let mut chars = text.chars();
    match chars.next() {
        Some(first) => first.to_uppercase().chain(chars).collect(),
        None => String::new(),
    }
}

fn set_key_fields(item: &mut Item, key: &SshKey) {
    for field in item.sections.iter_mut().flat_map(|s| s.fields.iter_mut()) {
        match field.path {
            FieldPath::SshPrivate => field.value = key.private_key.clone(),
            FieldPath::SshPublic => field.value = key.public_key.clone(),
            FieldPath::SshFingerprint => field.value = key.fingerprint.clone(),
            _ => {}
        }
    }
}

/// After an edit of an SSH private key field, works out the public key and
/// fingerprint again (or notices a passphrase-protected key).
pub(super) fn private_key_edited(win: &AppWindow, st: &Shared, section: usize, field: usize) {
    let text = {
        let state = st.borrow();
        match state
            .shown_sections
            .get(section)
            .and_then(|s| s.fields.get(field))
        {
            Some(f) if f.path == FieldPath::SshPrivate => Zeroizing::new(f.value.clone()),
            _ => return,
        }
    };
    let result = (!text.trim().is_empty()).then(|| sshkey::from_private(&text));
    {
        let mut state = st.borrow_mut();
        let x = &mut state.extras;
        x.ssh_pending = None;
        x.ssh_error.clear();
        match &result {
            None | Some(Ok(_)) => {}
            Some(Err(SshKeyError::PassphraseNeeded)) => x.ssh_pending = Some(text.clone()),
            // Only complain about a whole key, not one still being pasted or typed.
            Some(Err(e)) if text.contains("-----END") => x.ssh_error = sentence(&e.to_string()),
            Some(Err(_)) => {}
        }
    }
    if let Some(Ok(key)) = result {
        let converted = key.private_key.trim() != text.trim();
        update_key_rows(win, st, &key, converted);
    }
    render_extras(win, st);
}

/// Writes a key's values into the shown fields while editing. The private
/// key is rewritten only when it was converted (from PKCS#8, say), so the
/// field being typed in is otherwise left alone.
fn update_key_rows(win: &AppWindow, st: &Shared, key: &SshKey, replace_private: bool) {
    {
        let mut state = st.borrow_mut();
        let state = &mut *state;
        for (model, section) in state
            .section_models
            .iter()
            .zip(state.shown_sections.iter_mut())
        {
            for (row, field) in section.fields.iter_mut().enumerate() {
                let value = match field.path {
                    FieldPath::SshPublic => &key.public_key,
                    FieldPath::SshFingerprint => &key.fingerprint,
                    FieldPath::SshPrivate if replace_private => &key.private_key,
                    _ => continue,
                };
                if field.value == *value {
                    continue;
                }
                field.value = value.clone();
                // Re-insert the row so its editor picks up the new value.
                if row < model.row_count() {
                    model.remove(row);
                    model.insert(row, to_detail(field, false));
                }
            }
        }
    }
    sync_draft_sections(win, st);
}

// ---------------------------------------------------------------- events

/// Handles the worker's answers to the extras' commands, and the master
/// password check for the re-prompt.
pub(super) fn handle_extras_event(win: &AppWindow, st: &Shared, account: usize, event: Event) {
    match event {
        Event::PasswordVerified => {
            {
                let mut state = st.borrow_mut();
                let waiting = state.extras.verifying.take();
                let shown = state.shown_item();
                if let (Some((_, item)), Some((a, id))) = (waiting, shown)
                    && a == account
                    && item == id
                {
                    state.mark_verified(a, &id);
                }
            }
            render(win, st);
        }
        Event::PasswordRejected => {
            {
                let mut state = st.borrow_mut();
                state.extras.verifying = None;
                state.extras.reprompt_error = "That is not the master password".into();
            }
            render_extras(win, st);
        }
        Event::ItemActionDone { vault, message } => {
            let (profile, after) = {
                let mut state = st.borrow_mut();
                clear_busy(&mut state.extras);
                state.extras.move_mode = MoveMode::Closed;
                // A draft of a changed item must send the new revision when saved.
                if let Some(d) = state.draft.as_mut()
                    && d.account == account
                    && !d.is_new
                    && let Some(fresh) = vault.item(&d.item.id)
                {
                    d.core = fresh.clone();
                }
                (
                    state.accounts[account].profile.id.clone(),
                    state.extras.folder_after.take(),
                )
            };
            handle_account_event(win, st, &profile, Event::Changed { vault, message });
            if let Some(key) = after {
                show_folder_after(win, st, &key, &profile);
            }
            render_extras(win, st);
        }
        Event::ItemActionFailed { message } => {
            {
                let mut state = st.borrow_mut();
                clear_busy(&mut state.extras);
                state.extras.folder_after = None;
            }
            if !message.is_empty() {
                toast(win, st, &message);
            }
            render_extras(win, st);
        }
        Event::AttachmentWritten { path, open } => {
            st.borrow_mut().extras.attachment_busy.clear();
            if open {
                open_file(win, st, &path);
            } else {
                let name = path
                    .file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_default();
                toast(win, st, &format!("Saved “{name}”"));
            }
            render_extras(win, st);
        }
        _ => {}
    }
}

/// After a folder was renamed or deleted, shows the renamed folder (or No
/// folder, or else the account) in place of the row that is gone. Leaves the
/// pane alone if the user went elsewhere meanwhile.
fn show_folder_after(win: &AppWindow, st: &Shared, key: &str, profile: &str) {
    let target = {
        let state = st.borrow();
        let gone = matches!(&state.shown, Shown::Group(k) if state.row(k).is_none());
        if !gone {
            return;
        }
        if state.row(key).is_some() {
            key.to_string()
        } else {
            profile.to_string()
        }
    };
    select(win, st, &target);
}

fn clear_busy(x: &mut Extras) {
    x.attachment_busy.clear();
    x.move_busy = false;
    x.folder_busy = false;
}

/// Forgets what the extras hold for an account that locked: the answered
/// re-prompt, a pending key passphrase and its opened attachments.
pub(super) fn forget_extras(st: &Shared, account: usize) {
    let mut state = st.borrow_mut();
    let Some(profile) = state.accounts.get(account).map(|a| a.profile.id.clone()) else {
        return;
    };
    let x = &mut state.extras;
    if x.verified.as_ref().is_some_and(|(p, _)| *p == profile) {
        x.verified = None;
    }
    if x.verifying.as_ref().is_some_and(|(p, _)| *p == profile) {
        x.verifying = None;
    }
    x.ssh_pending = None;
    clear_busy(x);
    delete_opened(&mut state, Some(&profile));
}

impl App {
    /// Deletes the temporary copies of opened attachments; call on quit.
    pub fn forget_opened_files(&self) {
        CONTEXT.with(|c| {
            if let Some((_, st)) = c.borrow().as_ref() {
                delete_opened(&mut st.borrow_mut(), None);
            }
        });
    }
}

// ---------------------------------------------------------------- wiring

pub(super) fn wire_extras(w: &AppWindow, state: &Shared) {
    let data = w.global::<ItemExtras>();
    let weak = w.as_weak();
    macro_rules! on {
        ($setter:ident, |$win:ident, $st:ident $(, $arg:ident : $ty:ty)*| $body:block) => {{
            let weak = weak.clone();
            let state = state.clone();
            data.$setter(move |$($arg: $ty),*| {
                let Some($win) = weak.upgrade() else { return };
                let $st = &state;
                $st.borrow_mut().last_activity = Instant::now();
                $body
            });
        }};
    }
    on!(on_menu_picked, |win, st, id: SharedString| {
        menu_picked(&win, st, &id);
    });
    on!(on_verify, |win, st, password: SharedString| {
        verify(&win, st, password);
    });
    on!(on_set_reprompt, |win, st, on: bool| {
        set_draft_reprompt(&win, st, on);
    });
    on!(on_save_attachment, |win, st, index: i32| {
        save_attachment(&win, st, index);
    });
    on!(on_open_attachment, |win, st, index: i32| {
        open_attachment(&win, st, index);
    });
    on!(on_delete_attachment, |win, st, index: i32| {
        delete_attachment(&win, st, index);
    });
    on!(on_add_attachment, |win, st| {
        add_attachment(&win, st);
    });
    on!(on_remove_passkey, |win, st, index: i32| {
        remove_passkey(&win, st, index);
    });
    on!(on_pick_organization, |win, st, index: i32| {
        pick_organization(&win, st, index);
    });
    on!(on_toggle_collection, |win, st, index: i32, on: bool| {
        toggle_collection(&win, st, index, on);
    });
    on!(on_confirm_move, |win, st| {
        confirm_move(&win, st);
    });
    on!(on_cancel_move, |win, st| {
        st.borrow_mut().extras.move_mode = MoveMode::Closed;
        render_extras(&win, st);
    });
    on!(on_rename_folder, |win, st, name: SharedString| {
        rename_folder(&win, st, &name);
    });
    on!(on_delete_folder, |win, st| {
        delete_folder(&win, st);
    });
    on!(on_generate_ssh_key, |win, st, index: i32| {
        generate_ssh_key(&win, st, index);
    });
    on!(on_import_ssh_key, |win, st| {
        import_ssh_key(&win, st);
    });
    on!(on_ssh_passphrase, |win, st, passphrase: SharedString| {
        ssh_passphrase(&win, st, passphrase);
    });
    on!(on_cancel_ssh_import, |win, st| {
        cancel_ssh_import(&win, st);
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use hushjar_core::vault::{Attachment, CustomField, FieldType, ItemKind, Passkey, Uri};

    fn login() -> core::Item {
        let mut item = core::Item::new(ItemKind::Login, Some("org".into()), Some("work".into()));
        item.id = "abc".into();
        item.name = "Mail".into();
        item.notes = "note".into();
        item.reprompt = true;
        item.collection_ids = vec!["c1".into()];
        item.login.username = "sam".into();
        item.login.password = "pw".into();
        item.login.totp = "JBSWY3DPEHPK3PXP".into();
        item.login.uris = vec![Uri {
            uri: "https://mail.example".into(),
            match_type: Some(3),
        }];
        item.login.passkeys = 1;
        item.login.passkey_details = vec![Passkey {
            credential_id: "cred".into(),
            ..Default::default()
        }];
        item.fields = vec![CustomField {
            name: "PIN".into(),
            value: "1234".into(),
            kind: FieldType::Hidden,
            linked_id: None,
        }];
        item.password_history = vec![core::PasswordEntry {
            password: "old".into(),
            last_used: "2026-01-01T00:00:00Z".into(),
        }];
        item.attachments = vec![Attachment {
            id: "a1".into(),
            file_name: "scan.pdf".into(),
            size: 10,
            size_name: "10 Bytes".into(),
        }];
        item.created = "2026-01-01T00:00:00Z".into();
        item.raw = serde_json::json!({ "id": "abc", "key": "2.x|y|z" });
        item
    }

    #[test]
    fn clone_copies_values_but_not_identity_files_or_passkeys() {
        let original = login();
        let copy = clone_item(&original).expect("clonable");
        assert!(copy.is_new(), "a copy is a new item");
        assert_eq!(copy.name, "Mail (copy)");
        assert_eq!(copy.kind, ItemKind::Login);
        assert_eq!(copy.organization_id.as_deref(), Some("org"));
        assert_eq!(copy.folder_id.as_deref(), Some("work"));
        assert_eq!(copy.collection_ids, vec!["c1".to_string()]);
        assert_eq!(copy.login.username, "sam");
        assert_eq!(copy.login.password, "pw");
        assert_eq!(copy.login.totp, original.login.totp);
        assert_eq!(copy.login.uris, original.login.uris);
        assert_eq!(copy.fields, original.fields);
        assert_eq!(copy.notes, "note");
        assert!(copy.reprompt);
        assert_eq!(copy.login.passkeys, 0);
        assert!(copy.login.passkey_details.is_empty());
        assert!(copy.attachments.is_empty());
        assert!(copy.password_history.is_empty());
        assert!(copy.raw.is_null(), "no keys or JSON of the original reused");
        assert!(copy.created.is_empty());
    }

    #[test]
    fn clone_refuses_what_it_cannot_copy() {
        let mut hidden = login();
        hidden.view_password = false;
        assert!(
            clone_item(&hidden).is_none(),
            "would reveal a hidden password"
        );
        let mut broken = login();
        broken.unreadable = 1;
        assert!(clone_item(&broken).is_none());
        let other = core::Item::new(ItemKind::Other(9), None, None);
        assert!(clone_item(&other).is_none());
        let mut trashed = login();
        trashed.deleted = true;
        assert!(clone_item(&trashed).is_none());
        assert_eq!(copy_name("  "), "Copy");
    }

    #[test]
    fn reprompt_masks_hidden_values_only() {
        let item = model::from_core(&login());
        let fields: Vec<&Field> = item.sections.iter().flat_map(|s| &s.fields).collect();
        for field in fields {
            let shown = shown_detail(field, true, true);
            let hidden = matches!(field.kind, FieldKind::Secret | FieldKind::Totp);
            if hidden {
                assert_eq!(shown.value.as_str(), REPROMPT_MASK, "{}", field.label);
                assert_eq!(shown.kind, FieldKind::Info);
                assert!(!shown.copyable);
            } else {
                assert_eq!(shown, to_detail(field, true), "{}", field.label);
            }
            assert_eq!(shown_detail(field, true, false), to_detail(field, true));
        }
        let password = item.field_at(FieldPath::Password).unwrap();
        assert_ne!(shown_detail(password, true, true).value.as_str(), "pw");

        let mut ssh = core::Item::new(ItemKind::SshKey, None, None);
        ssh.ssh_key.private_key = "secret".into();
        ssh.ssh_key.public_key = "ssh-ed25519 AAAA".into();
        let ssh = model::from_core(&ssh);
        let private = ssh.field_at(FieldPath::SshPrivate).unwrap();
        assert_eq!(
            shown_detail(private, true, true).value.as_str(),
            REPROMPT_MASK
        );
        let public = ssh.field_at(FieldPath::SshPublic).unwrap();
        assert_eq!(
            shown_detail(public, true, true).value.as_str(),
            "ssh-ed25519 AAAA"
        );
    }

    #[test]
    fn sizes_read_naturally() {
        assert_eq!(format_size(0), "0 bytes");
        assert_eq!(format_size(1), "1 byte");
        assert_eq!(format_size(1023), "1023 bytes");
        assert_eq!(format_size(1024), "1 KB");
        assert_eq!(format_size(1234), "1.2 KB");
        assert_eq!(format_size(1536 * 1024), "1.5 MB");
        assert_eq!(format_size(150 * 1024 * 1024 + 1), "150 MB");
        assert_eq!(format_size(MAX_ATTACHMENT), "500 MB");
        assert_eq!(format_size(3 * 1024 * 1024 * 1024), "3 GB");
        assert_eq!(
            too_large("film.mkv", 612 * 1024 * 1024),
            "“film.mkv” is 612 MB. Attachments can be at most 500 MB."
        );
    }

    #[test]
    fn file_names_stay_in_their_folder() {
        assert_eq!(safe_file_name("scan.pdf"), "scan.pdf");
        assert_eq!(safe_file_name("../../etc/passwd"), "passwd");
        assert_eq!(safe_file_name("a\\b\\c.txt"), "c.txt");
        assert_eq!(safe_file_name(".."), "attachment");
        assert_eq!(safe_file_name("bad\nname"), "badname");
        assert_eq!(safe_file_name(""), "attachment");
    }

    #[test]
    fn folder_names_and_notes() {
        assert_eq!(clean_folder_name(" Work / Code /"), "Work/Code");
        assert_eq!(clean_folder_name("//"), "");
        assert_eq!(
            folder_delete_note("Work", 2, true),
            "Delete the folder “Work”? Its 2 items are kept and move to No folder. The folders inside it are kept too."
        );
        assert_eq!(
            folder_delete_note("Old", 0, false),
            "Delete the folder “Old”? It has no items."
        );
    }

    #[test]
    fn menu_follows_permissions() {
        let ids = |entries: Vec<MenuEntry>| -> Vec<String> {
            entries.iter().map(|e| e.id.to_string()).collect()
        };
        let mut personal = login();
        personal.organization_id = None;
        assert_eq!(
            ids(menu_entries(&personal, true, true)),
            ["clone", "archive", "move", "reprompt"]
        );
        assert_eq!(
            ids(menu_entries(&personal, true, false)),
            ["clone", "archive", "reprompt"]
        );
        let org = login();
        assert_eq!(
            ids(menu_entries(&org, true, true)),
            ["clone", "archive", "collections", "reprompt"]
        );
        let mut read_only = login();
        read_only.editable = false;
        assert_eq!(ids(menu_entries(&read_only, true, true)), ["clone"]);
        let entries = menu_entries(&org, false, true);
        assert!(
            entries.iter().all(|e| !e.enabled),
            "offline: shown but disabled"
        );
        let reprompt = entries.iter().find(|e| e.id == "reprompt").unwrap();
        assert!(reprompt.toggle && reprompt.checked);
        let mut archived = login();
        archived.archived = true;
        assert_eq!(
            menu_entries(&archived, true, true)[1].label.as_str(),
            "Take out of archive"
        );
    }
}

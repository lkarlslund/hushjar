//! The Send screen: a list of Sends across the unlocked accounts and a form
//! to make or change one.
//!
//! The list is rebuilt from the vaults on every render. The form's values
//! live in the Slint `SendsData` properties while the user types and are
//! read back when they press Save, so a sync never overwrites a half-typed
//! Send.

use hushjar_core::api::MAX_FILE_BYTES;
use hushjar_core::send::{SendEntry, SendKind};
use hushjar_core::vault::iso_in;

use super::*;
use crate::{SendRow, SendsData};

/// How long from now a Send is deleted or stops being shared, as in the
/// Bitwarden apps. The longest is 30 days; Vaultwarden allows up to 31.
const CHOICES: [(&str, i64); 7] = [
    ("In 1 hour", 3_600),
    ("In 1 day", 86_400),
    ("In 2 days", 2 * 86_400),
    ("In 3 days", 3 * 86_400),
    ("In 7 days", 7 * 86_400),
    ("In 14 days", 14 * 86_400),
    ("In 30 days", 30 * 86_400),
];

/// The position of "In 7 days" in [`CHOICES`], the default deletion time.
const DEFAULT_DELETION: i32 = 4;

/// What a pick in a date box means.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DateChoice {
    /// Leave the Send's current date alone.
    Keep,
    Never,
    In(i64),
}

/// Maps a position in a date box to its meaning. Boxes for a saved Send
/// start with "Keep", and the expiry box has "Never" before the times.
fn date_choice(index: i32, existing: bool, allow_never: bool) -> DateChoice {
    let mut i = index.max(0) as usize;
    if existing {
        if i == 0 {
            return DateChoice::Keep;
        }
        i -= 1;
    }
    if allow_never {
        if i == 0 {
            return DateChoice::Never;
        }
        i -= 1;
    }
    CHOICES
        .get(i)
        .map_or(DateChoice::Keep, |(_, secs)| DateChoice::In(*secs))
}

/// The entries of a date box; `keep` is the first entry for a saved Send.
fn date_options(keep: Option<String>, allow_never: bool) -> Vec<String> {
    let mut list = Vec::new();
    list.extend(keep);
    if allow_never {
        list.push("Never".into());
    }
    list.extend(CHOICES.iter().map(|(label, _)| (*label).to_string()));
    list
}

/// A length of time in words: "5 minutes", "1 hour", "3 days".
fn span_text(seconds: i64) -> String {
    let (n, unit) = match seconds {
        ..=3_599 => ((seconds / 60).max(1), "minute"),
        3_600..=86_399 => (seconds / 3_600, "hour"),
        _ => (seconds / 86_400, "day"),
    };
    format!("{n} {unit}{}", if n == 1 { "" } else { "s" })
}

/// Seconds since 1970 for an ISO timestamp such as `2026-12-03T10:00:00.000Z`.
fn parse_iso(text: &str) -> Option<i64> {
    let field = |from: usize, to: usize| -> Option<i64> { text.get(from..to)?.parse().ok() };
    let (year, month, day) = (field(0, 4)?, field(5, 7)?, field(8, 10)?);
    let (hour, minute, second) = (field(11, 13)?, field(14, 16)?, field(17, 19)?);
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }
    // Howard Hinnant's days-from-civil algorithm.
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let doy = (153 * ((month + 9) % 12) + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    Some(days * 86_400 + hour * 3_600 + minute * 60 + second)
}

/// "in 3 days", or "already passed", for the "Keep" entries.
fn when_text(iso: &str, now: i64) -> String {
    match parse_iso(iso) {
        Some(at) if at > now => format!("in {}", span_text(at - now)),
        Some(_) => "already passed".into(),
        None => "unknown".into(),
    }
}

/// The short labels on a Send in the list.
fn status_chips(send: &SendEntry, now: i64) -> Vec<String> {
    let mut chips = Vec::new();
    if send.disabled {
        chips.push("Disabled".into());
    }
    match (&send.expiration_date, parse_iso(&send.deletion_date)) {
        (Some(expiry), _) => match parse_iso(expiry) {
            Some(at) if at > now => chips.push(format!("Expires in {}", span_text(at - now))),
            Some(_) => chips.push("Expired".into()),
            None => {}
        },
        (None, Some(at)) if at > now => {
            chips.push(format!("Deletes in {}", span_text(at - now)));
        }
        (None, Some(_)) => chips.push("Deleting soon".into()),
        (None, None) => {}
    }
    if send.has_password {
        chips.push("Password".into());
    }
    if let Some(max) = send.max_access_count {
        chips.push(format!("{}/{max} views", send.access_count));
    }
    chips
}

/// One line of the list, with where to find the Send again.
#[derive(Debug, PartialEq)]
struct RowInfo {
    account: usize,
    id: String,
    name: String,
    kind: SendKind,
    chips: Vec<String>,
}

/// The list over several accounts' Sends, sorted by name.
fn build_rows(accounts: &[(usize, &[SendEntry])], now: i64) -> Vec<RowInfo> {
    let mut rows: Vec<RowInfo> = accounts
        .iter()
        .flat_map(|(account, sends)| {
            sends.iter().map(move |send| RowInfo {
                account: *account,
                id: send.id.clone(),
                name: send.name.clone(),
                kind: send.kind,
                chips: status_chips(send, now),
            })
        })
        .collect();
    rows.sort_by(|a, b| (a.name.to_lowercase(), &a.id).cmp(&(b.name.to_lowercase(), &b.id)));
    rows
}

/// The values of the form, as typed.
struct Form {
    name: String,
    text: String,
    hide_text: bool,
    notes: String,
    max_views: String,
    password: Zeroizing<String>,
    remove_password: bool,
    hide_email: bool,
    disabled: bool,
    deletion_index: i32,
    expiry_index: i32,
}

/// The most views a Send can be limited to: the server stores a 32-bit number.
fn parse_max_views(text: &str) -> Result<Option<u64>, String> {
    let text = text.trim();
    if text.is_empty() {
        return Ok(None);
    }
    match text.parse::<u64>() {
        Ok(n) if (1..=i32::MAX as u64).contains(&n) => Ok(Some(n)),
        _ => Err("Type a whole number of views, or leave it empty for no limit.".into()),
    }
}

/// Puts the form's values into `send`, or says what is wrong with them.
fn apply_form(send: &mut SendEntry, form: &Form) -> Result<(), String> {
    let existing = !send.is_new();
    if form.name.trim().is_empty() {
        return Err("Give the Send a name.".into());
    }
    if send.kind == SendKind::Text && form.text.is_empty() {
        return Err("Type the text you want to share.".into());
    }
    send.max_access_count = parse_max_views(&form.max_views)?;
    send.name = form.name.trim().to_string();
    send.notes = form.notes.clone();
    if send.kind == SendKind::Text {
        send.text = form.text.clone();
        send.hide_text = form.hide_text;
    }
    send.hide_email = form.hide_email;
    send.disabled = form.disabled;
    if let DateChoice::In(secs) = date_choice(form.deletion_index, existing, false) {
        send.deletion_date = iso_in(secs);
    }
    match date_choice(form.expiry_index, existing, true) {
        DateChoice::Keep => {}
        DateChoice::Never => send.expiration_date = None,
        DateChoice::In(secs) => send.expiration_date = Some(iso_in(secs)),
    }
    Ok(())
}

/// Whether organisation policies stop the user from making or changing
/// Sends. Policies feed this; while it is true the screen explains why and
/// disables creating and saving.
fn send_disabled(state: &State) -> bool {
    state
        .accounts
        .iter()
        .any(|a| a.vault.is_some() && a.policies.as_ref().is_some_and(|p| p.send_disabled))
}

/// A file picked in the dialog, read into memory.
struct PickedFile {
    name: String,
    bytes: Zeroizing<Vec<u8>>,
}

/// The Send being made or edited.
struct SendDraft {
    account: usize,
    send: SendEntry,
    file: Option<PickedFile>,
}

#[derive(Default)]
pub(super) struct Sends {
    draft: Option<SendDraft>,
    picking: bool,
}

impl Sends {
    /// Whether a form is open, and so may hold typed text.
    pub(super) fn has_draft(&self) -> bool {
        self.draft.is_some()
    }
}

fn now() -> i64 {
    unix_now() as i64
}

fn size_text(bytes: usize) -> String {
    const UNITS: [&str; 4] = ["bytes", "KB", "MB", "GB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} bytes")
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

impl State {
    /// The accounts with an open vault, in the order they are listed.
    fn unlocked(&self) -> Vec<usize> {
        (0..self.accounts.len())
            .filter(|i| self.accounts[*i].vault.is_some())
            .collect()
    }

    fn send_rows(&self) -> Vec<RowInfo> {
        let lists: Vec<(usize, &[SendEntry])> = self
            .unlocked()
            .into_iter()
            .filter_map(|i| Some((i, self.accounts[i].vault.as_ref()?.sends.as_slice())))
            .collect();
        build_rows(&lists, now())
    }
}

pub(super) fn show_sends(win: &AppWindow, st: &Shared) {
    if !leave_to(win, st, Pending::Sends) {
        return;
    }
    {
        let mut state = st.borrow_mut();
        state.shown = Shown::Sends;
        state.selected = None;
        state.sends.draft = None;
    }
    win.set_selected_key(SharedString::new());
    win.set_selected_index(-1);
    load_form(win, st);
    render(win, st);
}

/// Refreshes the list and the status of the screen. Leaves the form alone,
/// except when the Send it shows has been deleted.
pub(super) fn render_sends(win: &AppWindow, st: &Shared) {
    let gone = {
        let state = st.borrow();
        state.sends.draft.as_ref().is_some_and(|d| {
            !d.send.is_new()
                && !state.accounts.get(d.account).is_some_and(|a| {
                    a.vault
                        .as_ref()
                        .is_some_and(|v| v.sends.iter().any(|x| x.id == d.send.id))
                })
        })
    };
    if gone {
        st.borrow_mut().sends.draft = None;
        load_form(win, st);
    }
    let state = st.borrow();
    let many = state.unlocked().len() > 1;
    let rows = state.send_rows();
    let draft = state.sends.draft.as_ref();
    let selected = draft
        .filter(|d| !d.send.is_new())
        .and_then(|d| {
            rows.iter()
                .position(|r| r.account == d.account && r.id == d.send.id)
        })
        .map_or(-1, |i| i as i32);
    let models: Vec<SendRow> = rows
        .iter()
        .map(|r| {
            let view = &state.accounts[r.account].view;
            SendRow {
                name: s(&r.name),
                kind: match r.kind {
                    SendKind::Text => 0,
                    SendKind::File => 1,
                    SendKind::Other(_) => 2,
                },
                show_account: many,
                initials: s(&view.initials),
                tint: color(view.tint),
                chips: ModelRc::new(VecModel::from(
                    r.chips.iter().map(|c| s(c)).collect::<Vec<_>>(),
                )),
            }
        })
        .collect();
    let data = win.global::<SendsData>();
    data.set_rows(ModelRc::new(VecModel::from(models)));
    data.set_selected(selected);
    let policy = send_disabled(&state);
    let none = state.unlocked().is_empty();
    data.set_blocked(policy || none);
    data.set_message(s(if policy {
        "Your organisation does not allow you to make or change Sends."
    } else if none {
        "Unlock an account to see and make Sends."
    } else {
        ""
    }));
    data.set_busy(draft.is_some_and(|d| state.accounts.get(d.account).is_some_and(|a| a.busy)));
    data.set_can_copy_link(draft.is_some_and(|d| link_for(&state, d).is_some()));
}

/// The share link of a saved Send.
fn link_for(state: &State, draft: &SendDraft) -> Option<Zeroizing<String>> {
    if draft.send.access_id.is_empty() {
        return None;
    }
    let key = draft.send.key.as_ref()?;
    let account = state.accounts.get(draft.account)?;
    Some(Zeroizing::new(
        account
            .profile
            .server
            .send_link(&draft.send.access_id, key.material()),
    ))
}

/// Puts the draft's values into the form, or empties the form.
fn load_form(win: &AppWindow, st: &Shared) {
    let state = st.borrow();
    let data = win.global::<SendsData>();
    let Some(d) = state.sends.draft.as_ref() else {
        clear_form(&data);
        return;
    };
    let send = &d.send;
    let existing = !send.is_new();
    let at = now();
    let strings = |list: Vec<String>| {
        ModelRc::new(VecModel::from(
            list.iter().map(|o| s(o)).collect::<Vec<_>>(),
        ))
    };
    data.set_editing(true);
    data.set_is_new(!existing);
    data.set_kind(match send.kind {
        SendKind::Text => 0,
        _ => 1,
    });
    data.set_name(s(&send.name));
    data.set_text(s(&send.text));
    data.set_hide_text(send.hide_text);
    data.set_notes(s(&send.notes));
    data.set_max_views(
        send.max_access_count
            .map(|n| n.to_string())
            .unwrap_or_default()
            .into(),
    );
    data.set_password(SharedString::new());
    data.set_remove_password(false);
    data.set_has_password(send.has_password);
    data.set_hide_email(send.hide_email);
    data.set_disabled(send.disabled);
    data.set_deletion_options(strings(date_options(
        existing.then(|| format!("Keep ({})", when_text(&send.deletion_date, at))),
        false,
    )));
    data.set_deletion_index(if existing { 0 } else { DEFAULT_DELETION });
    data.set_expiry_options(strings(date_options(
        existing.then(|| match &send.expiration_date {
            Some(date) => format!("Keep ({})", when_text(date, at)),
            None => "Keep (never)".into(),
        }),
        true,
    )));
    data.set_expiry_index(0);
    data.set_file_info(s(&file_info(d)));
    data.set_views_note(if existing {
        s(&match send.access_count {
            1 => "It has been opened 1 time.".to_string(),
            n => format!("It has been opened {n} times."),
        })
    } else {
        SharedString::new()
    });
    let unlocked = state.unlocked();
    let emails: Vec<String> = unlocked
        .iter()
        .map(|i| state.accounts[*i].view.email.clone())
        .collect();
    data.set_account_index(unlocked.iter().position(|i| *i == d.account).unwrap_or(0) as i32);
    data.set_account_label(if existing && unlocked.len() > 1 {
        s(&format!("In {}", state.accounts[d.account].view.email))
    } else {
        SharedString::new()
    });
    data.set_account_options(strings(emails));
}

fn file_info(d: &SendDraft) -> String {
    if d.send.kind != SendKind::File {
        return String::new();
    }
    match (&d.send.file, &d.file) {
        (Some(f), _) if !d.send.is_new() => format!("{} · {}", f.file_name, f.size_name),
        (_, Some(f)) => format!("{} · {}", f.name, size_text(f.bytes.len())),
        _ => "No file chosen yet".into(),
    }
}

/// Empties the form so no text or password stays in the window.
fn clear_form(data: &SendsData<'_>) {
    data.set_editing(false);
    data.set_is_new(false);
    data.set_name(SharedString::new());
    data.set_text(SharedString::new());
    data.set_notes(SharedString::new());
    data.set_password(SharedString::new());
    data.set_remove_password(false);
    data.set_file_info(SharedString::new());
}

/// Drops the form and any picked file; used when leaving the pane or locking.
pub(super) fn forget_sends(win: &AppWindow, st: &Shared) {
    st.borrow_mut().sends.draft = None;
    clear_form(&win.global::<SendsData>());
}

fn new_send(win: &AppWindow, st: &Shared, kind: SendKind) {
    {
        let mut state = st.borrow_mut();
        if send_disabled(&state) {
            return;
        }
        let previous = state.sends.draft.as_ref().map(|d| d.account);
        let unlocked = state.unlocked();
        let Some(account) = previous
            .filter(|a| unlocked.contains(a))
            .or_else(|| unlocked.first().copied())
        else {
            return;
        };
        state.sends.draft = Some(SendDraft {
            account,
            send: SendEntry::new(kind),
            file: None,
        });
    }
    load_form(win, st);
    render_sends(win, st);
}

fn select_send(win: &AppWindow, st: &Shared, index: usize) {
    {
        let mut state = st.borrow_mut();
        let Some(row) = state.send_rows().into_iter().nth(index) else {
            return;
        };
        if let SendKind::Other(_) = row.kind {
            drop(state);
            toast(
                win,
                st,
                "This kind of Send can only be opened in another app",
            );
            return;
        }
        let send = state.accounts[row.account]
            .vault
            .as_ref()
            .and_then(|v| v.sends.iter().find(|x| x.id == row.id))
            .cloned();
        let Some(send) = send else { return };
        state.sends.draft = Some(SendDraft {
            account: row.account,
            send,
            file: None,
        });
    }
    load_form(win, st);
    render_sends(win, st);
}

fn read_form(win: &AppWindow) -> Form {
    let data = win.global::<SendsData>();
    Form {
        name: data.get_name().to_string(),
        text: data.get_text().to_string(),
        hide_text: data.get_hide_text(),
        notes: data.get_notes().to_string(),
        max_views: data.get_max_views().to_string(),
        password: Zeroizing::new(data.get_password().to_string()),
        remove_password: data.get_remove_password(),
        hide_email: data.get_hide_email(),
        disabled: data.get_disabled(),
        deletion_index: data.get_deletion_index(),
        expiry_index: data.get_expiry_index(),
    }
}

/// Checks the form and sends the Send to its account's worker.
fn save(win: &AppWindow, st: &Shared) {
    let mut form = read_form(win);
    let mut state = st.borrow_mut();
    if send_disabled(&state) {
        drop(state);
        toast(
            win,
            st,
            "Your organisation does not allow you to change Sends",
        );
        return;
    }
    let Some(d) = state.sends.draft.as_mut() else {
        return;
    };
    let account = d.account;
    if state.accounts.get(account).is_none_or(|a| a.busy) {
        return;
    }
    let d = state.sends.draft.as_ref().expect("checked above");
    let mut send = d.send.clone();
    let picked = d.file.as_ref();
    let is_new_file = send.is_new() && send.kind == SendKind::File;
    if is_new_file && picked.is_none() {
        drop(state);
        toast(win, st, "Choose a file to share first");
        return;
    }
    if form.name.trim().is_empty()
        && let Some(f) = picked
    {
        form.name = f.name.clone();
    }
    if let Err(message) = apply_form(&mut send, &form) {
        drop(state);
        toast(win, st, &message);
        return;
    }
    let password = (!form.password.is_empty()).then(|| form.password.clone());
    let command = match (is_new_file, picked) {
        (true, Some(f)) => Command::CreateFileSend {
            send: Box::new(send),
            file_name: f.name.clone(),
            bytes: f.bytes.clone(),
            password,
        },
        _ => Command::SaveSend {
            send: Box::new(send),
            password,
            remove_password: form.remove_password,
        },
    };
    state.accounts[account].busy = true;
    let _ = state.accounts[account].worker.tx.send(command);
    drop(state);
    win.global::<SendsData>().set_password(SharedString::new());
    render_sends(win, st);
}

fn copy_link(win: &AppWindow, st: &Shared) {
    let link = {
        let state = st.borrow();
        state.sends.draft.as_ref().and_then(|d| link_for(&state, d))
    };
    match link {
        // The link carries the key, so it is copied like a password.
        Some(link) => copy(win, st, &link, "Send link"),
        None => toast(win, st, "Save the Send first to get its link"),
    }
}

fn delete(win: &AppWindow, st: &Shared) {
    let mut state = st.borrow_mut();
    let Some(d) = state.sends.draft.as_ref().filter(|d| !d.send.is_new()) else {
        return;
    };
    let (account, id) = (d.account, d.send.id.clone());
    if state.accounts.get(account).is_none_or(|a| a.busy) {
        return;
    }
    state.accounts[account].busy = true;
    let _ = state.accounts[account]
        .worker
        .tx
        .send(Command::DeleteSend(id));
    drop(state);
    render_sends(win, st);
}

/// Runs `f` on the UI thread with the app, from another thread.
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

/// Reads the chosen file, refusing one the server could not take.
fn read_picked(path: &std::path::Path) -> Result<PickedFile, String> {
    let too_large = || {
        format!(
            "That file is too large. The limit is {} MB.",
            MAX_FILE_BYTES >> 20
        )
    };
    let length = std::fs::metadata(path)
        .map_err(|e| format!("Could not read the file: {e}"))?
        .len();
    if length > MAX_FILE_BYTES as u64 {
        return Err(too_large());
    }
    let bytes = std::fs::read(path).map_err(|e| format!("Could not read the file: {e}"))?;
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .filter(|n| !n.is_empty())
        .ok_or("That file has no name")?;
    Ok(PickedFile {
        name,
        bytes: Zeroizing::new(bytes),
    })
}

/// Opens the file dialog on its own thread, so the window stays alive.
fn pick_file(win: &AppWindow, st: &Shared) {
    let is_new_file = st
        .borrow()
        .sends
        .draft
        .as_ref()
        .is_some_and(|d| d.send.is_new() && d.send.kind == SendKind::File);
    if !is_new_file || std::mem::replace(&mut st.borrow_mut().sends.picking, true) {
        return;
    }
    let _ = win;
    let spawned = std::thread::Builder::new()
        .name("hushjar-file-dialog".into())
        .spawn(|| {
            let result = crate::dialogs::pick_file("Choose a file to share", &[])
                .map(|path| read_picked(&path));
            on_ui(move |win, st| file_picked(win, st, result));
        });
    if spawned.is_err() {
        st.borrow_mut().sends.picking = false;
    }
}

/// The dialog is closed: `None` if nothing was chosen.
fn file_picked(win: &AppWindow, st: &Shared, result: Option<Result<PickedFile, String>>) {
    st.borrow_mut().sends.picking = false;
    match result {
        None => {}
        Some(Err(message)) => toast(win, st, &message),
        Some(Ok(file)) => {
            let data = win.global::<SendsData>();
            if data.get_name().trim().is_empty() {
                data.set_name(s(&file.name));
            }
            if let Some(d) = st.borrow_mut().sends.draft.as_mut() {
                d.file = Some(file);
            }
            load_file_info(win, st);
        }
    }
}

fn load_file_info(win: &AppWindow, st: &Shared) {
    let info = st.borrow().sends.draft.as_ref().map(file_info);
    win.global::<SendsData>()
        .set_file_info(s(&info.unwrap_or_default()));
}

/// A Send was saved: shows the server's copy, and copies a new Send's link.
pub(super) fn saved(
    win: &AppWindow,
    st: &Shared,
    index: usize,
    send: SendEntry,
    vault: Vault,
    link: Option<Zeroizing<String>>,
) {
    let was_new = {
        let mut state = st.borrow_mut();
        let a = &mut state.accounts[index];
        a.view = Account::from_vault(&a.profile, &vault);
        a.vault = Some(vault);
        a.busy = false;
        let was_new = state
            .sends
            .draft
            .as_ref()
            .is_some_and(|d| d.account == index && d.send.is_new());
        if state.shown == Shown::Sends {
            state.sends.draft = Some(SendDraft {
                account: index,
                send,
                file: None,
            });
        }
        was_new
    };
    refresh_tree(win, st);
    if st.borrow().shown == Shown::Sends {
        load_form(win, st);
    }
    render(win, st);
    match link {
        Some(link) if was_new => {
            copy(win, st, &link, "Send link");
        }
        _ => toast(win, st, "Send saved"),
    }
}

/// A new Send may or may not have been made: drop the form so a second
/// Save cannot make a duplicate. The synced list shows what happened.
pub(super) fn save_uncertain(win: &AppWindow, st: &Shared, index: usize) {
    let uncertain = st
        .borrow()
        .sends
        .draft
        .as_ref()
        .is_some_and(|d| d.account == index && d.send.is_new());
    if uncertain {
        forget_sends(win, st);
    }
}

pub(super) fn wire_sends(w: &AppWindow, state: &Shared) {
    let data = w.global::<SendsData>();
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
    on!(on_new_text, |win, st| {
        new_send(&win, st, SendKind::Text);
    });
    on!(on_new_file, |win, st| {
        new_send(&win, st, SendKind::File);
    });
    on!(on_select, |win, st, index: i32| {
        select_send(&win, st, index.max(0) as usize);
    });
    on!(on_account_picked, |win, st, index: i32| {
        {
            let mut state = st.borrow_mut();
            let account = state.unlocked().get(index.max(0) as usize).copied();
            if let (Some(account), Some(d)) = (account, state.sends.draft.as_mut())
                && d.send.is_new()
            {
                d.account = account;
            }
        }
        render_sends(&win, st);
    });
    on!(on_pick_file, |win, st| {
        pick_file(&win, st);
    });
    on!(on_save, |win, st| {
        save(&win, st);
    });
    on!(on_copy_link, |win, st| {
        copy_link(&win, st);
    });
    on!(on_delete, |win, st| {
        delete(&win, st);
    });
    on!(on_close, |win, st| {
        forget_sends(&win, st);
        render_sends(&win, st);
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    const DAY: i64 = 86_400;
    // 2000-03-01T00:00:00Z
    const T0: i64 = 951_868_800;

    fn iso(secs: i64) -> String {
        let (days, rem) = (secs.div_euclid(DAY), secs.rem_euclid(DAY));
        let (y, m, d) = civil_from_days(days);
        format!(
            "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}.000Z",
            rem / 3600,
            rem % 3600 / 60,
            rem % 60
        )
    }

    // Independent of the code under test: the day number to a date by
    // counting forward from 2000-03-01, which is all these tests need.
    fn civil_from_days(days: i64) -> (i64, i64, i64) {
        let from = days - T0.div_euclid(DAY);
        let lengths = [31, 30, 31, 30, 31, 31, 30, 31, 30, 31, 31, 28];
        let (mut y, mut m, mut d) = (2000, 3, from);
        let mut i = 0;
        while d >= lengths[i] {
            d -= lengths[i];
            i += 1;
            m += 1;
            if m == 13 {
                m = 1;
                y += 1;
            }
        }
        (y, m, d + 1)
    }

    fn send(name: &str) -> SendEntry {
        let mut s = SendEntry::new(SendKind::Text);
        s.id = name.into();
        s.name = name.into();
        s.deletion_date = iso(T0 + 7 * DAY);
        s
    }

    fn form() -> Form {
        Form {
            name: "Wifi".into(),
            text: "secret".into(),
            hide_text: true,
            notes: String::new(),
            max_views: String::new(),
            password: Zeroizing::new(String::new()),
            remove_password: false,
            hide_email: false,
            disabled: false,
            deletion_index: DEFAULT_DELETION,
            expiry_index: 0,
        }
    }

    #[test]
    fn parses_timestamps() {
        assert_eq!(parse_iso("1970-01-01T00:00:00.000Z"), Some(0));
        assert_eq!(parse_iso("2000-03-01T00:00:00.000Z"), Some(T0));
        assert_eq!(parse_iso("2000-03-01T01:02:03Z"), Some(T0 + 3723));
        assert_eq!(parse_iso("nonsense"), None);
        assert_eq!(parse_iso("2000-13-01T00:00:00Z"), None);
    }

    #[test]
    fn date_choices_for_new_and_saved_sends() {
        assert_eq!(date_choice(0, false, false), DateChoice::In(3_600));
        assert_eq!(date_choice(4, false, false), DateChoice::In(7 * DAY));
        assert_eq!(date_choice(6, false, false), DateChoice::In(30 * DAY));
        assert_eq!(date_choice(0, true, false), DateChoice::Keep);
        assert_eq!(date_choice(1, true, false), DateChoice::In(3_600));
        assert_eq!(date_choice(0, false, true), DateChoice::Never);
        assert_eq!(date_choice(1, false, true), DateChoice::In(3_600));
        assert_eq!(date_choice(0, true, true), DateChoice::Keep);
        assert_eq!(date_choice(1, true, true), DateChoice::Never);
        assert_eq!(date_choice(2, true, true), DateChoice::In(3_600));
        assert_eq!(date_choice(99, true, true), DateChoice::Keep);
        assert_eq!(date_choice(-1, false, true), DateChoice::Never);
    }

    #[test]
    fn options_line_up_with_choices() {
        assert_eq!(DEFAULT_DELETION as usize, 4);
        assert_eq!(CHOICES[DEFAULT_DELETION as usize].1, 7 * DAY);
        for (existing, never) in [(false, false), (true, false), (false, true), (true, true)] {
            let options = date_options(existing.then(|| "Keep".to_string()), never);
            assert_eq!(
                options.len(),
                CHOICES.len() + usize::from(existing) + usize::from(never)
            );
            // The last option is always the longest time.
            assert_eq!(options.last().map(String::as_str), Some("In 30 days"));
            let last = options.len() as i32 - 1;
            assert_eq!(date_choice(last, existing, never), DateChoice::In(30 * DAY));
        }
    }

    #[test]
    fn spans_in_words() {
        assert_eq!(span_text(10), "1 minute");
        assert_eq!(span_text(5 * 60), "5 minutes");
        assert_eq!(span_text(3_600), "1 hour");
        assert_eq!(span_text(5 * 3_600 + 100), "5 hours");
        assert_eq!(span_text(DAY), "1 day");
        assert_eq!(span_text(3 * DAY + 5), "3 days");
    }

    #[test]
    fn chips_describe_the_send() {
        let mut s = send("a");
        assert_eq!(status_chips(&s, T0), ["Deletes in 7 days"]);
        s.expiration_date = Some(iso(T0 + 3 * DAY));
        s.has_password = true;
        s.max_access_count = Some(10);
        s.access_count = 3;
        assert_eq!(
            status_chips(&s, T0 + 10),
            ["Expires in 2 days", "Password", "3/10 views"]
        );
        s.disabled = true;
        s.expiration_date = Some(iso(T0 + DAY));
        assert_eq!(status_chips(&s, T0 + 2 * DAY)[..2], ["Disabled", "Expired"]);
        s.expiration_date = None;
        s.deletion_date = iso(T0 + DAY);
        assert_eq!(status_chips(&s, T0 + 2 * DAY)[1], "Deleting soon");
    }

    #[test]
    fn rows_are_sorted_across_accounts() {
        let first = vec![send("beta"), send("Alpha")];
        let second = vec![send("alpine")];
        let rows = build_rows(&[(0, &first), (1, &second)], T0);
        let names: Vec<&str> = rows.iter().map(|r| r.name.as_str()).collect();
        assert_eq!(names, ["Alpha", "alpine", "beta"]);
        assert_eq!(rows[1].account, 1);
        assert_eq!(rows[0].chips, ["Deletes in 7 days"]);
        assert!(build_rows(&[], T0).is_empty());
    }

    #[test]
    fn views_must_be_a_positive_number() {
        assert_eq!(parse_max_views(""), Ok(None));
        assert_eq!(parse_max_views(" 5 "), Ok(Some(5)));
        assert!(parse_max_views("0").is_err());
        assert!(parse_max_views("-1").is_err());
        assert!(parse_max_views("many").is_err());
        assert!(parse_max_views("99999999999").is_err());
    }

    #[test]
    fn form_fills_a_new_send() {
        let mut s = SendEntry::new(SendKind::Text);
        let mut f = form();
        f.max_views = "3".into();
        f.hide_email = true;
        f.expiry_index = 2;
        apply_form(&mut s, &f).unwrap();
        assert_eq!(s.name, "Wifi");
        assert_eq!(s.text, "secret");
        assert!(s.hide_text && s.hide_email);
        assert_eq!(s.max_access_count, Some(3));
        assert!(s.expiration_date.is_some());
        let deletes = parse_iso(&s.deletion_date).unwrap();
        assert!((deletes - now() - 7 * DAY).abs() < 5);
    }

    #[test]
    fn form_keeps_dates_of_a_saved_send() {
        let mut s = send("old");
        s.expiration_date = Some(iso(T0 + DAY));
        let (deletion, expiry) = (s.deletion_date.clone(), s.expiration_date.clone());
        let mut f = form();
        f.deletion_index = 0;
        f.expiry_index = 0;
        apply_form(&mut s, &f).unwrap();
        assert_eq!(
            (s.deletion_date.clone(), s.expiration_date.clone()),
            (deletion, expiry)
        );
        f.expiry_index = 1;
        apply_form(&mut s, &f).unwrap();
        assert_eq!(s.expiration_date, None);
    }

    #[test]
    fn form_rejects_missing_values() {
        let mut s = SendEntry::new(SendKind::Text);
        let mut f = form();
        f.name = "  ".into();
        assert!(apply_form(&mut s, &f).is_err());
        let mut f = form();
        f.text.clear();
        assert!(apply_form(&mut s, &f).is_err());
        // A file Send needs no text.
        let mut file = SendEntry::new(SendKind::File);
        let mut f = form();
        f.text.clear();
        assert!(apply_form(&mut file, &f).is_ok());
    }

    #[test]
    fn sizes_in_words() {
        assert_eq!(size_text(10), "10 bytes");
        assert_eq!(size_text(2048), "2.0 KB");
        assert_eq!(size_text(5 << 20), "5.0 MB");
    }
}

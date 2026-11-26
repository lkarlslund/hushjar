//! The import and export pane.
//!
//! Exporting asks for the master password first (the worker checks it), then
//! for a place to save the file; the worker writes it. Importing reads the
//! chosen file here, and the worker parses it, then uploads it. File
//! contents are kept in `Zeroizing` buffers and dropped when the pane is
//! left or an account locks.

use std::path::PathBuf;

use hushjar_core::exchange::import::ParsedImport;

use super::*;
use crate::TransferData;
use crate::exchange::{self, ExportFormat, ExportScope, Target};

/// A file the user picked: its name and its contents or why they could not be read.
type LoadedFile = (String, Result<Zeroizing<Vec<u8>>, String>);

/// The largest import file read into memory.
const MAX_FILE_BYTES: u64 = 64 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum ExportStage {
    #[default]
    Idle,
    /// Waiting for the worker to check the master password.
    Verifying,
    /// The save dialog is open.
    Choosing,
    /// The worker is writing the file.
    Writing,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum ImportStage {
    #[default]
    Idle,
    Reading,
    Parsing,
    Importing,
}

/// An export waiting for its password check and file name.
struct ExportJob {
    account: String,
    scope: ExportScope,
    format: ExportFormat,
    password: Option<Zeroizing<String>>,
}

#[derive(Default)]
pub(super) struct Transfer {
    /// Local IDs of the chosen accounts; `None` means the first unlocked.
    export_account: Option<String>,
    import_account: Option<String>,
    export_what: usize,
    export_format: usize,
    import_folder: usize,
    import_format: usize,
    export_stage: ExportStage,
    import_stage: ImportStage,
    job: Option<ExportJob>,
    bytes: Option<Zeroizing<Vec<u8>>>,
    file_name: String,
    parsed: Option<ParsedImport>,
    needs_password: bool,
    /// Set while the pane may hold secrets, so leaving it clears them.
    active: bool,
}

/// Whether an organisation policy forbids exporting this account's personal
/// vault ("disable personal vault export"). Another job wires the real
/// policy in here; until then nothing is forbidden. The pane disables the
/// personal-vault export and explains why when this returns true.
fn personal_export_disabled(_state: &State, _account: usize) -> bool {
    false
}

/// Indices into `State::accounts` of the unlocked accounts.
fn unlocked(state: &State) -> Vec<usize> {
    (0..state.accounts.len())
        .filter(|&i| state.accounts[i].vault.is_some())
        .collect()
}

/// The account for a stored choice, falling back to the first unlocked one.
fn resolve(state: &State, choice: &Option<String>) -> Option<usize> {
    let list = unlocked(state);
    choice
        .as_ref()
        .and_then(|id| {
            list.iter()
                .copied()
                .find(|&i| state.accounts[i].profile.id == *id)
        })
        .or_else(|| list.first().copied())
}

impl State {
    fn export_account(&self) -> Option<usize> {
        resolve(self, &self.transfer.export_account)
    }

    fn import_account(&self) -> Option<usize> {
        resolve(self, &self.transfer.import_account)
    }

    /// "My vault", then one entry per organisation of the account.
    fn export_choices(&self, account: usize) -> Vec<(ExportScope, String)> {
        let mut list = vec![(ExportScope::Personal, "My vault".to_string())];
        if let Some(vault) = &self.accounts[account].vault {
            list.extend(
                vault
                    .organizations
                    .iter()
                    .map(|o| (ExportScope::Organization(o.id.clone()), o.name.clone())),
            );
        }
        list
    }

    fn import_folders(&self, account: usize) -> Vec<String> {
        let mut names: Vec<String> = self.accounts[account]
            .view
            .folders
            .iter()
            .map(|f| f.name.clone())
            .collect();
        names.sort_by_key(|n| n.to_lowercase());
        names
    }
}

pub(super) fn show_transfer(win: &AppWindow, st: &Shared) {
    if !leave_to(win, st, Pending::Transfer) {
        return;
    }
    forget_transfer(win, st);
    {
        let mut state = st.borrow_mut();
        state.shown = Shown::Transfer;
        state.selected = None;
        state.transfer.active = true;
    }
    win.set_selected_key(SharedString::new());
    win.set_selected_index(-1);
    render(win, st);
}

/// Drops file contents and passwords, in memory and in the pane.
pub(super) fn forget_transfer(win: &AppWindow, st: &Shared) {
    st.borrow_mut().transfer = Transfer::default();
    let data = win.global::<TransferData>();
    for clear in [
        TransferData::set_master_password,
        TransferData::set_export_file_password,
        TransferData::set_export_file_confirm,
        TransferData::set_import_file_password,
    ] {
        clear(&data, SharedString::new());
    }
    for clear in [
        TransferData::set_export_error,
        TransferData::set_export_result,
        TransferData::set_import_file_name,
        TransferData::set_import_preview,
        TransferData::set_import_error,
        TransferData::set_import_result,
    ] {
        clear(&data, SharedString::new());
    }
    data.set_import_needs_password(false);
    data.set_import_ready(false);
    data.set_export_busy(false);
    data.set_import_busy(false);
    data.set_export_what(0);
    data.set_export_format(0);
    data.set_import_folder(0);
    data.set_import_format(0);
}

fn strings<T: AsRef<str>>(list: impl IntoIterator<Item = T>) -> ModelRc<SharedString> {
    ModelRc::new(VecModel::from(
        list.into_iter().map(|t| s(t.as_ref())).collect::<Vec<_>>(),
    ))
}

/// Fills the option lists and messages from the current state. What the user
/// typed is left alone.
pub(super) fn render_transfer(win: &AppWindow, st: &Shared) {
    let state = st.borrow();
    let data = win.global::<TransferData>();
    let list = unlocked(&state);
    data.set_any_account(!list.is_empty());
    data.set_accounts(strings(
        list.iter().map(|&i| &state.accounts[i].profile.email),
    ));
    let position = |account: Option<usize>| {
        account
            .and_then(|a| list.iter().position(|&i| i == a))
            .unwrap_or(0) as i32
    };
    data.set_export_account(position(state.export_account()));
    data.set_import_account(position(state.import_account()));

    let t = &state.transfer;
    if let Some(account) = state.export_account() {
        let choices = state.export_choices(account);
        let what = t.export_what.min(choices.len() - 1);
        data.set_export_what_options(strings(choices.iter().map(|(_, n)| n)));
        data.set_export_what(what as i32);
        let blocked = what == 0 && personal_export_disabled(&state, account);
        data.set_export_blocked(
            if blocked {
                "Your organisation does not allow you to export your personal vault."
            } else {
                ""
            }
            .into(),
        );
    }
    let format = ExportFormat::ALL[t.export_format.min(ExportFormat::ALL.len() - 1)];
    data.set_export_format_options(strings(ExportFormat::ALL.map(ExportFormat::label)));
    data.set_export_format(t.export_format as i32);
    data.set_export_plain(format.is_plain());
    data.set_export_needs_file_password(format.needs_file_password());
    data.set_export_busy(t.export_stage != ExportStage::Idle);

    if let Some(account) = state.import_account() {
        let mut folders = vec![
            "Keep the file's folders".to_string(),
            "No folder".to_string(),
        ];
        folders.extend(state.import_folders(account));
        data.set_import_folder_options(strings(&folders));
        data.set_import_folder(t.import_folder.min(folders.len() - 1) as i32);
    }
    data.set_import_format_options(strings(exchange::import_format_options()));
    data.set_import_format(t.import_format as i32);
    data.set_import_file_name(s(&t.file_name));
    data.set_import_needs_password(t.needs_password);
    data.set_import_busy(t.import_stage != ImportStage::Idle);
    data.set_import_ready(t.parsed.is_some());
}

pub(super) fn wire_transfer(w: &AppWindow, state: &Shared) {
    let data = w.global::<TransferData>();
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
    on!(on_export_account_picked, |win, st, index: i32| {
        let id = nth_unlocked_id(&st.borrow(), index);
        let mut state = st.borrow_mut();
        state.transfer.export_account = id;
        state.transfer.export_what = 0;
        drop(state);
        render_transfer(&win, st);
    });
    on!(on_export_what_picked, |win, st, index: i32| {
        st.borrow_mut().transfer.export_what = index.max(0) as usize;
        render_transfer(&win, st);
    });
    on!(on_export_format_picked, |win, st, index: i32| {
        st.borrow_mut().transfer.export_format = index.max(0) as usize;
        render_transfer(&win, st);
    });
    on!(on_export_clicked, |win, st| {
        start_export(&win, st);
    });
    on!(on_import_account_picked, |win, st, index: i32| {
        let id = nth_unlocked_id(&st.borrow(), index);
        {
            let mut state = st.borrow_mut();
            state.transfer.import_account = id;
            state.transfer.import_folder = 0;
        }
        discard_file(&win, st);
    });
    on!(on_import_folder_picked, |win, st, index: i32| {
        st.borrow_mut().transfer.import_folder = index.max(0) as usize;
        render_transfer(&win, st);
    });
    on!(on_import_format_picked, |win, st, index: i32| {
        st.borrow_mut().transfer.import_format = index.max(0) as usize;
        if st.borrow().transfer.bytes.is_some() {
            start_parse(&win, st);
        } else {
            render_transfer(&win, st);
        }
    });
    on!(on_pick_file, |win, st| {
        pick_import_file(&win, st);
    });
    on!(on_continue_with_password, |win, st| {
        start_parse(&win, st);
    });
    on!(on_import_clicked, |win, st| {
        start_import(&win, st);
    });
}

fn nth_unlocked_id(state: &State, index: i32) -> Option<String> {
    let list = unlocked(state);
    list.get(index.max(0) as usize)
        .map(|&i| state.accounts[i].profile.id.clone())
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

fn password(text: SharedString) -> Zeroizing<String> {
    Zeroizing::new(text.to_string())
}

// ---------------------------------------------------------------- export

fn export_problem(win: &AppWindow, st: &Shared) -> Result<ExportJob, String> {
    let state = st.borrow();
    let data = win.global::<TransferData>();
    let account = state.export_account().ok_or("Unlock an account first")?;
    let choices = state.export_choices(account);
    let what = state.transfer.export_what.min(choices.len() - 1);
    if what == 0 && personal_export_disabled(&state, account) {
        return Err("Your organisation does not allow you to export your personal vault.".into());
    }
    let format = ExportFormat::ALL[state
        .transfer
        .export_format
        .min(ExportFormat::ALL.len() - 1)];
    let file_password = format
        .needs_file_password()
        .then(|| password(data.get_export_file_password()));
    if let Some(p) = &file_password {
        if p.is_empty() {
            return Err("Choose a password for the file".into());
        }
        if **p != *data.get_export_file_confirm() {
            return Err("The two file passwords are different".into());
        }
    }
    if data.get_master_password().is_empty() {
        return Err("Enter your master password to export".into());
    }
    Ok(ExportJob {
        account: state.accounts[account].profile.id.clone(),
        scope: choices[what].0.clone(),
        format,
        password: file_password,
    })
}

fn start_export(win: &AppWindow, st: &Shared) {
    let data = win.global::<TransferData>();
    if st.borrow().transfer.export_stage != ExportStage::Idle {
        return;
    }
    data.set_export_result(SharedString::new());
    let job = match export_problem(win, st) {
        Ok(job) => job,
        Err(message) => {
            data.set_export_error(s(&message));
            return;
        }
    };
    data.set_export_error(SharedString::new());
    let master = password(data.get_master_password());
    let mut state = st.borrow_mut();
    let Some(index) = state.account_index(&job.account) else {
        return;
    };
    let _ = state.accounts[index]
        .worker
        .tx
        .send(Command::VerifyPassword { password: master });
    state.transfer.job = Some(job);
    state.transfer.export_stage = ExportStage::Verifying;
    drop(state);
    data.set_export_busy(true);
}

/// The master password was right: ask where to save the file.
fn choose_export_path(st: &Shared) {
    let name = {
        let mut state = st.borrow_mut();
        let Some(job) = &state.transfer.job else {
            return;
        };
        let name = job.format.file_name(unix_now());
        state.transfer.export_stage = ExportStage::Choosing;
        name
    };
    let extension = st
        .borrow()
        .transfer
        .job
        .as_ref()
        .map_or("json", |j| j.format.extension());
    std::thread::spawn(move || {
        let path = rfd::FileDialog::new()
            .set_title("Save export")
            .set_file_name(name)
            .add_filter(extension.to_uppercase(), &[extension])
            .save_file();
        on_ui(move |win, st| export_path_chosen(win, st, path));
    });
}

fn export_path_chosen(win: &AppWindow, st: &Shared, path: Option<PathBuf>) {
    let mut state = st.borrow_mut();
    let (Some(path), Some(job)) = (path, state.transfer.job.take()) else {
        state.transfer.job = None;
        state.transfer.export_stage = ExportStage::Idle;
        drop(state);
        win.global::<TransferData>().set_export_busy(false);
        return;
    };
    let Some(index) = state.account_index(&job.account) else {
        state.transfer.export_stage = ExportStage::Idle;
        return;
    };
    let _ = state.accounts[index].worker.tx.send(Command::Export {
        scope: job.scope,
        format: job.format,
        password: job.password,
        path,
    });
    state.transfer.export_stage = ExportStage::Writing;
}

// ---------------------------------------------------------------- import

/// Forgets the loaded file and what was parsed from it.
fn discard_file(win: &AppWindow, st: &Shared) {
    {
        let mut state = st.borrow_mut();
        let t = &mut state.transfer;
        t.bytes = None;
        t.parsed = None;
        t.file_name.clear();
        t.needs_password = false;
        t.import_stage = ImportStage::Idle;
    }
    let data = win.global::<TransferData>();
    data.set_import_file_password(SharedString::new());
    data.set_import_preview(SharedString::new());
    data.set_import_error(SharedString::new());
    data.set_import_result(SharedString::new());
    render_transfer(win, st);
}

fn pick_import_file(win: &AppWindow, st: &Shared) {
    if st.borrow().transfer.import_stage != ImportStage::Idle {
        return;
    }
    st.borrow_mut().transfer.import_stage = ImportStage::Reading;
    render_transfer(win, st);
    std::thread::spawn(move || {
        let picked = rfd::FileDialog::new()
            .set_title("Choose a file to import")
            .add_filter("Exports", &["json", "csv"])
            .add_filter("All files", &["*"])
            .pick_file();
        let loaded = picked.map(|path| {
            let name = path
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default();
            (name, read_limited(&path))
        });
        on_ui(move |win, st| file_chosen(win, st, loaded));
    });
}

fn read_limited(path: &std::path::Path) -> Result<Zeroizing<Vec<u8>>, String> {
    use std::io::Read;
    let file = std::fs::File::open(path).map_err(|e| format!("Could not open the file: {e}"))?;
    let mut bytes = Zeroizing::new(Vec::new());
    file.take(MAX_FILE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| format!("Could not read the file: {e}"))?;
    if bytes.len() as u64 > MAX_FILE_BYTES {
        return Err("This file is too large to import".into());
    }
    Ok(bytes)
}

fn file_chosen(win: &AppWindow, st: &Shared, loaded: Option<LoadedFile>) {
    st.borrow_mut().transfer.import_stage = ImportStage::Idle;
    let Some((name, result)) = loaded else {
        render_transfer(win, st);
        return;
    };
    discard_file(win, st);
    match result {
        Ok(bytes) => {
            {
                let mut state = st.borrow_mut();
                state.transfer.bytes = Some(bytes);
                state.transfer.file_name = name;
            }
            start_parse(win, st);
        }
        Err(message) => win.global::<TransferData>().set_import_error(s(&message)),
    }
}

fn start_parse(win: &AppWindow, st: &Shared) {
    let data = win.global::<TransferData>();
    let file_password = {
        let p = data.get_import_file_password();
        (st.borrow().transfer.needs_password && !p.is_empty()).then(|| password(p))
    };
    let mut state = st.borrow_mut();
    let (Some(account), Some(bytes)) = (state.import_account(), state.transfer.bytes.clone())
    else {
        return;
    };
    let format = exchange::import_format_at(state.transfer.import_format);
    let sent = state.accounts[account]
        .worker
        .tx
        .send(Command::ParseImport {
            bytes,
            format,
            password: file_password,
        });
    if sent.is_ok() {
        state.transfer.import_stage = ImportStage::Parsing;
        state.transfer.parsed = None;
    }
    drop(state);
    data.set_import_error(SharedString::new());
    data.set_import_preview(SharedString::new());
    data.set_import_result(SharedString::new());
    render_transfer(win, st);
}

fn start_import(win: &AppWindow, st: &Shared) {
    let mut state = st.borrow_mut();
    let Some(account) = state.import_account() else {
        return;
    };
    let Some(mut parsed) = state.transfer.parsed.clone() else {
        return;
    };
    let target = match state.transfer.import_folder {
        0 => Target::FileFolders,
        1 => Target::Nowhere,
        n => match state.import_folders(account).get(n - 2) {
            Some(name) => Target::Folder(name.clone()),
            None => Target::FileFolders,
        },
    };
    exchange::apply_target(&mut parsed, &target);
    let sent = state.accounts[account].worker.tx.send(Command::Import {
        parsed: Box::new(parsed),
    });
    if sent.is_ok() {
        state.transfer.import_stage = ImportStage::Importing;
    }
    drop(state);
    let data = win.global::<TransferData>();
    data.set_import_error(SharedString::new());
    render_transfer(win, st);
}

// ---------------------------------------------------------------- events

/// Handles the worker's answers to export and import commands.
pub(super) fn handle_transfer_event(win: &AppWindow, st: &Shared, index: usize, event: Event) {
    let data = win.global::<TransferData>();
    match event {
        Event::PasswordVerified => {
            let waiting = st.borrow().transfer.export_stage == ExportStage::Verifying;
            if waiting {
                choose_export_path(st);
            }
        }
        Event::PasswordRejected => {
            finish_export(st);
            data.set_export_error("That is not your master password".into());
        }
        Event::Exported { path } => {
            finish_export(st);
            data.set_master_password(SharedString::new());
            data.set_export_file_password(SharedString::new());
            data.set_export_file_confirm(SharedString::new());
            data.set_export_result(s(&format!("Saved to {}", path.display())));
        }
        Event::ImportParsed { parsed } => {
            let text = exchange::preview_text(&parsed);
            let mut state = st.borrow_mut();
            state.transfer.import_stage = ImportStage::Idle;
            state.transfer.needs_password = false;
            state.transfer.parsed = Some(*parsed);
            drop(state);
            data.set_import_file_password(SharedString::new());
            data.set_import_preview(s(&text));
        }
        Event::ImportPasswordNeeded { wrong } => {
            let mut state = st.borrow_mut();
            state.transfer.import_stage = ImportStage::Idle;
            state.transfer.needs_password = true;
            drop(state);
            data.set_import_error(
                if wrong {
                    "That password does not open the file"
                } else {
                    ""
                }
                .into(),
            );
            data.set_import_preview("This file is protected with a password.".into());
        }
        Event::Imported { summary, vault } => {
            {
                let mut state = st.borrow_mut();
                let a = &mut state.accounts[index];
                a.view = Account::from_vault(&a.profile, &vault);
                a.vault = Some(vault);
                state.transfer.import_stage = ImportStage::Idle;
                state.transfer.parsed = None;
                state.transfer.bytes = None;
                state.transfer.file_name.clear();
            }
            refresh_tree(win, st);
            data.set_import_preview(SharedString::new());
            data.set_import_result(s(&exchange::summary_text(&summary)));
        }
        Event::TransferFailed { message } => {
            let importing = st.borrow().transfer.import_stage != ImportStage::Idle;
            if importing {
                st.borrow_mut().transfer.import_stage = ImportStage::Idle;
                data.set_import_error(s(&message));
            } else {
                finish_export(st);
                data.set_export_error(s(&message));
            }
        }
        _ => {}
    }
    render_transfer(win, st);
}

fn finish_export(st: &Shared) {
    let mut state = st.borrow_mut();
    state.transfer.export_stage = ExportStage::Idle;
    state.transfer.job = None;
}

impl Transfer {
    pub(super) fn is_active(&self) -> bool {
        self.active
    }
}

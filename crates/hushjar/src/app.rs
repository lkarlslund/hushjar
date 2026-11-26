//! App state and the glue between the Slint window, the account workers and
//! the clipboard.

use std::cell::RefCell;
use std::collections::{HashMap, HashSet, VecDeque};
use std::rc::Rc;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use hushjar_core::api::{Server, TwoFactorProvider};
use hushjar_core::store::{Profile, Store};
use hushjar_core::vault::{self as core, Vault};
use slint::{
    Color, ComponentHandle, Model, ModelRc, SharedString, Timer, TimerMode, VecModel, Weak,
};
use zeroize::Zeroizing;

use crate::clipboard::Clipboard;
use crate::model::{self, Account, Field, FieldPath, Item, ItemType};
use crate::sshagent::{AskMode, Bridge, Prompt};
use crate::tree::{self, GroupBy, Row};
use crate::worker::{Command, Event, Worker};
use crate::{
    AccountBadge, AccountSummary, AppWindow, DetailField, DetailSection, FieldKind, GroupSummary,
    ItemHeader, PaneMode, RowKind, SignInForm, TreeRow,
};

/// Lock every account after this long without a key press or click.
const IDLE_LOCK: Duration = Duration::from_secs(15 * 60);

#[derive(Clone, Debug, PartialEq)]
enum Shown {
    Nothing,
    Item { account: usize, id: String },
    Group(String),
    Locked(usize),
    Account(usize),
    SignIn,
}

struct Draft {
    account: usize,
    item: Item,
    original: Item,
    core: core::Item,
    is_new: bool,
    saving: bool,
}

impl Draft {
    fn dirty(&self) -> bool {
        self.is_new || self.item != self.original
    }
}

#[derive(Clone, Debug)]
enum Pending {
    Select(String),
    LockAll,
    NewItem,
}

struct AccountState {
    profile: Profile,
    view: Account,
    vault: Option<Vault>,
    worker: Worker,
    busy: bool,
    needs_sign_in: bool,
    two_factor: Vec<TwoFactorProvider>,
    synced_at: Option<u64>,
    note: String,
}

#[derive(Default)]
struct SignIn {
    stage: i32,
    server_choice: i32,
    url: String,
    email: String,
    error: String,
    busy: bool,
    providers: Vec<TwoFactorProvider>,
    password: Zeroizing<String>,
    server: Option<Server>,
    worker: Option<Worker>,
}

pub struct State {
    store: Arc<Store>,
    accounts: Vec<AccountState>,
    sign_in: SignIn,
    group_by: GroupBy,
    expanded: HashSet<String>,
    filter: String,
    rows: Vec<Row>,
    selected: Option<String>,
    shown: Shown,
    draft: Option<Draft>,
    pending: Option<Pending>,
    /// One model per visible section, so single fields can be updated in place.
    section_models: Vec<Rc<VecModel<DetailField>>>,
    /// The sections behind `section_models`, as shown.
    shown_sections: Vec<model::Section>,
    rows_model: Rc<VecModel<TreeRow>>,
    toast_timer: Rc<Timer>,
    clipboard: Rc<RefCell<Clipboard>>,
    last_activity: Instant,
    next_id: usize,
    bridge: Arc<Bridge>,
    agent: Result<hushjar_agent::Agent, String>,
    prompts: VecDeque<Prompt>,
    /// Per SSH key ("account/item"): offered to the agent, and when to ask.
    ssh_settings: HashMap<String, (bool, AskMode)>,
}

type Shared = Rc<RefCell<State>>;

thread_local! {
    static CONTEXT: RefCell<Option<(Weak<AppWindow>, Shared)>> = const { RefCell::new(None) };
}

pub struct App {
    pub window: AppWindow,
    _timers: Vec<Timer>,
}

fn color((r, g, b): (u8, u8, u8)) -> Color {
    Color::from_rgb_u8(r, g, b)
}

fn s(value: &str) -> SharedString {
    value.into()
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn relative(synced: Option<u64>) -> String {
    let Some(t) = synced else {
        return "Not synced yet".into();
    };
    let ago = unix_now().saturating_sub(t);
    match ago {
        0..=59 => "Synced just now".into(),
        60..=3599 => format!("Synced {} min ago", ago / 60),
        3600..=86_399 => format!("Synced {} h ago", ago / 3600),
        _ => format!("Synced {} days ago", ago / 86_400),
    }
}

/// The current code for a verification code secret, grouped for reading.
fn totp_display(secret: &str) -> (String, u64) {
    match hushjar_core::totp::generate(secret, unix_now()) {
        Ok(code) => {
            let v = &code.value;
            let shown = if v.len() >= 6 && v.chars().all(|c| c.is_ascii_digit()) {
                let (a, b) = v.split_at(v.len() / 2);
                format!("{a} {b}")
            } else {
                v.clone()
            };
            (shown, code.period)
        }
        Err(_) => ("Invalid verification code setup".into(), 30),
    }
}

fn to_detail(field: &Field, view: bool) -> DetailField {
    let mut kind = field.kind;
    let value = if view && field.kind == FieldKind::Totp {
        totp_display(&field.value).0
    } else {
        field.value.clone()
    };
    if !view && field.path == FieldPath::SshPrivate {
        kind = FieldKind::Multiline;
    }
    DetailField {
        label: s(&field.label),
        value: value.into(),
        kind,
        copyable: field.copyable,
        removable: field.removable,
        label_editable: field.label_editable,
    }
}

fn emitter() -> impl Fn(String, Event) + Send + 'static {
    move |id, event| {
        let _ = slint::invoke_from_event_loop(move || {
            CONTEXT.with(|c| {
                if let Some((weak, st)) = &*c.borrow()
                    && let Some(win) = weak.upgrade()
                {
                    handle_event(&win, st, &id, event);
                }
            });
        });
    }
}

impl State {
    fn filtering(&self) -> bool {
        !self.filter.trim().is_empty()
    }

    fn row(&self, key: &str) -> Option<&Row> {
        self.rows.iter().find(|r| r.key == key)
    }

    fn selected_index(&self) -> Option<usize> {
        let key = self.selected.as_deref()?;
        self.rows.iter().position(|r| r.key == key)
    }

    fn views(&self) -> Vec<Account> {
        self.accounts.iter().map(|a| a.view.clone()).collect()
    }

    fn item(&self, account: usize, id: &str) -> Option<&Item> {
        if let Some(d) = &self.draft
            && d.account == account
            && d.item.id == id
        {
            return Some(&d.item);
        }
        self.accounts
            .get(account)?
            .view
            .items
            .iter()
            .find(|i| i.id == id)
    }

    fn core_item(&self, account: usize, id: &str) -> Option<&core::Item> {
        self.accounts.get(account)?.vault.as_ref()?.item(id)
    }

    fn editing_shown(&self) -> bool {
        matches!((&self.shown, &self.draft), (Shown::Item { account, id }, Some(d)) if d.account == *account && d.item.id == *id)
    }

    fn folder_options(&self, account: usize) -> Vec<(Option<String>, String)> {
        let mut options = vec![(None, "No folder".to_string())];
        let mut folders = self.accounts[account].view.folders.clone();
        folders.sort_by_key(|f| f.name.to_lowercase());
        options.extend(folders.into_iter().map(|f| (Some(f.id), f.name)));
        options
    }

    fn item_path(&self, account: usize, item: &Item) -> String {
        let a = &self.accounts[account].view;
        let mut path = a.email.clone();
        if let Some(name) = item.folder.as_deref().and_then(|id| a.folder_name(id)) {
            path.push_str(" › ");
            path.push_str(&name.replace('/', " › "));
        }
        if !item.collections.is_empty() {
            let names: Vec<&str> = a
                .collections
                .iter()
                .filter(|c| item.collections.contains(&c.id))
                .map(|c| c.name.as_str())
                .collect();
            path.push_str(&format!("  ·  {}", names.join(", ")));
        }
        path
    }

    fn account_index(&self, id: &str) -> Option<usize> {
        self.accounts.iter().position(|a| a.profile.id == id)
    }

    fn any_unlocked(&self) -> bool {
        self.accounts.iter().any(|a| a.vault.is_some())
    }
}

impl App {
    pub fn new(store: Store) -> Result<Self, slint::PlatformError> {
        let window = AppWindow::new()?;
        let store = Arc::new(store);
        let profiles = store.profiles();
        let mut accounts = Vec::new();
        for profile in profiles {
            let worker = Worker::spawn(store.clone(), Some(profile.clone()), emitter());
            accounts.push(AccountState {
                view: Account::locked(&profile),
                profile,
                vault: None,
                worker,
                busy: false,
                needs_sign_in: false,
                two_factor: vec![],
                synced_at: None,
                note: String::new(),
            });
        }
        let bridge = Arc::new(Bridge::new(|prompt| {
            let _ = slint::invoke_from_event_loop(move || {
                CONTEXT.with(|c| {
                    if let Some((weak, st)) = &*c.borrow()
                        && let Some(win) = weak.upgrade()
                    {
                        show_prompt(&win, st, prompt);
                    }
                });
            });
        }));
        let agent = match hushjar_agent::default_socket_path() {
            Some(path) => hushjar_agent::Agent::start(&path, bridge.clone(), bridge.clone())
                .map_err(|e| e.to_string()),
            None => Err("the SSH agent is not available on this system yet".into()),
        };
        let ssh_settings = load_ssh_settings(&store);
        let state: Shared = Rc::new(RefCell::new(State {
            store,
            accounts,
            sign_in: SignIn::default(),
            group_by: GroupBy::Folders,
            expanded: HashSet::new(),
            filter: String::new(),
            rows: vec![],
            selected: None,
            shown: Shown::Nothing,
            draft: None,
            pending: None,
            section_models: vec![],
            shown_sections: vec![],
            rows_model: Rc::new(VecModel::default()),
            toast_timer: Rc::new(Timer::default()),
            clipboard: Rc::new(RefCell::new(Clipboard::new())),
            last_activity: Instant::now(),
            next_id: 1,
            bridge,
            agent,
            prompts: VecDeque::new(),
            ssh_settings,
        }));
        CONTEXT.with(|c| *c.borrow_mut() = Some((window.as_weak(), state.clone())));
        window.set_rows(ModelRc::from(state.borrow().rows_model.clone()));
        let types: Vec<SharedString> = ItemType::CREATABLE.iter().map(|t| s(t.label())).collect();
        window.set_item_types(ModelRc::new(VecModel::from(types)));

        let app = Self {
            window,
            _timers: vec![],
        };
        wire(&app.window, &state);
        refresh_tree(&app.window, &state);
        let first = state
            .borrow()
            .accounts
            .first()
            .map(|a| a.profile.id.clone());
        match first {
            Some(key) => {
                select(&app.window, &state, &key);
                app.window.set_unlock_focus_request(1);
            }
            None => show_sign_in(&app.window, &state),
        }
        update_sync_text(&app.window, &state);
        app.window.set_agent_running(state.borrow().agent.is_ok());
        update_agent_keys(&app.window, &state);

        // Once a second: verification codes, the sync label and the idle lock.
        let ticker = Timer::default();
        let weak = app.window.as_weak();
        let st = state.clone();
        ticker.start(TimerMode::Repeated, Duration::from_secs(1), move || {
            let Some(w) = weak.upgrade() else { return };
            let period = st.borrow().current_totp_period();
            let now = unix_now();
            let remaining = (period - now % period) as i32;
            w.set_totp_remaining(remaining);
            if remaining as u64 == period {
                refresh_codes(&st);
            }
            if now.is_multiple_of(15) {
                update_sync_text(&w, &st);
            }
            let expired = {
                let mut state = st.borrow_mut();
                let before = state.prompts.len();
                state.prompts.retain(|p| p.deadline > Instant::now());
                before != state.prompts.len()
            };
            if expired {
                render_prompt(&w, &st);
            }
            let idle =
                st.borrow().last_activity.elapsed() > IDLE_LOCK && st.borrow().any_unlocked();
            if idle {
                st.borrow_mut().draft = None;
                lock_all(&w, &st);
                toast(&w, &st, "Locked after 15 minutes without activity");
            }
        });
        Ok(Self {
            _timers: vec![ticker],
            ..app
        })
    }
}

impl State {
    fn current_totp_period(&self) -> u64 {
        if let Shown::Item { account, id } = &self.shown
            && let Some(item) = self.item(*account, id)
            && let Some(f) = item.field_at(FieldPath::Totp)
            && !f.value.is_empty()
        {
            return totp_display(&f.value).1;
        }
        30
    }
}

fn wire(w: &AppWindow, state: &Shared) {
    let weak = w.as_weak();

    // Every callback gets a weak window handle and the shared state, and
    // counts as activity for the idle lock.
    macro_rules! on {
        ($setter:ident, |$win:ident, $st:ident $(, $arg:ident : $ty:ty)*| $body:block) => {{
            let weak = weak.clone();
            let state = state.clone();
            w.$setter(move |$($arg: $ty),*| {
                let Some($win) = weak.upgrade() else { return };
                let _ = &$win;
                let $st = &state;
                $st.borrow_mut().last_activity = Instant::now();
                $body
            });
        }};
    }

    on!(on_activity, |win, st| {});
    on!(on_filter_edited, |win, st, text: SharedString| {
        st.borrow_mut().filter = text.to_string();
        refresh_tree(&win, st);
    });
    on!(on_filter_accepted, |win, st| {
        let first = st
            .borrow()
            .rows
            .iter()
            .find(|r| r.kind == RowKind::Item)
            .map(|r| r.key.clone());
        if let Some(key) = first {
            select(&win, st, &key);
            win.invoke_focus_tree();
        }
    });
    on!(on_group_by_picked, |win, st, index: i32| {
        st.borrow_mut().group_by = GroupBy::from_index(index);
        refresh_tree(&win, st);
    });
    on!(on_row_clicked, |win, st, key: SharedString| {
        select(&win, st, &key);
    });
    on!(on_row_toggled, |win, st, key: SharedString| {
        toggle(&win, st, &key);
    });
    on!(on_row_activated, |win, st, key: SharedString| {
        activate(&win, st, &key);
    });
    on!(on_move_selection, |win, st, delta: i32| {
        let target = {
            let st = st.borrow();
            if st.rows.is_empty() {
                return;
            }
            let last = st.rows.len() as i64 - 1;
            let current = st
                .selected_index()
                .map(|i| i as i64)
                .unwrap_or(if delta > 0 { -1 } else { last + 1 });
            let next = (current + delta as i64).clamp(0, last) as usize;
            st.rows[next].key.clone()
        };
        select(&win, st, &target);
    });
    on!(on_expand_selection, |win, st| {
        let action = {
            let st = st.borrow();
            st.selected_index().map(|i| {
                (
                    st.rows[i].clone(),
                    st.rows.get(i + 1).map(|r| r.key.clone()),
                )
            })
        };
        if let Some((row, next)) = action {
            if row.expandable && !row.expanded {
                toggle(&win, st, &row.key);
            } else if let (true, Some(next)) = (row.expanded, next) {
                select(&win, st, &next);
            }
        }
    });
    on!(on_collapse_selection, |win, st| {
        let action = {
            let st = st.borrow();
            st.selected_index().map(|i| {
                let row = st.rows[i].clone();
                let parent = st.rows[..i]
                    .iter()
                    .rev()
                    .find(|r| r.depth < row.depth)
                    .map(|r| r.key.clone());
                (row, parent)
            })
        };
        if let Some((row, parent)) = action {
            if row.expanded && !st.borrow().filtering() {
                toggle(&win, st, &row.key);
            } else if let Some(parent) = parent {
                select(&win, st, &parent);
            }
        }
    });
    on!(on_activate_selection, |win, st| {
        let key = st.borrow().selected.clone();
        if let Some(key) = key {
            activate(&win, st, &key);
        }
    });
    on!(on_add_account, |win, st| {
        show_sign_in(&win, st);
    });

    on!(on_copy_field, |win, st, section: i32, field: i32| {
        let value = st
            .borrow()
            .section_models
            .get(section as usize)
            .and_then(|m| m.row_data(field as usize));
        if let Some(f) = value {
            let text = if f.kind == FieldKind::Totp {
                f.value.replace(' ', "")
            } else {
                f.value.to_string()
            };
            copy(&win, st, &text, &f.label.to_lowercase());
        }
    });
    on!(on_copy_shortcut, |win, st, which: SharedString| {
        let (path, label) = match which.as_str() {
            "username" => (FieldPath::Username, "username"),
            "password" => (FieldPath::Password, "password"),
            _ => (FieldPath::Totp, "verification code"),
        };
        let found = {
            let st = st.borrow();
            match &st.shown {
                Shown::Item { account, id } => st
                    .item(*account, id)
                    .and_then(|i| i.field_at(path))
                    .filter(|f| !f.value.is_empty() && f.kind != FieldKind::Info)
                    .map(|f| {
                        if path == FieldPath::Totp {
                            totp_display(&f.value).0.replace(' ', "")
                        } else {
                            f.value.clone()
                        }
                    }),
                _ => None,
            }
        };
        match found {
            Some(value) => copy(&win, st, &value, label),
            None => toast(&win, st, &format!("This item has no {label}")),
        }
    });
    on!(on_open_url, |win, st, url: SharedString| {
        open_url(&win, st, &url);
    });

    on!(on_begin_edit, |win, st| {
        begin_edit(&win, st);
    });
    on!(on_save, |win, st| {
        save(&win, st);
    });
    on!(on_cancel, |win, st| {
        st.borrow_mut().pending = None;
        cancel(&win, st);
    });
    on!(on_keep_editing, |win, st| {
        st.borrow_mut().pending = None;
        win.set_leave_pending(false);
    });
    on!(on_discard_and_leave, |win, st| {
        cancel(&win, st);
        run_pending(&win, st);
    });
    on!(on_save_and_leave, |win, st| {
        win.set_leave_pending(false);
        save(&win, st);
    });
    on!(on_edit_field, |win,
                        st,
                        section: i32,
                        field: i32,
                        text: SharedString| {
        edit_shown_field(&win, st, section as usize, field as usize, |f| {
            f.value = text.to_string()
        });
    });
    on!(on_edit_label, |win,
                        st,
                        section: i32,
                        field: i32,
                        text: SharedString| {
        edit_shown_field(&win, st, section as usize, field as usize, |f| {
            f.label = text.to_string()
        });
    });
    on!(on_edit_name, |win, st, text: SharedString| {
        edit_draft(&win, st, |item| item.name = text.to_string());
    });
    on!(on_toggle_favorite, |win, st| {
        if st.borrow().editing_shown() {
            edit_draft(&win, st, |item| item.favorite = !item.favorite);
            render_header(&win, st);
            return;
        }
        quick_save(&win, st, |item| item.favorite = !item.favorite);
    });
    on!(on_pick_folder, |win, st, index: i32| {
        let folder = {
            let st = st.borrow();
            let Some(d) = &st.draft else { return };
            st.folder_options(d.account)
                .get(index as usize)
                .map(|(id, _)| id.clone())
        };
        if let Some(folder) = folder {
            edit_draft(&win, st, |item| item.folder = folder);
            win.set_folder_index(index);
            render_header(&win, st);
        }
    });
    on!(on_pick_type, |win, st, index: i32| {
        let Some(kind) = ItemType::CREATABLE.get(index as usize).copied() else {
            return;
        };
        {
            let mut st = st.borrow_mut();
            let Some(d) = st.draft.as_mut().filter(|d| d.is_new) else {
                return;
            };
            let mut fresh = core::Item::new(
                kind.to_kind(),
                d.core.organization_id.clone(),
                d.item.folder.clone(),
            );
            fresh.collection_ids = d.core.collection_ids.clone();
            let mut item = model::from_core(&fresh);
            item.id = d.item.id.clone();
            item.name = d.item.name.clone();
            add_blank_website(&mut item);
            d.core = fresh;
            d.item = item;
        }
        win.set_type_index(index);
        render(&win, st);
    });
    on!(on_create_folder, |win, st, name: SharedString| {
        let account = st.borrow().draft.as_ref().map(|d| d.account);
        if let Some(account) = account {
            let _ = st.borrow().accounts[account]
                .worker
                .tx
                .send(Command::CreateFolder(name.trim().to_string()));
            toast(&win, st, "Creating folder…");
        }
    });
    on!(on_generate, |win, st, section: i32, field: i32| {
        let password = generate_password();
        let (s_idx, f_idx) = (section as usize, field as usize);
        edit_shown_field(&win, st, s_idx, f_idx, |f| f.value = password.to_string());
        // Re-insert the row so its editor picks up the new value.
        {
            let state = st.borrow();
            if let (Some(model), Some(f)) = (
                state.section_models.get(s_idx),
                state
                    .shown_sections
                    .get(s_idx)
                    .and_then(|s| s.fields.get(f_idx)),
            ) && f_idx < model.row_count()
            {
                model.remove(f_idx);
                model.insert(f_idx, to_detail(f, false));
            }
        }
        toast(&win, st, "Generated a new password");
    });
    on!(on_add_field, |win, st, section: i32| {
        let s_idx = section as usize;
        let new = {
            let mut state = st.borrow_mut();
            let Some(sec) = state.shown_sections.get_mut(s_idx) else {
                return;
            };
            let Some(kind) = sec.add else { return };
            let field = kind.new_field();
            sec.fields.push(field.clone());
            field
        };
        sync_draft_sections(&win, st);
        if let Some(model) = st.borrow().section_models.get(s_idx) {
            model.push(to_detail(&new, false));
        }
    });
    on!(on_remove_field, |win, st, section: i32, field: i32| {
        let (s_idx, f_idx) = (section as usize, field as usize);
        let removed = {
            let mut state = st.borrow_mut();
            match state.shown_sections.get_mut(s_idx) {
                Some(sec) if f_idx < sec.fields.len() => {
                    sec.fields.remove(f_idx);
                    true
                }
                _ => false,
            }
        };
        if removed {
            sync_draft_sections(&win, st);
            if let Some(model) = st.borrow().section_models.get(s_idx) {
                model.remove(f_idx);
            }
        }
    });
    on!(on_delete_item, |win, st| {
        let st_ref = st.borrow();
        let Shown::Item { account, id } = st_ref.shown.clone() else {
            return;
        };
        let deleted = st_ref.item(account, &id).is_some_and(|i| i.deleted);
        let command = if deleted {
            Command::Delete(id)
        } else {
            Command::Trash(id)
        };
        let _ = st_ref.accounts[account].worker.tx.send(command);
        drop(st_ref);
        st.borrow_mut().accounts[account].busy = true;
    });
    on!(on_restore_item, |win, st| {
        let st_ref = st.borrow();
        let Shown::Item { account, id } = st_ref.shown.clone() else {
            return;
        };
        let _ = st_ref.accounts[account]
            .worker
            .tx
            .send(Command::Restore(id));
    });
    on!(on_unlock, |win, st, password: SharedString| {
        let Shown::Locked(account) = st.borrow().shown.clone() else {
            return;
        };
        if password.is_empty() {
            win.set_unlock_error(s("Enter the master password"));
            return;
        }
        win.set_unlock_error(SharedString::new());
        win.set_busy(true);
        let mut state = st.borrow_mut();
        state.accounts[account].busy = true;
        let _ = state.accounts[account].worker.tx.send(Command::Unlock {
            password: Zeroizing::new(password.to_string()),
        });
    });

    on!(
        on_sign_in_submit,
        |win, st, choice: i32, url: SharedString, email: SharedString, password: SharedString| {
            sign_in_submit(&win, st, choice, &url, &email, &password);
        }
    );
    on!(on_sign_in_code, |win,
                          st,
                          provider: i32,
                          code: SharedString,
                          remember: bool| {
        let mut state = st.borrow_mut();
        let si = &mut state.sign_in;
        let (Some(server), Some(worker)) = (si.server.clone(), si.worker.as_ref()) else {
            return;
        };
        let Some(provider) = si.providers.get(provider as usize).copied() else {
            return;
        };
        if code.trim().is_empty() {
            si.error = "Enter the code".into();
        } else {
            si.busy = true;
            si.error.clear();
            let _ = worker.tx.send(Command::SignIn {
                server,
                email: si.email.clone(),
                password: si.password.clone(),
                second: Some((provider, code.trim().to_string(), remember)),
            });
        }
        drop(state);
        render_sign_in(&win, st);
    });
    on!(on_sign_in_email, |win, st, provider: i32| {
        let _ = provider;
        let state = st.borrow();
        let si = &state.sign_in;
        if let (Some(server), Some(worker)) = (si.server.clone(), si.worker.as_ref()) {
            let _ = worker.tx.send(Command::SendEmailCode {
                server,
                email: si.email.clone(),
                password: si.password.clone(),
            });
        }
    });
    on!(on_sign_in_cancel, |win, st| {
        st.borrow_mut().sign_in = SignIn::default();
        let first = st.borrow().accounts.first().map(|a| a.profile.id.clone());
        match first {
            Some(key) => select(&win, st, &key),
            None => show_sign_in(&win, st),
        }
    });
    on!(on_account_sync, |win, st| {
        if let Shown::Account(account) = st.borrow().shown.clone() {
            sync_account(&win, st, account);
        }
    });
    on!(on_account_lock, |win, st| {
        if let Shown::Account(account) = st.borrow().shown.clone() {
            let _ = st.borrow().accounts[account].worker.tx.send(Command::Lock);
        }
    });
    on!(on_account_remove, |win, st| {
        if let Shown::Account(account) | Shown::Locked(account) = st.borrow().shown.clone() {
            let _ = st.borrow().accounts[account]
                .worker
                .tx
                .send(Command::Remove);
        }
    });
    on!(
        on_account_reconnect,
        |win, st, password: SharedString, code: SharedString, remember: bool| {
            let Shown::Account(account) = st.borrow().shown.clone() else {
                return;
            };
            let mut state = st.borrow_mut();
            let a = &mut state.accounts[account];
            let provider = if a.two_factor.contains(&TwoFactorProvider::Authenticator) {
                TwoFactorProvider::Authenticator
            } else {
                a.two_factor
                    .first()
                    .copied()
                    .unwrap_or(TwoFactorProvider::Authenticator)
            };
            let second =
                (!code.trim().is_empty()).then(|| (provider, code.trim().to_string(), remember));
            a.busy = true;
            let _ = a.worker.tx.send(Command::Reconnect {
                password: Zeroizing::new(password.to_string()),
                second,
            });
            drop(state);
            render(&win, st);
        }
    );

    on!(on_sync, |win, st| {
        let unlocked: Vec<usize> = st
            .borrow()
            .accounts
            .iter()
            .enumerate()
            .filter(|(_, a)| a.vault.is_some())
            .map(|(i, _)| i)
            .collect();
        if unlocked.is_empty() {
            toast(&win, st, "Unlock an account to sync it");
        }
        for account in unlocked {
            sync_account(&win, st, account);
        }
    });
    on!(on_new_item, |win, st| {
        if st.borrow().draft.as_ref().is_some_and(Draft::dirty) {
            st.borrow_mut().pending = Some(Pending::NewItem);
            win.set_leave_pending(true);
            return;
        }
        if !new_item(&win, st) {
            toast(&win, st, "Unlock an account first");
        }
    });
    on!(on_lock_all, |win, st| {
        if st.borrow().draft.as_ref().is_some_and(Draft::dirty) {
            st.borrow_mut().pending = Some(Pending::LockAll);
            win.set_leave_pending(true);
            return;
        }
        lock_all(&win, st);
        toast(&win, st, "Locked every account");
    });
    on!(on_ssh_answer, |win, st, allow: bool| {
        let prompt = st.borrow_mut().prompts.pop_front();
        if let Some(prompt) = prompt {
            prompt.answer(allow);
        }
        render_prompt(&win, st);
    });
    on!(on_agent_clicked, |win, st| {
        let (path, count) = {
            let state = st.borrow();
            match &state.agent {
                Ok(agent) => (
                    Ok(agent.socket_path().display().to_string()),
                    state.bridge.key_count(),
                ),
                Err(e) => (Err(e.clone()), 0),
            }
        };
        match path {
            Ok(path) => {
                let clipboard = st.borrow().clipboard.clone();
                let line = format!("export SSH_AUTH_SOCK={path}");
                let copied = Clipboard::copy(&clipboard, &line).is_ok();
                let keys = if count == 1 {
                    "1 key".to_string()
                } else {
                    format!("{count} keys")
                };
                let tail = if copied {
                    " Copied the SSH_AUTH_SOCK line."
                } else {
                    ""
                };
                toast(&win, st, &format!("SSH agent is offering {keys}.{tail}"));
            }
            Err(e) => toast(&win, st, &format!("The SSH agent could not start: {e}")),
        }
    });
    on!(on_ssh_toggle, |win, st, on: bool| {
        change_ssh_setting(&win, st, |setting| setting.0 = on);
    });
    on!(on_ssh_mode_picked, |win, st, index: i32| {
        change_ssh_setting(&win, st, |setting| {
            setting.1 = if index == 1 {
                AskMode::EveryTime
            } else {
                AskMode::FirstTime
            }
        });
    });
    on!(on_not_yet, |win, st, what: SharedString| {
        let milestone = if what.as_str() == "Settings" {
            "M3"
        } else {
            "M4"
        };
        toast(&win, st, &format!("{what} is planned for {milestone}"));
    });
}

fn ssh_key_id(account: &AccountState, item: &str) -> String {
    format!("{}/{}", account.profile.id, item)
}

fn load_ssh_settings(store: &Store) -> HashMap<String, (bool, AskMode)> {
    let settings = store.read_settings();
    let mut out = HashMap::new();
    if let Some(keys) = settings.get("ssh_keys").and_then(|v| v.as_object()) {
        for (id, value) in keys {
            let enabled = value
                .get("enabled")
                .and_then(|v| v.as_bool())
                .unwrap_or(true);
            let mode = AskMode::parse(value.get("ask").and_then(|v| v.as_str()).unwrap_or("first"));
            out.insert(id.clone(), (enabled, mode));
        }
    }
    out
}

fn save_ssh_settings(st: &Shared) {
    let state = st.borrow();
    let mut settings = state.store.read_settings();
    if !settings.is_object() {
        settings = serde_json::json!({});
    }
    let keys: serde_json::Map<String, serde_json::Value> = state
        .ssh_settings
        .iter()
        .map(|(id, (enabled, mode))| {
            (
                id.clone(),
                serde_json::json!({ "enabled": enabled, "ask": mode.as_str() }),
            )
        })
        .collect();
    settings["ssh_keys"] = serde_json::Value::Object(keys);
    let _ = state.store.write_settings(&settings);
}

/// Offers the SSH keys of unlocked accounts that are switched on.
fn update_agent_keys(win: &AppWindow, st: &Shared) {
    let state = st.borrow();
    let mut keys = Vec::new();
    let mut modes = HashMap::new();
    for account in &state.accounts {
        let Some(vault) = &account.vault else {
            continue;
        };
        for item in vault.items.iter().filter(|i| {
            i.kind == core::ItemKind::SshKey && !i.deleted && !i.ssh_key.private_key.is_empty()
        }) {
            let id = ssh_key_id(account, &item.id);
            let (enabled, mode) = state
                .ssh_settings
                .get(&id)
                .copied()
                .unwrap_or((true, AskMode::FirstTime));
            if enabled {
                keys.push(hushjar_agent::AgentKey {
                    id: id.clone(),
                    name: item.name.clone(),
                    private_key_openssh: hushjar_agent::Zeroizing::new(
                        item.ssh_key.private_key.clone(),
                    ),
                });
                modes.insert(id, mode);
            }
        }
    }
    state.bridge.set_keys(keys, modes);
    win.set_agent_keys(state.bridge.key_count() as i32);
}

fn render_ssh_settings(win: &AppWindow, st: &Shared) {
    let state = st.borrow();
    let shown = match &state.shown {
        Shown::Item { account, id } => state
            .item(*account, id)
            .filter(|i| i.kind == ItemType::SshKey && !i.id.starts_with("new-"))
            .map(|_| ssh_key_id(&state.accounts[*account], id)),
        _ => None,
    };
    win.set_ssh_visible(shown.is_some() && state.agent.is_ok());
    let (enabled, mode) = shown
        .and_then(|id| state.ssh_settings.get(&id).copied())
        .unwrap_or((true, AskMode::FirstTime));
    win.set_ssh_enabled(enabled);
    win.set_ssh_mode(if mode == AskMode::EveryTime { 1 } else { 0 });
}

fn change_ssh_setting(win: &AppWindow, st: &Shared, change: impl FnOnce(&mut (bool, AskMode))) {
    {
        let mut state = st.borrow_mut();
        let Shown::Item { account, id } = state.shown.clone() else {
            return;
        };
        let key = ssh_key_id(&state.accounts[account], &id);
        let setting = state
            .ssh_settings
            .entry(key)
            .or_insert((true, AskMode::FirstTime));
        change(setting);
    }
    save_ssh_settings(st);
    update_agent_keys(win, st);
    render_ssh_settings(win, st);
}

fn show_prompt(win: &AppWindow, st: &Shared, prompt: Prompt) {
    st.borrow_mut().prompts.push_back(prompt);
    render_prompt(win, st);
    use slint::winit_030::WinitWindowAccessor;
    win.window().with_winit_window(|w| {
        w.request_user_attention(Some(
            slint::winit_030::winit::window::UserAttentionType::Critical,
        ));
    });
}

fn render_prompt(win: &AppWindow, st: &Shared) {
    let text = st
        .borrow()
        .prompts
        .front()
        .map(|p| p.text.clone())
        .unwrap_or_default();
    win.set_ssh_prompt(text.into());
}

fn toast(win: &AppWindow, st: &Shared, text: &str) {
    let timer = st.borrow().toast_timer.clone();
    win.set_toast(text.into());
    let weak: Weak<AppWindow> = win.as_weak();
    let duration = Duration::from_millis(2200 + 40 * text.len() as u64);
    timer.start(TimerMode::SingleShot, duration, move || {
        if let Some(w) = weak.upgrade() {
            w.set_toast(SharedString::new());
        }
    });
}

fn copy(win: &AppWindow, st: &Shared, text: &str, label: &str) {
    let clipboard = st.borrow().clipboard.clone();
    match Clipboard::copy(&clipboard, text) {
        Ok(()) => toast(
            win,
            st,
            &format!(
                "Copied {label} · clears in {} s",
                crate::clipboard::CLEAR_AFTER.as_secs()
            ),
        ),
        Err(message) => toast(win, st, &message),
    }
}

/// Opens web addresses only; other schemes could start arbitrary programs.
fn open_url(win: &AppWindow, st: &Shared, url: &str) {
    let url = url.trim();
    let url = if url.contains("://") {
        url.to_string()
    } else {
        format!("https://{url}")
    };
    let lower = url.to_ascii_lowercase();
    if !(lower.starts_with("https://") || lower.starts_with("http://")) {
        toast(win, st, "Only web addresses can be opened");
        return;
    }
    let program = if cfg!(target_os = "macos") {
        "open"
    } else if cfg!(windows) {
        "explorer"
    } else {
        "xdg-open"
    };
    if let Err(err) = std::process::Command::new(program).arg(&url).spawn() {
        toast(win, st, &format!("Could not open the website: {err}"));
    }
}

/// 20 characters from a 64-character alphabet, using the OS random source.
fn generate_password() -> Zeroizing<String> {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut bytes = [0u8; 20];
    getrandom::fill(&mut bytes).expect("operating system random source");
    Zeroizing::new(
        bytes
            .iter()
            .map(|b| ALPHABET[(b & 63) as usize] as char)
            .collect(),
    )
}

fn add_blank_website(item: &mut Item) {
    if item.kind == ItemType::Login
        && let Some(sec) = item
            .sections
            .iter_mut()
            .find(|s| s.add == Some(model::AddKind::Website))
        && sec.fields.is_empty()
    {
        sec.fields.push(Field::url("https://"));
    }
}

fn handle_event(win: &AppWindow, st: &Shared, id: &str, event: Event) {
    if id.is_empty() {
        handle_sign_in_event(win, st, event);
    } else {
        handle_account_event(win, st, id, event);
    }
    update_agent_keys(win, st);
}

fn handle_account_event(win: &AppWindow, st: &Shared, id: &str, event: Event) {
    let Some(index) = st.borrow().account_index(id) else {
        return;
    };
    match event {
        Event::Unlocked { vault, synced_at } | Event::Synced { vault, synced_at } => {
            let first_unlock;
            {
                let mut state = st.borrow_mut();
                let a = &mut state.accounts[index];
                first_unlock = a.vault.is_none();
                a.view = Account::from_vault(&a.profile, &vault);
                a.vault = Some(vault);
                a.synced_at = synced_at.or(a.synced_at);
                a.busy = false;
                a.note.clear();
                if !first_unlock {
                    a.needs_sign_in = false;
                    a.two_factor.clear();
                }
                if first_unlock {
                    let key = a.profile.id.clone();
                    state.expanded.insert(key);
                }
            }
            win.set_busy(false);
            refresh_tree(win, st);
            if first_unlock {
                let key = st.borrow().accounts[index].profile.id.clone();
                select(win, st, &key);
                win.invoke_focus_tree();
            } else if !st.borrow().editing_shown() {
                reselect_shown(win, st);
                render(win, st);
            }
            update_sync_text(win, st);
        }
        Event::NeedsSignIn { two_factor } => {
            {
                let mut state = st.borrow_mut();
                let a = &mut state.accounts[index];
                a.busy = false;
                a.needs_sign_in = true;
                a.two_factor = two_factor;
                a.note = "Offline: sign in again to sync".into();
                if let Some(d) = state.draft.as_mut() {
                    d.saving = false;
                }
            }
            win.set_busy(false);
            render(win, st);
            toast(
                win,
                st,
                "Sign in again to sync this account (select the account)",
            );
        }
        Event::Saved { item, vault } => {
            let was_new;
            {
                let mut state = st.borrow_mut();
                was_new = state
                    .draft
                    .as_ref()
                    .is_some_and(|d| d.is_new && d.account == index);
                if state.draft.as_ref().is_some_and(|d| d.account == index) {
                    state.draft = None;
                }
                let a = &mut state.accounts[index];
                a.view = Account::from_vault(&a.profile, &vault);
                a.vault = Some(vault);
                a.busy = false;
                if let Shown::Item { account, .. } = &state.shown
                    && *account == index
                {
                    state.shown = Shown::Item {
                        account: index,
                        id: item.id.clone(),
                    };
                }
            }
            win.set_busy(false);
            refresh_tree(win, st);
            reselect_shown(win, st);
            render(win, st);
            toast(win, st, if was_new { "Created" } else { "Saved" });
            run_pending(win, st);
        }
        Event::Changed { vault, message } => {
            {
                let mut state = st.borrow_mut();
                let a = &mut state.accounts[index];
                a.view = Account::from_vault(&a.profile, &vault);
                a.vault = Some(vault);
                a.busy = false;
                if let Shown::Item { account, id } = state.shown.clone()
                    && account == index
                    && state.item(account, &id).is_none()
                {
                    state.shown = Shown::Nothing;
                }
            }
            refresh_tree(win, st);
            if !st.borrow().editing_shown() {
                reselect_shown(win, st);
                render(win, st);
            } else if let Some(account) = st.borrow().draft.as_ref().map(|d| d.account) {
                // A new folder: offer it in the folder box.
                let names: Vec<SharedString> = st
                    .borrow()
                    .folder_options(account)
                    .iter()
                    .map(|(_, n)| s(n))
                    .collect();
                win.set_folders(ModelRc::new(VecModel::from(names)));
            }
            toast(win, st, &message);
        }
        Event::Failed { message } | Event::SaveUncertain { message } => {
            {
                let mut state = st.borrow_mut();
                state.accounts[index].busy = false;
                state.accounts[index].note = message.clone();
                if let Some(d) = state.draft.as_mut() {
                    d.saving = false;
                }
            }
            win.set_busy(false);
            if matches!(st.borrow().shown, Shown::Locked(i) if i == index) {
                win.set_unlock_error(s(&message));
            } else {
                toast(win, st, &message);
            }
            if !st.borrow().editing_shown() {
                render(win, st);
            }
        }
        Event::Locked => {
            {
                let mut state = st.borrow_mut();
                let a = &mut state.accounts[index];
                a.view = Account::locked(&a.profile);
                a.vault = None;
                a.busy = false;
                if state.draft.as_ref().is_some_and(|d| d.account == index) {
                    state.draft = None;
                }
                let affected = match &state.shown {
                    Shown::Item { account, .. } | Shown::Account(account) => *account == index,
                    Shown::Group(key) => state.row(key).is_some_and(|r| r.account == index),
                    _ => false,
                };
                if affected {
                    state.shown = Shown::Locked(index);
                    state.selected = Some(state.accounts[index].profile.id.clone());
                }
            }
            refresh_tree(win, st);
            render(win, st);
            update_sync_text(win, st);
        }
        Event::Removed => {
            {
                let mut state = st.borrow_mut();
                let email = state.accounts[index].profile.email.clone();
                state.accounts.remove(index);
                state.draft = None;
                state.shown = Shown::Nothing;
                state.selected = None;
                drop(state);
                toast(win, st, &format!("Removed {email} from this computer"));
            }
            refresh_tree(win, st);
            let first = st.borrow().accounts.first().map(|a| a.profile.id.clone());
            match first {
                Some(key) => select(win, st, &key),
                None => show_sign_in(win, st),
            }
        }
        Event::SignedIn { .. } | Event::TwoFactorRequired { .. } | Event::EmailSent => {}
    }
}

fn handle_sign_in_event(win: &AppWindow, st: &Shared, event: Event) {
    match event {
        Event::SignedIn {
            profile,
            vault,
            synced_at,
        } => {
            let profile = *profile;
            let key = profile.id.clone();
            let email = profile.email.clone();
            {
                let mut state = st.borrow_mut();
                // The worker that signed in keeps the session and becomes
                // this account's worker; it now reports under the account's ID.
                let Some(worker) = state.sign_in.worker.take() else {
                    return;
                };
                state.sign_in = SignIn::default();
                if let Some(existing) = state.account_index(&key) {
                    state.accounts.remove(existing);
                }
                let view = Account::from_vault(&profile, &vault);
                state.accounts.push(AccountState {
                    profile,
                    view,
                    vault: Some(vault),
                    worker,
                    busy: false,
                    needs_sign_in: false,
                    two_factor: vec![],
                    synced_at,
                    note: String::new(),
                });
                state.expanded.insert(key.clone());
            }
            refresh_tree(win, st);
            select(win, st, &key);
            update_sync_text(win, st);
            toast(win, st, &format!("Signed in as {email}"));
        }
        Event::TwoFactorRequired { providers } => {
            {
                let mut state = st.borrow_mut();
                let si = &mut state.sign_in;
                si.busy = false;
                let supported: Vec<_> = providers
                    .into_iter()
                    .filter(|p| {
                        p.supported()
                            && !matches!(
                                p,
                                TwoFactorProvider::YubiKey | TwoFactorProvider::WebAuthn
                            )
                    })
                    .collect();
                if si.stage == 1 {
                    si.error = "That code was not accepted".into();
                } else if supported.is_empty() {
                    si.error =
                        "This account uses a two-step login method Hushjar does not support yet"
                            .into();
                } else {
                    si.stage = 1;
                    si.error.clear();
                }
                if !supported.is_empty() {
                    si.providers = supported;
                }
            }
            render_sign_in(win, st);
        }
        Event::EmailSent => {
            toast(win, st, "A code is on its way to your email");
        }
        Event::Failed { message } => {
            {
                let mut state = st.borrow_mut();
                state.sign_in.busy = false;
                state.sign_in.error = message;
            }
            render_sign_in(win, st);
        }
        _ => {}
    }
}

fn sign_in_submit(
    win: &AppWindow,
    st: &Shared,
    choice: i32,
    url: &str,
    email: &str,
    password: &str,
) {
    let server = match choice {
        0 => Server::parse("bitwarden.com"),
        1 => Server::parse("bitwarden.eu"),
        _ => Server::parse(url),
    };
    {
        let mut state = st.borrow_mut();
        let store = state.store.clone();
        let si = &mut state.sign_in;
        si.server_choice = choice;
        si.url = url.to_string();
        si.email = email.trim().to_string();
        match server {
            Err(e) => si.error = e.to_string(),
            Ok(_) if choice == 2 && url.trim().is_empty() => {
                si.error = "Enter your server's address".into()
            }
            Ok(_) if !email.contains('@') => si.error = "Enter your email address".into(),
            Ok(_) if password.is_empty() => si.error = "Enter your master password".into(),
            Ok(server) => {
                si.error.clear();
                si.busy = true;
                si.password = Zeroizing::new(password.to_string());
                si.server = Some(server.clone());
                if si.worker.is_none() {
                    si.worker = Some(Worker::spawn(store, None, emitter()));
                }
                if let Some(worker) = &si.worker {
                    let _ = worker.tx.send(Command::SignIn {
                        server,
                        email: si.email.clone(),
                        password: si.password.clone(),
                        second: None,
                    });
                }
            }
        }
    }
    render_sign_in(win, st);
}

fn show_sign_in(win: &AppWindow, st: &Shared) {
    {
        let mut state = st.borrow_mut();
        if state.draft.as_ref().is_some_and(Draft::dirty) {
            return;
        }
        state.draft = None;
        state.shown = Shown::SignIn;
        state.selected = None;
    }
    win.set_selected_key(SharedString::new());
    win.set_selected_index(-1);
    render(win, st);
}

fn render_sign_in(win: &AppWindow, st: &Shared) {
    let state = st.borrow();
    let si = &state.sign_in;
    let labels: Vec<SharedString> = si
        .providers
        .iter()
        .map(|p| {
            s(match p {
                TwoFactorProvider::Authenticator => "Authenticator app",
                TwoFactorProvider::Email => "Email",
                TwoFactorProvider::YubiKey => "YubiKey",
                TwoFactorProvider::WebAuthn => "Security key",
                TwoFactorProvider::Other(_) => "Other",
            })
        })
        .collect();
    win.set_sign_in(SignInForm {
        stage: si.stage,
        server_choice: si.server_choice,
        url: s(&si.url),
        email: s(&si.email),
        error: s(&si.error),
        busy: si.busy,
        email_provider: si.providers.first() == Some(&TwoFactorProvider::Email)
            && si.providers.len() == 1
            || si.providers.contains(&TwoFactorProvider::Email)
                && !si.providers.contains(&TwoFactorProvider::Authenticator),
        providers: ModelRc::new(VecModel::from(labels)),
        provider_index: 0,
        reconnect: false,
    });
    if state.shown == Shown::SignIn {
        win.set_mode(PaneMode::SignIn);
    }
}

fn sync_account(win: &AppWindow, st: &Shared, account: usize) {
    {
        let mut state = st.borrow_mut();
        let a = &mut state.accounts[account];
        if a.vault.is_none() || a.busy {
            return;
        }
        a.busy = true;
        let _ = a.worker.tx.send(Command::Sync);
    }
    win.set_sync_text(s("Syncing…"));
    if matches!(st.borrow().shown, Shown::Account(i) if i == account) {
        render(win, st);
    }
}

fn update_sync_text(win: &AppWindow, st: &Shared) {
    let state = st.borrow();
    let latest = state
        .accounts
        .iter()
        .filter(|a| a.vault.is_some())
        .filter_map(|a| a.synced_at)
        .max();
    let text = if state.accounts.iter().any(|a| a.busy && a.vault.is_some()) {
        "Syncing…".to_string()
    } else if !state.any_unlocked() {
        String::new()
    } else {
        relative(latest)
    };
    win.set_sync_text(text.into());
}

fn refresh_tree(win: &AppWindow, st: &Shared) {
    let mut st = st.borrow_mut();
    let views = st.views();
    let built = tree::build(&views, st.group_by, &st.expanded, &st.filter);
    st.rows = built.rows;
    let rows: Vec<TreeRow> = st
        .rows
        .iter()
        .map(|r| TreeRow {
            key: s(&r.key),
            kind: r.kind,
            icon: r.icon,
            depth: r.depth as i32,
            label: s(&r.label),
            detail: s(&r.detail),
            count: r.count as i32,
            expandable: r.expandable,
            expanded: r.expanded,
            locked: r.locked,
            tint: color(views[r.account].tint),
            initials: s(&views[r.account].initials),
        })
        .collect();
    st.rows_model.set_vec(rows);
    win.set_match_count(built.matches as i32);
    win.set_group_by(st.group_by.index());
    win.set_selected_key(st.selected.as_deref().map(s).unwrap_or_default());
    win.set_selected_index(st.selected_index().map(|i| i as i32).unwrap_or(-1));
}

fn toggle(win: &AppWindow, st: &Shared, key: &str) {
    {
        let mut st = st.borrow_mut();
        if st.filtering() {
            return;
        }
        if !st.expanded.remove(key) {
            st.expanded.insert(key.to_string());
        }
    }
    refresh_tree(win, st);
}

fn activate(win: &AppWindow, st: &Shared, key: &str) {
    let row = st.borrow().row(key).cloned();
    let Some(row) = row else { return };
    if row.locked {
        select(win, st, key);
        win.set_unlock_focus_request(win.get_unlock_focus_request() + 1);
    } else if row.expandable {
        toggle(win, st, key);
    }
}

fn select(win: &AppWindow, st: &Shared, key: &str) {
    {
        let mut s = st.borrow_mut();
        if let Some(d) = &s.draft {
            let same_item = s.row(key).and_then(|r| r.item.as_deref()) == Some(d.item.id.as_str())
                && s.row(key).map(|r| r.account) == Some(d.account);
            if !same_item {
                if d.dirty() {
                    s.pending = Some(Pending::Select(key.to_string()));
                    drop(s);
                    win.set_leave_pending(true);
                    return;
                }
                s.draft = None;
            }
        }
        let Some(row) = s.row(key).cloned() else {
            return;
        };
        s.selected = Some(key.to_string());
        s.shown = match (&row.kind, &row.item) {
            (RowKind::Item, Some(id)) => Shown::Item {
                account: row.account,
                id: id.clone(),
            },
            (RowKind::Account, _) if row.locked => Shown::Locked(row.account),
            (RowKind::Account, _) => Shown::Account(row.account),
            _ => Shown::Group(row.key.clone()),
        };
    }
    win.set_unlock_error(SharedString::new());
    win.set_selected_key(key.into());
    let index = st.borrow().selected_index().map(|i| i as i32).unwrap_or(-1);
    win.set_selected_index(index);
    render(win, st);
}

fn account_summary(a: &AccountState) -> AccountSummary {
    let status = if a.busy {
        "Working…".to_string()
    } else if a.needs_sign_in {
        "Offline: sign in again to sync".to_string()
    } else if !a.note.is_empty() {
        a.note.clone()
    } else {
        relative(a.synced_at)
    };
    AccountSummary {
        email: s(&a.profile.email),
        server: s(&a.profile.server.name),
        tint: color(a.view.tint),
        initials: s(&a.view.initials),
        status: status.into(),
        needs_sign_in: a.needs_sign_in,
        two_factor: !a.two_factor.is_empty(),
        busy: a.busy,
        count: a.view.items.iter().filter(|i| !i.deleted).count() as i32,
    }
}

fn render(win: &AppWindow, st: &Shared) {
    let shown = st.borrow().shown.clone();
    let editing = st.borrow().editing_shown();
    win.set_editing(editing);
    win.set_leave_pending(st.borrow().pending.is_some());
    win.set_dirty(st.borrow().draft.as_ref().is_some_and(Draft::dirty));
    win.set_busy(st.borrow().draft.as_ref().is_some_and(|d| d.saving) || matches!(shown, Shown::Locked(i) if st.borrow().accounts.get(i).is_some_and(|a| a.busy)));
    match shown {
        Shown::Nothing => win.set_mode(PaneMode::Empty),
        Shown::SignIn => {
            render_sign_in(win, st);
            win.set_mode(PaneMode::SignIn);
        }
        Shown::Account(account) => {
            let Some(summary) = st.borrow().accounts.get(account).map(account_summary) else {
                return;
            };
            win.set_summary(summary);
            win.set_mode(PaneMode::Account);
        }
        Shown::Locked(account) => {
            let st = st.borrow();
            let Some(a) = st.accounts.get(account) else {
                return;
            };
            win.set_account(AccountBadge {
                email: s(&a.profile.email),
                server: s(&a.profile.server.name),
                tint: color(a.view.tint),
                initials: s(&a.view.initials),
            });
            win.set_mode(PaneMode::Locked);
        }
        Shown::Group(key) => {
            let st = st.borrow();
            let Some(row) = st.row(&key) else {
                win.set_mode(PaneMode::Empty);
                return;
            };
            let parent = row
                .path
                .rsplit_once(" › ")
                .map(|(p, _)| p.to_string())
                .unwrap_or_default();
            win.set_group(GroupSummary {
                title: s(&row.label),
                icon: row.icon,
                path: if parent.is_empty() {
                    s(&row.path)
                } else {
                    parent.into()
                },
                count: row.count as i32,
            });
            win.set_mode(PaneMode::Group);
        }
        Shown::Item { account, id } => {
            let mut stm = st.borrow_mut();
            let Some(item) = stm.item(account, &id).cloned() else {
                drop(stm);
                win.set_mode(PaneMode::Empty);
                return;
            };
            let mut models = Vec::new();
            let mut sections = Vec::new();
            let mut shown_sections = Vec::new();
            for section in &item.sections {
                if editing && section.view_only {
                    continue;
                }
                let fields: Vec<&Field> = if editing {
                    section.fields.iter().collect()
                } else {
                    section
                        .fields
                        .iter()
                        .filter(|f| !f.value.is_empty())
                        .collect()
                };
                if !editing && fields.is_empty() {
                    continue;
                }
                let model = Rc::new(VecModel::from(
                    fields
                        .iter()
                        .map(|f| to_detail(f, !editing))
                        .collect::<Vec<_>>(),
                ));
                sections.push(DetailSection {
                    title: s(&section.title),
                    fields: ModelRc::from(model.clone()),
                    add_label: section.add.map(|a| s(a.label())).unwrap_or_default(),
                });
                shown_sections.push(model::Section {
                    fields: fields.into_iter().cloned().collect(),
                    ..section.clone()
                });
                models.push(model);
            }
            if !editing && !item.created.is_empty() {
                let history = vec![
                    DetailField {
                        label: s("Created"),
                        value: s(&item.created),
                        kind: FieldKind::Info,
                        ..Default::default()
                    },
                    DetailField {
                        label: s("Last edited"),
                        value: s(&item.revised),
                        kind: FieldKind::Info,
                        ..Default::default()
                    },
                ];
                let model = Rc::new(VecModel::from(history));
                sections.push(DetailSection {
                    title: s("History"),
                    fields: ModelRc::from(model.clone()),
                    add_label: SharedString::new(),
                });
                shown_sections.push(model::Section::new("History", vec![]));
                models.push(model);
            }
            stm.section_models = models;
            stm.shown_sections = shown_sections;
            let options = stm.folder_options(account);
            let folder_index = options
                .iter()
                .position(|(id, _)| *id == item.folder)
                .unwrap_or(0);
            let names: Vec<SharedString> = options.iter().map(|(_, name)| s(name)).collect();
            let type_index = ItemType::CREATABLE
                .iter()
                .position(|t| *t == item.kind)
                .unwrap_or(0);
            drop(stm);
            win.set_sections(ModelRc::new(VecModel::from(sections)));
            win.set_folders(ModelRc::new(VecModel::from(names)));
            win.set_folder_index(folder_index as i32);
            win.set_type_index(type_index as i32);
            render_ssh_settings(win, st);
            render_header(win, st);
            win.set_mode(PaneMode::Item);
        }
    }
}

fn render_header(win: &AppWindow, st: &Shared) {
    let st = st.borrow();
    let Shown::Item { account, id } = &st.shown else {
        return;
    };
    let Some(item) = st.item(*account, id) else {
        return;
    };
    let is_new = st
        .draft
        .as_ref()
        .is_some_and(|d| d.is_new && d.item.id == *id);
    let unlocked = st
        .accounts
        .get(*account)
        .is_some_and(|a| a.vault.is_some() && !a.needs_sign_in);
    win.set_header(ItemHeader {
        name: s(if item.name.is_empty() && !st.editing_shown() {
            "Untitled"
        } else {
            &item.name
        }),
        icon: item.kind.icon(),
        path: st.item_path(*account, item).into(),
        favorite: item.favorite,
        deleted: item.deleted,
        is_new,
        editable: item.editable && unlocked,
    });
}

/// Updates verification codes in place, so revealed fields stay revealed.
fn refresh_codes(st: &Shared) {
    let st = st.borrow();
    if st.editing_shown() {
        return;
    }
    for (model, section) in st.section_models.iter().zip(&st.shown_sections) {
        for (row, field) in section.fields.iter().enumerate() {
            if field.kind == FieldKind::Totp && row < model.row_count() {
                model.set_row_data(row, to_detail(field, true));
            }
        }
    }
}

fn begin_edit(win: &AppWindow, st: &Shared) {
    {
        let mut state = st.borrow_mut();
        if state.draft.is_some() {
            return;
        }
        let Shown::Item { account, id } = state.shown.clone() else {
            return;
        };
        let Some(item) = state.item(account, &id).cloned() else {
            return;
        };
        let online =
            state.accounts[account].vault.is_some() && !state.accounts[account].needs_sign_in;
        if item.deleted || !item.editable || !online {
            drop(state);
            if !online {
                toast(win, st, "Sign in again to edit items in this account");
            }
            return;
        }
        let Some(core) = state.core_item(account, &id).cloned() else {
            return;
        };
        let mut editable = item.clone();
        add_blank_website(&mut editable);
        state.draft = Some(Draft {
            account,
            original: item,
            item: editable,
            core,
            is_new: false,
            saving: false,
        });
    }
    render(win, st);
}

fn edit_draft(win: &AppWindow, st: &Shared, change: impl FnOnce(&mut Item)) {
    let dirty = {
        let mut st = st.borrow_mut();
        let Some(d) = st.draft.as_mut() else { return };
        change(&mut d.item);
        d.dirty()
    };
    win.set_dirty(dirty);
}

/// Changes one shown field while editing and copies the edit into the draft.
fn edit_shown_field(
    win: &AppWindow,
    st: &Shared,
    section: usize,
    field: usize,
    change: impl FnOnce(&mut Field),
) {
    {
        let mut state = st.borrow_mut();
        let Some(f) = state
            .shown_sections
            .get_mut(section)
            .and_then(|s| s.fields.get_mut(field))
        else {
            return;
        };
        change(f);
    }
    sync_draft_sections(win, st);
}

/// While editing, the shown sections are the draft's sections (view-only
/// sections are left out), so copy them back in order.
fn sync_draft_sections(win: &AppWindow, st: &Shared) {
    let dirty = {
        let mut state = st.borrow_mut();
        let shown = state.shown_sections.clone();
        let Some(d) = state.draft.as_mut() else {
            return;
        };
        let mut shown = shown.into_iter();
        for section in d.item.sections.iter_mut().filter(|s| !s.view_only) {
            if let Some(edited) = shown.next() {
                section.fields = edited.fields;
            }
        }
        d.dirty()
    };
    win.set_dirty(dirty);
}

fn save(win: &AppWindow, st: &Shared) {
    let message = {
        let mut state = st.borrow_mut();
        let Some(draft) = state.draft.as_mut() else {
            return;
        };
        if draft.saving {
            return;
        }
        if !draft.dirty() {
            state.draft = None;
            None
        } else if draft.item.name.trim().is_empty() {
            Some("Give the item a name first")
        } else {
            let mut core = model::apply(&draft.item, &draft.core);
            if draft.is_new {
                core.id.clear();
            }
            draft.saving = true;
            let account = draft.account;
            let _ = state.accounts[account]
                .worker
                .tx
                .send(Command::Save(Box::new(core)));
            state.accounts[account].busy = true;
            None
        }
    };
    if let Some(message) = message {
        toast(win, st, message);
    }
    render(win, st);
}

/// Saves a small change to the shown item without entering edit mode.
fn quick_save(win: &AppWindow, st: &Shared, change: impl FnOnce(&mut core::Item)) {
    let state = st.borrow();
    let Shown::Item { account, id } = state.shown.clone() else {
        return;
    };
    let editable = state.item(account, &id).is_some_and(|i| i.editable)
        && !state.accounts[account].needs_sign_in;
    let Some(mut core) = state.core_item(account, &id).cloned().filter(|_| editable) else {
        drop(state);
        toast(win, st, "This item cannot be changed right now");
        return;
    };
    change(&mut core);
    let _ = state.accounts[account]
        .worker
        .tx
        .send(Command::Save(Box::new(core)));
}

/// After the tree changes, point the selection at a row for the shown item.
fn reselect_shown(win: &AppWindow, st: &Shared) {
    let key = {
        let s = st.borrow();
        let Shown::Item { account, id } = &s.shown else {
            return;
        };
        if s.selected
            .as_deref()
            .and_then(|k| s.row(k))
            .and_then(|r| r.item.as_ref())
            == Some(id)
        {
            return;
        }
        s.rows
            .iter()
            .filter(|r| r.account == *account && r.item.as_deref() == Some(id))
            .find(|r| !r.key.contains("/fav/"))
            .map(|r| r.key.clone())
    };
    if let Some(key) = key {
        st.borrow_mut().selected = Some(key.clone());
        win.set_selected_key(key.into());
        let index = st.borrow().selected_index().map(|i| i as i32).unwrap_or(-1);
        win.set_selected_index(index);
    }
}

fn cancel(win: &AppWindow, st: &Shared) {
    {
        let mut s = st.borrow_mut();
        let Some(draft) = s.draft.take() else { return };
        if draft.saving {
            s.draft = Some(draft);
            return;
        }
        if draft.is_new {
            s.shown = match s.selected.clone() {
                Some(key) if s.row(&key).is_some() => Shown::Group(key),
                _ => Shown::Nothing,
            };
        }
    }
    render(win, st);
}

fn run_pending(win: &AppWindow, st: &Shared) {
    if st.borrow().draft.is_some() {
        return;
    }
    let pending = st.borrow_mut().pending.take();
    win.set_leave_pending(false);
    match pending {
        Some(Pending::Select(key)) => select(win, st, &key),
        Some(Pending::LockAll) => lock_all(win, st),
        Some(Pending::NewItem) => {
            new_item(win, st);
        }
        None => {}
    }
}

fn lock_all(win: &AppWindow, st: &Shared) {
    {
        let mut s = st.borrow_mut();
        s.draft = None;
        s.pending = None;
        for a in &s.accounts {
            if a.vault.is_some() {
                let _ = a.worker.tx.send(Command::Lock);
            }
        }
        s.clipboard.borrow_mut().clear_if_ours();
    }
    win.set_leave_pending(false);
}

/// Starts a new login in the selected account, folder or collection.
/// Returns false when no account is unlocked.
fn new_item(win: &AppWindow, st: &Shared) -> bool {
    {
        let mut s = st.borrow_mut();
        let selected = s.selected.as_deref().and_then(|k| s.row(k)).cloned();
        let usable = |a: &AccountState| a.vault.is_some() && !a.needs_sign_in;
        let account = selected
            .as_ref()
            .map(|r| r.account)
            .filter(|a| usable(&s.accounts[*a]))
            .or_else(|| s.accounts.iter().position(usable));
        let Some(account) = account else { return false };
        let row = selected.filter(|r| r.account == account);
        let folder = row.as_ref().and_then(|r| r.folder.clone());
        // In a collection, create the item in that collection's organisation.
        let collection = row.as_ref().and_then(|r| {
            r.key
                .split_once("/c/")
                .map(|(_, id)| id.split('/').next().unwrap_or(id).to_string())
        });
        let organization = collection.as_ref().and_then(|c| {
            s.accounts[account]
                .vault
                .as_ref()?
                .collections
                .iter()
                .find(|x| x.id == *c)
                .map(|x| x.organization_id.clone())
        });
        let mut core = core::Item::new(core::ItemKind::Login, organization.clone(), folder);
        if organization.is_some() {
            core.collection_ids = collection.into_iter().collect();
        }
        let id = format!("new-{}", s.next_id);
        s.next_id += 1;
        let mut item = model::from_core(&core);
        item.id = id.clone();
        add_blank_website(&mut item);
        s.draft = Some(Draft {
            account,
            original: item.clone(),
            item,
            core,
            is_new: true,
            saving: false,
        });
        s.shown = Shown::Item { account, id };
    }
    win.set_type_index(0);
    render(win, st);
    true
}

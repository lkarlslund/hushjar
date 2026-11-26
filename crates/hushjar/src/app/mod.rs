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
use crate::prefs::{LockAction, Prefs};
use crate::sshagent::{AskMode, Bridge, Prompt};
use crate::tree::{self, GroupBy, Row};
use crate::worker::{Command, Event, Worker};
mod edit;
mod events;
mod generator;
mod integration;
mod sends;
mod settings;
mod sign_in;
mod ssh;
mod view;
mod wire;

use edit::*;
use events::*;
use generator::{Generator, render_generator, show_generator, wire_generator};
use integration::Integration;
use sends::{Sends, forget_sends, render_sends, show_sends, wire_sends};
use settings::*;
use sign_in::*;
use ssh::*;
use view::*;
use wire::*;

use crate::{
    AccountBadge, AccountSummary, AppWindow, DetailField, DetailSection, FieldKind, GroupSummary,
    ItemHeader, PaneMode, RowKind, SignInForm, TreeRow,
};

#[derive(Clone, Debug, PartialEq)]
enum Shown {
    Nothing,
    Item { account: usize, id: String },
    Group(String),
    Locked(usize),
    Account(usize),
    SignIn,
    Settings,
    Generator,
    Sends,
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
    Settings,
    Generator,
    Sends,
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
    unlock: UnlockOptions,
}

/// Ways to unlock an account other than the master password.
#[derive(Clone, Copy, Debug, Default)]
struct UnlockOptions {
    pin: bool,
    system_auth: bool,
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
    prefs: Prefs,
    /// The desktop's own colour scheme, for the "System" theme.
    system_scheme: slint::language::ColorScheme,
    desktop: Integration,
    generator: Generator,
    sends: Sends,
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
                unlock: UnlockOptions::default(),
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
        let prefs = Prefs::from_settings(&store.read_settings());
        let generator = Generator::from_settings(&store.read_settings());
        let system_scheme = window.global::<crate::Palette>().get_color_scheme();
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
            prefs,
            system_scheme,
            desktop: Integration::new(),
            generator,
            sends: Sends::default(),
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
        wire_settings(&app.window, &state);
        wire_generator(&app.window, &state);
        wire_sends(&app.window, &state);
        apply_prefs(&app.window, &state);
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
            let limit = st.borrow().idle_limit();
            let idle = limit.is_some_and(|limit| st.borrow().last_activity.elapsed() > limit)
                && st.borrow().any_unlocked();
            if idle {
                st.borrow_mut().draft = None;
                time_out_all(&w, &st);
            }
        });
        Ok(Self {
            _timers: vec![ticker],
            ..app
        })
    }
}

impl State {
    /// The strictest of the user's choice and any organisation policy.
    fn idle_limit(&self) -> Option<Duration> {
        match (self.prefs.idle_limit(), self.policy_idle_limit()) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        }
    }

    /// The longest timeout organisation policies allow, if any.
    fn policy_idle_limit(&self) -> Option<Duration> {
        None
    }

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
        Ok(()) => {
            let delay = clipboard.borrow().clear_after;
            let text = match delay {
                Some(d) if d.as_secs() >= 60 => {
                    format!("Copied {label} · clears in {} min", d.as_secs() / 60)
                }
                Some(d) => format!("Copied {label} · clears in {} s", d.as_secs()),
                None => format!("Copied {label}"),
            };
            toast(win, st, &text)
        }
        Err(message) => toast(win, st, &message),
    }
}

/// Copies something that is not a secret, such as a shell line.
fn copy_plain(win: &AppWindow, st: &Shared, text: &str) {
    let clipboard = st.borrow().clipboard.clone();
    match Clipboard::copy(&clipboard, text) {
        Ok(()) => toast(win, st, "Copied"),
        Err(message) => toast(win, st, &message),
    }
}

/// When the user has unsaved changes, asks first and returns false;
/// `then` runs once they choose to leave.
fn leave_to(win: &AppWindow, st: &Shared, then: Pending) -> bool {
    if st.borrow().draft.as_ref().is_some_and(Draft::dirty) {
        st.borrow_mut().pending = Some(then);
        win.set_leave_pending(true);
        return false;
    }
    st.borrow_mut().draft = None;
    true
}

/// Locks, or logs out, every unlocked account after the idle time.
fn time_out_all(win: &AppWindow, st: &Shared) {
    let log_out = st.borrow().prefs.lock_action == LockAction::LogOut;
    if log_out {
        let s = st.borrow();
        for a in &s.accounts {
            if a.vault.is_some() {
                let _ = a.worker.tx.send(Command::LogOut);
            }
        }
        s.clipboard.borrow_mut().clear_if_ours();
        drop(s);
        toast(win, st, "Logged out after no activity");
    } else {
        lock_all(win, st);
        toast(win, st, "Locked after no activity");
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

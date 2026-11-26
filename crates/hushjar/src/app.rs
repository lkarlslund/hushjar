//! Prototype app state and the glue between it and the Slint window.

use std::cell::RefCell;
use std::collections::HashSet;
use std::hash::{Hash, Hasher};
use std::rc::Rc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use slint::{
    Color, ComponentHandle, Model, ModelRc, SharedString, Timer, TimerMode, VecModel, Weak,
};

use crate::mock::{self, Account, Field, Item, ItemType};
use crate::tree::{self, GroupBy, Row};
use crate::{
    AccountBadge, AppWindow, DetailField, DetailSection, FieldKind, GroupSummary, ItemHeader,
    PaneMode, RowIcon, RowKind, TreeRow,
};

const TOTP_PERIOD: u64 = 30;

#[derive(Clone, Debug, PartialEq)]
enum Shown {
    Nothing,
    Item { account: usize, id: String },
    Group(String),
    Locked(usize),
}

struct Draft {
    account: usize,
    item: Item,
    original: Item,
    is_new: bool,
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

pub struct State {
    accounts: Vec<Account>,
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
    rows_model: Rc<VecModel<TreeRow>>,
    toast_timer: Rc<Timer>,
    next_id: usize,
}

type Shared = Rc<RefCell<State>>;

pub struct App {
    pub window: AppWindow,
    state: Shared,
    _timers: Vec<Timer>,
}

fn color((r, g, b): (u8, u8, u8)) -> Color {
    Color::from_rgb_u8(r, g, b)
}

fn s(value: &str) -> SharedString {
    value.into()
}

/// A stand-in for real TOTP: stable for each 30-second step, but not RFC 6238.
/// The real implementation belongs in hushjar-core (M1).
fn mock_totp(secret: &str) -> String {
    let step = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
        / TOTP_PERIOD;
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    (secret, step).hash(&mut hasher);
    let code = hasher.finish() % 1_000_000;
    format!("{:03} {:03}", code / 1000, code % 1000)
}

fn totp_remaining() -> i32 {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    (TOTP_PERIOD - now % TOTP_PERIOD) as i32
}

/// 20 characters from a 64-character alphabet, using the OS random source.
fn generate_password() -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut bytes = [0u8; 20];
    getrandom::fill(&mut bytes).expect("operating system random source");
    bytes
        .iter()
        .map(|b| ALPHABET[(b & 63) as usize] as char)
        .collect()
}

fn to_detail(field: &Field, view: bool) -> DetailField {
    let value = if view && field.kind == FieldKind::Totp {
        mock_totp(&field.value)
    } else {
        field.value.clone()
    };
    DetailField {
        label: s(&field.label),
        value: value.into(),
        kind: field.kind,
        copyable: field.copyable,
        removable: field.removable,
        label_editable: field.label_editable,
    }
}

impl State {
    fn new(accounts: Vec<Account>) -> Self {
        let expanded = ["p", "w", "p/f/Work", "p/f/Work/Code"]
            .into_iter()
            .map(String::from)
            .collect();
        Self {
            accounts,
            group_by: GroupBy::Folders,
            expanded,
            filter: String::new(),
            rows: vec![],
            selected: None,
            shown: Shown::Nothing,
            draft: None,
            pending: None,
            section_models: vec![],
            rows_model: Rc::new(VecModel::default()),
            toast_timer: Rc::new(Timer::default()),
            next_id: 1,
        }
    }

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

    fn item(&self, account: usize, id: &str) -> Option<&Item> {
        if let Some(d) = &self.draft
            && d.account == account
            && d.item.id == id
        {
            return Some(&d.item);
        }
        self.accounts
            .get(account)?
            .items
            .iter()
            .find(|i| i.id == id)
    }

    fn editing_shown(&self) -> bool {
        matches!((&self.shown, &self.draft), (Shown::Item { account, id }, Some(d)) if d.account == *account && d.item.id == *id)
    }

    fn folder_options(&self, account: usize) -> Vec<(Option<String>, String)> {
        let mut options = vec![(None, "No folder".to_string())];
        let mut folders = self.accounts[account].folders.clone();
        folders.sort_by(|a, b| a.name.cmp(&b.name));
        options.extend(folders.into_iter().map(|f| (Some(f.id), f.name)));
        options
    }

    fn item_path(&self, account: usize, item: &Item) -> String {
        let a = &self.accounts[account];
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
}

impl App {
    pub fn new() -> Result<Self, slint::PlatformError> {
        let window = AppWindow::new()?;
        let state: Shared = Rc::new(RefCell::new(State::new(mock::sample())));
        window.set_rows(ModelRc::from(state.borrow().rows_model.clone()));
        window.set_sync_text(s("Synced 2 min ago"));

        let app = Self {
            window,
            state,
            _timers: vec![],
        };
        app.wire();
        refresh_tree(&app.window, &app.state);
        select(&app.window, &app.state, "p/f/Work/Code/i/github");

        let totp = Timer::default();
        let weak = app.window.as_weak();
        let state = app.state.clone();
        totp.start(TimerMode::Repeated, Duration::from_secs(1), move || {
            if let Some(w) = weak.upgrade() {
                let remaining = totp_remaining();
                w.set_totp_remaining(remaining);
                if remaining == TOTP_PERIOD as i32 {
                    refresh_codes(&state);
                }
            }
        });
        app.window.set_totp_remaining(totp_remaining());
        Ok(Self {
            _timers: vec![totp],
            ..app
        })
    }

    fn wire(&self) {
        let w = &self.window;
        let weak = w.as_weak();
        let state = self.state.clone();

        // Every callback gets a weak window handle and the shared state.
        macro_rules! on {
            ($setter:ident, |$win:ident, $st:ident $(, $arg:ident : $ty:ty)*| $body:block) => {{
                let weak = weak.clone();
                let state = state.clone();
                w.$setter(move |$($arg: $ty),*| {
                    let Some($win) = weak.upgrade() else { return };
                    let $st = &state;
                    $body
                });
            }};
        }

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
            toast(&win, st, "Adding accounts arrives with real sign-in in M1");
        });

        on!(on_copy_field, |win, st, section: i32, field: i32| {
            let value = st
                .borrow()
                .section_models
                .get(section as usize)
                .and_then(|m| m.row_data(field as usize));
            if let Some(f) = value {
                win.invoke_copy_text(f.value.clone());
                toast(&win, st, &format!("Copied {}", f.label.to_lowercase()));
            }
        });
        on!(on_copy_shortcut, |win, st, which: SharedString| {
            let label = match which.as_str() {
                "username" => "Username",
                "password" => "Password",
                _ => "Verification code",
            };
            let found = {
                let st = st.borrow();
                match &st.shown {
                    Shown::Item { account, id } => st
                        .item(*account, id)
                        .and_then(|i| i.field(label))
                        .filter(|f| !f.value.is_empty())
                        .map(|f| to_detail(f, true).value),
                    _ => None,
                }
            };
            match found {
                Some(value) => {
                    win.invoke_copy_text(value);
                    toast(&win, st, &format!("Copied {}", label.to_lowercase()));
                }
                None => toast(
                    &win,
                    st,
                    &format!("This item has no {}", label.to_lowercase()),
                ),
            }
        });
        on!(on_open_url, |win, st, url: SharedString| {
            if let Err(err) = std::process::Command::new("xdg-open")
                .arg(url.as_str())
                .spawn()
            {
                toast(&win, st, &format!("Could not open the website: {err}"));
            }
        });

        on!(on_begin_edit, |win, st| {
            begin_edit(&win, st);
        });
        on!(on_save, |win, st| {
            if let Some(message) = save(&win, st) {
                toast(&win, st, &message);
            }
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
            let message = save(&win, st);
            let saved = st.borrow().draft.is_none();
            if let Some(message) = message {
                toast(&win, st, &message);
            }
            if saved {
                run_pending(&win, st);
            } else {
                st.borrow_mut().pending = None;
                win.set_leave_pending(false);
            }
        });
        on!(
            on_edit_field,
            |win, st, section: i32, field: i32, text: SharedString| {
                edit_draft(&win, st, |item| {
                    if let Some(f) = item
                        .sections
                        .get_mut(section as usize)
                        .and_then(|s| s.fields.get_mut(field as usize))
                    {
                        f.value = text.to_string();
                    }
                });
            }
        );
        on!(
            on_edit_label,
            |win, st, section: i32, field: i32, text: SharedString| {
                edit_draft(&win, st, |item| {
                    if let Some(f) = item
                        .sections
                        .get_mut(section as usize)
                        .and_then(|s| s.fields.get_mut(field as usize))
                    {
                        f.label = text.to_string();
                    }
                });
            }
        );
        on!(on_edit_name, |win, st, text: SharedString| {
            edit_draft(&win, st, |item| item.name = text.to_string());
        });
        on!(on_toggle_favorite, |win, st| {
            if st.borrow().editing_shown() {
                edit_draft(&win, st, |item| item.favorite = !item.favorite);
                render_header(&win, st);
                return;
            }
            let now = {
                let mut st = st.borrow_mut();
                let Shown::Item { account, id } = st.shown.clone() else {
                    return;
                };
                let Some(item) = st.accounts[account].items.iter_mut().find(|i| i.id == id) else {
                    return;
                };
                item.favorite = !item.favorite;
                item.favorite
            };
            refresh_tree(&win, st);
            render_header(&win, st);
            toast(
                &win,
                st,
                if now {
                    "Added to favourites"
                } else {
                    "Removed from favourites"
                },
            );
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
        on!(on_generate, |win, st, section: i32, field: i32| {
            let password = generate_password();
            let (s_idx, f_idx) = (section as usize, field as usize);
            edit_draft(&win, st, |item| {
                if let Some(f) = item
                    .sections
                    .get_mut(s_idx)
                    .and_then(|s| s.fields.get_mut(f_idx))
                {
                    f.value = password.clone();
                }
            });
            // Re-insert the row so its editor picks up the new value.
            {
                let state = st.borrow();
                if let (Some(model), Some(draft)) = (state.section_models.get(s_idx), &state.draft)
                    && let Some(f) = draft
                        .item
                        .sections
                        .get(s_idx)
                        .and_then(|s| s.fields.get(f_idx))
                    && f_idx < model.row_count()
                {
                    model.remove(f_idx);
                    model.insert(f_idx, to_detail(f, false));
                }
            }
            toast(&win, st, "Generated a new password");
        });
        on!(on_add_field, |win, st, section: i32| {
            let s_idx = section as usize;
            let mut new = None;
            edit_draft(&win, st, |item| {
                if let Some(sec) = item.sections.get_mut(s_idx)
                    && let Some(kind) = sec.add
                {
                    let f = kind.new_field();
                    sec.fields.push(f.clone());
                    new = Some(f);
                }
            });
            if let (Some(f), Some(model)) = (new, st.borrow().section_models.get(s_idx)) {
                model.push(to_detail(&f, false));
            }
        });
        on!(on_remove_field, |win, st, section: i32, field: i32| {
            let (s_idx, f_idx) = (section as usize, field as usize);
            let mut removed = false;
            edit_draft(&win, st, |item| {
                if let Some(sec) = item.sections.get_mut(s_idx)
                    && f_idx < sec.fields.len()
                {
                    sec.fields.remove(f_idx);
                    removed = true;
                }
            });
            if removed && let Some(model) = st.borrow().section_models.get(s_idx) {
                model.remove(f_idx);
            }
        });
        on!(on_delete_item, |win, st| {
            let message = {
                let mut st = st.borrow_mut();
                let Shown::Item { account, id } = st.shown.clone() else {
                    return;
                };
                let items = &mut st.accounts[account].items;
                let Some(pos) = items.iter().position(|i| i.id == id) else {
                    return;
                };
                if items[pos].deleted {
                    items.remove(pos);
                    st.shown = Shown::Nothing;
                    "Deleted permanently"
                } else {
                    items[pos].deleted = true;
                    "Moved to trash"
                }
            };
            refresh_tree(&win, st);
            render(&win, st);
            toast(&win, st, message);
        });
        on!(on_restore_item, |win, st| {
            {
                let mut st = st.borrow_mut();
                let Shown::Item { account, id } = st.shown.clone() else {
                    return;
                };
                if let Some(item) = st.accounts[account].items.iter_mut().find(|i| i.id == id) {
                    item.deleted = false;
                }
            }
            refresh_tree(&win, st);
            render(&win, st);
            toast(&win, st, "Restored");
        });
        on!(on_unlock, |win, st, password: SharedString| {
            let email = {
                let mut st = st.borrow_mut();
                let Shown::Locked(account) = st.shown else {
                    return;
                };
                if password.is_empty() {
                    drop(st);
                    win.set_unlock_error(s("Enter the master password"));
                    return;
                }
                // Prototype: any non-empty password unlocks.
                st.accounts[account].locked = false;
                let id = st.accounts[account].id.clone();
                st.expanded.insert(id.clone());
                st.selected = Some(id.clone());
                st.shown = Shown::Group(id);
                st.accounts[account].email.clone()
            };
            win.set_unlock_error(SharedString::new());
            refresh_tree(&win, st);
            render(&win, st);
            win.invoke_focus_tree();
            toast(&win, st, &format!("Unlocked {email}"));
        });

        on!(on_sync, |win, st| {
            win.set_sync_text(s("Synced just now"));
            let count = st.borrow().accounts.iter().filter(|a| !a.locked).count();
            toast(&win, st, &format!("Synced {count} unlocked accounts"));
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
        on!(on_not_yet, |win, st, what: SharedString| {
            let milestone = if what.as_str() == "Settings" {
                "M3"
            } else {
                "M4"
            };
            toast(&win, st, &format!("{what} is planned for {milestone}"));
        });
    }
}

fn toast(win: &AppWindow, st: &Shared, text: &str) {
    let timer = st.borrow().toast_timer.clone();
    win.set_toast(text.into());
    let weak: Weak<AppWindow> = win.as_weak();
    timer.start(
        TimerMode::SingleShot,
        Duration::from_millis(2200),
        move || {
            if let Some(w) = weak.upgrade() {
                w.set_toast(SharedString::new());
            }
        },
    );
}

fn refresh_tree(win: &AppWindow, st: &Shared) {
    let mut st = st.borrow_mut();
    let built = tree::build(&st.accounts, st.group_by, &st.expanded, &st.filter);
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
            tint: color(st.accounts[r.account].tint),
            initials: s(&st.accounts[r.account].initials),
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
            _ => Shown::Group(row.key.clone()),
        };
    }
    win.set_unlock_error(SharedString::new());
    win.set_selected_key(key.into());
    let index = st.borrow().selected_index().map(|i| i as i32).unwrap_or(-1);
    win.set_selected_index(index);
    render(win, st);
}

fn render(win: &AppWindow, st: &Shared) {
    let shown = st.borrow().shown.clone();
    let editing = st.borrow().editing_shown();
    win.set_editing(editing);
    win.set_leave_pending(st.borrow().pending.is_some());
    win.set_dirty(st.borrow().draft.as_ref().is_some_and(Draft::dirty));
    match shown {
        Shown::Nothing => win.set_mode(PaneMode::Empty),
        Shown::Locked(account) => {
            let st = st.borrow();
            let a = &st.accounts[account];
            win.set_account(AccountBadge {
                email: s(&a.email),
                server: s(&a.server),
                tint: color(a.tint),
                initials: s(&a.initials),
            });
            win.set_mode(PaneMode::Locked);
        }
        Shown::Group(key) => {
            let st = st.borrow();
            let Some(row) = st.row(&key) else {
                win.set_mode(PaneMode::Empty);
                return;
            };
            let (title, path) = if row.kind == RowKind::Account {
                (row.label.clone(), row.detail.clone())
            } else {
                let parent = row
                    .path
                    .rsplit_once(" › ")
                    .map(|(p, _)| p.to_string())
                    .unwrap_or_default();
                (
                    row.label.clone(),
                    if parent.is_empty() {
                        row.path.clone()
                    } else {
                        parent
                    },
                )
            };
            win.set_group(GroupSummary {
                title: title.into(),
                icon: if row.kind == RowKind::Account {
                    RowIcon::MyVault
                } else {
                    row.icon
                },
                path: path.into(),
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
            for section in &item.sections {
                let fields: Vec<DetailField> = if editing {
                    section.fields.iter().map(|f| to_detail(f, false)).collect()
                } else {
                    section
                        .fields
                        .iter()
                        .filter(|f| !f.value.is_empty())
                        .map(|f| to_detail(f, true))
                        .collect()
                };
                if !editing && fields.is_empty() {
                    continue;
                }
                let model = Rc::new(VecModel::from(fields));
                sections.push(DetailSection {
                    title: s(&section.title),
                    fields: ModelRc::from(model.clone()),
                    add_label: section.add.map(|a| s(a.label())).unwrap_or_default(),
                });
                models.push(model);
            }
            if !editing {
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
                models.push(model);
            }
            stm.section_models = models;
            let options = stm.folder_options(account);
            let folder_index = options
                .iter()
                .position(|(id, _)| *id == item.folder)
                .unwrap_or(0);
            let names: Vec<SharedString> = options.iter().map(|(_, name)| s(name)).collect();
            drop(stm);
            win.set_sections(ModelRc::new(VecModel::from(sections)));
            win.set_folders(ModelRc::new(VecModel::from(names)));
            win.set_folder_index(folder_index as i32);
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
    });
}

fn refresh_codes(st: &Shared) {
    let st = st.borrow();
    if st.editing_shown() {
        return;
    }
    let Shown::Item { account, id } = &st.shown else {
        return;
    };
    let Some(item) = st.item(*account, id) else {
        return;
    };
    let visible: Vec<_> = item
        .sections
        .iter()
        .map(|s| {
            s.fields
                .iter()
                .filter(|f| !f.value.is_empty())
                .collect::<Vec<_>>()
        })
        .filter(|f| !f.is_empty())
        .collect();
    for (model, fields) in st.section_models.iter().zip(visible) {
        for (row, field) in fields.into_iter().enumerate() {
            if field.kind == FieldKind::Totp {
                model.set_row_data(row, to_detail(field, true));
            }
        }
    }
}

fn begin_edit(win: &AppWindow, st: &Shared) {
    {
        let mut st = st.borrow_mut();
        if st.draft.is_some() {
            return;
        }
        let Shown::Item { account, id } = st.shown.clone() else {
            return;
        };
        let Some(item) = st.item(account, &id).cloned() else {
            return;
        };
        if item.deleted {
            return;
        }
        st.draft = Some(Draft {
            account,
            original: item.clone(),
            item,
            is_new: false,
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

/// Saves the draft. Returns a message for the toast.
fn save(win: &AppWindow, st: &Shared) -> Option<String> {
    let message = {
        let mut s = st.borrow_mut();
        let draft = s.draft.as_ref()?;
        if !draft.dirty() {
            s.draft = None;
            None
        } else if draft.item.name.trim().is_empty() {
            return Some("Give the item a name first".into());
        } else {
            let mut draft = s.draft.take()?;
            draft.item.revised = "Just now".into();
            let items = &mut s.accounts[draft.account].items;
            match items.iter_mut().find(|i| i.id == draft.item.id) {
                Some(existing) => *existing = draft.item.clone(),
                None => items.push(draft.item.clone()),
            }
            s.shown = Shown::Item {
                account: draft.account,
                id: draft.item.id.clone(),
            };
            Some(if draft.is_new { "Created" } else { "Saved" }.to_string())
        }
    };
    refresh_tree(win, st);
    reselect_shown(win, st);
    render(win, st);
    message
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
        for a in &mut s.accounts {
            a.locked = true;
        }
        s.selected = s.accounts.first().map(|a| a.id.clone());
        s.shown = if s.accounts.is_empty() {
            Shown::Nothing
        } else {
            Shown::Locked(0)
        };
    }
    refresh_tree(win, st);
    render(win, st);
}

/// Starts a new login in the selected account and folder. Returns false when
/// no account is unlocked.
fn new_item(win: &AppWindow, st: &Shared) -> bool {
    {
        let mut s = st.borrow_mut();
        let selected = s.selected.as_deref().and_then(|k| s.row(k)).cloned();
        let account = selected
            .as_ref()
            .map(|r| r.account)
            .filter(|a| !s.accounts[*a].locked)
            .or_else(|| s.accounts.iter().position(|a| !a.locked));
        let Some(account) = account else { return false };
        let folder = selected
            .filter(|r| r.account == account)
            .and_then(|r| r.folder);
        let id = format!("new-{}", s.next_id);
        s.next_id += 1;
        let item = Item::blank(id.clone(), ItemType::Login, folder);
        s.draft = Some(Draft {
            account,
            original: item.clone(),
            item,
            is_new: true,
        });
        s.shown = Shown::Item { account, id };
    }
    render(win, st);
    true
}

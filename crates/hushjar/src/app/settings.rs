//! The settings pane: app preferences and per-account unlock options.

use super::*;
use crate::prefs::{self, LockAction, ThemeChoice};
use crate::{AccountSecurity, SettingsData};

pub(super) fn show_settings(win: &AppWindow, st: &Shared) {
    if !leave_to(win, st, Pending::Settings) {
        return;
    }
    {
        let mut state = st.borrow_mut();
        state.shown = Shown::Settings;
        state.selected = None;
    }
    win.set_selected_key(SharedString::new());
    win.set_selected_index(-1);
    render(win, st);
}

/// Fills the settings pane from the current preferences and accounts.
pub(super) fn render_settings(win: &AppWindow, st: &Shared) {
    let state = st.borrow();
    let data = win.global::<SettingsData>();
    // Options first, so the boxes can show the chosen entry.
    let options = |list: &[(&str, Option<u64>)]| -> ModelRc<SharedString> {
        ModelRc::new(VecModel::from(
            list.iter().map(|(label, _)| s(label)).collect::<Vec<_>>(),
        ))
    };
    data.set_lock_after_options(options(&prefs::LOCK_AFTER));
    data.set_clear_after_options(options(&prefs::CLEAR_AFTER));
    let p = &state.prefs;
    data.set_theme(match p.theme {
        ThemeChoice::System => 0,
        ThemeChoice::Light => 1,
        ThemeChoice::Dark => 2,
    });
    data.set_lock_after(p.lock_after as i32);
    data.set_lock_on_screen_lock(p.lock_on_screen_lock);
    data.set_lock_on_sleep(p.lock_on_sleep);
    data.set_lock_action(i32::from(p.lock_action == LockAction::LogOut));
    data.set_clear_after(p.clear_after as i32);
    data.set_ssh_default(i32::from(p.ssh_default == AskMode::EveryTime));
    data.set_tray(p.tray);
    data.set_close_to_tray(p.close_to_tray);
    data.set_start_in_tray(p.start_in_tray);
    data.set_start_on_login(state.desktop.start_on_login());
    data.set_desktop_available(state.desktop.available());
    data.set_system_auth_available(state.desktop.system_auth_available());
    data.set_system_auth_note(state.desktop.system_auth_note().into());
    data.set_agent_status(
        match &state.agent {
            Ok(agent) => format!(
                "Listening on {} and offering {} {}.",
                agent.socket_path().display(),
                state.bridge.key_count(),
                if state.bridge.key_count() == 1 {
                    "key"
                } else {
                    "keys"
                }
            ),
            Err(e) => format!("The SSH agent is not running: {e}"),
        }
        .into(),
    );
    data.set_policy_note(policy_note(&state).into());
    data.set_version(env!("CARGO_PKG_VERSION").into());
    let accounts: Vec<AccountSecurity> = state
        .accounts
        .iter()
        .map(|a| AccountSecurity {
            email: s(&a.profile.email),
            tint: color(a.view.tint),
            initials: s(&a.view.initials),
            unlocked: a.vault.is_some(),
            pin: a.unlock.pin,
            pin_in_memory: a.unlock.pin_in_memory,
            system_auth: a.unlock.system_auth,
        })
        .collect();
    data.set_accounts(ModelRc::new(VecModel::from(accounts)));
}

/// Explains limits that organisation policies put on the timeout.
fn policy_note(state: &State) -> String {
    match state.policy_idle_limit() {
        Some(limit) => format!(
            "An organisation policy locks accounts after at most {} minutes.",
            limit.as_secs() / 60
        ),
        None => String::new(),
    }
}

/// Reads the pane back into the preferences, saves and applies them.
fn settings_changed(win: &AppWindow, st: &Shared) {
    let data = win.global::<SettingsData>();
    let start_on_login = data.get_start_on_login();
    {
        let mut state = st.borrow_mut();
        let p = &mut state.prefs;
        p.theme = match data.get_theme() {
            1 => ThemeChoice::Light,
            2 => ThemeChoice::Dark,
            _ => ThemeChoice::System,
        };
        p.lock_after = (data.get_lock_after().max(0) as usize).min(prefs::LOCK_AFTER.len() - 1);
        p.lock_on_screen_lock = data.get_lock_on_screen_lock();
        p.lock_on_sleep = data.get_lock_on_sleep();
        p.lock_action = if data.get_lock_action() == 1 {
            LockAction::LogOut
        } else {
            LockAction::Lock
        };
        p.clear_after = (data.get_clear_after().max(0) as usize).min(prefs::CLEAR_AFTER.len() - 1);
        p.ssh_default = if data.get_ssh_default() == 1 {
            AskMode::EveryTime
        } else {
            AskMode::FirstTime
        };
        p.tray = data.get_tray();
        p.close_to_tray = p.tray && data.get_close_to_tray();
        p.start_in_tray = p.tray && data.get_start_in_tray();
        let mut settings = state.store.read_settings();
        state.prefs.store_into(&mut settings);
        let _ = state.store.write_settings(&settings);
    }
    let autostart = st.borrow_mut().desktop.set_start_on_login(start_on_login);
    if let Err(message) = autostart {
        toast(win, st, &message);
    }
    apply_prefs(win, st);
    update_agent_keys(win, st);
    render_settings(win, st);
}

/// Puts the preferences into effect.
pub(super) fn apply_prefs(win: &AppWindow, st: &Shared) {
    let state = st.borrow();
    let scheme = match state.prefs.theme {
        ThemeChoice::System => state.system_scheme,
        ThemeChoice::Light => slint::language::ColorScheme::Light,
        ThemeChoice::Dark => slint::language::ColorScheme::Dark,
    };
    win.global::<crate::Palette>().set_color_scheme(scheme);
    state.clipboard.borrow_mut().clear_after = state.prefs.clear_delay();
    let tray = state.prefs.tray;
    drop(state);
    st.borrow_mut().desktop.show_tray(tray);
}

pub(super) fn wire_settings(w: &AppWindow, state: &Shared) {
    let data = w.global::<SettingsData>();
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
    on!(on_changed, |win, st| {
        settings_changed(&win, st);
    });
    on!(on_copy_agent_line, |win, st| {
        let path = {
            let state = st.borrow();
            state
                .agent
                .as_ref()
                .map(|a| a.socket_path().display().to_string())
                .map_err(|e| e.clone())
        };
        match path {
            Ok(path) => copy_plain(&win, st, &format!("export SSH_AUTH_SOCK={path}")),
            Err(e) => toast(&win, st, &format!("The SSH agent is not running: {e}")),
        }
    });
    on!(on_forget_approvals, |win, st| {
        st.borrow().bridge.forget_approvals();
        toast(&win, st, "Every key asks again before its next use");
    });
    on!(on_set_pin, |win, st, index: i32, pin: SharedString| {
        set_pin(&win, st, index as usize, &pin);
    });
    on!(on_remove_pin, |win, st, index: i32| {
        remove_pin(&win, st, index as usize);
    });
    on!(on_system_auth, |win, st, index: i32, on: bool| {
        set_system_auth(&win, st, index as usize, on);
        render_settings(&win, st);
    });
}

fn set_system_auth(win: &AppWindow, st: &Shared, _account: usize, _on: bool) {
    toast(win, st, "System authentication is not connected yet");
}

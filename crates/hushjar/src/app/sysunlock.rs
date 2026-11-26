//! Unlocking with system authentication (polkit on Linux: the computer's
//! password or fingerprint). While Hushjar runs, the user key of each
//! account that has it switched on is kept in memory and released only after
//! the system confirms the user. After a restart, or a log out, the master
//! password is needed once, as in Bitwarden's "require password on start".

use std::collections::HashSet;

use super::*;
use crate::UnlockData;
use crate::desktop::sysauth::{self, KeyHolder, UnlockError};

/// Accounts with system authentication switched on, from settings.json.
pub(super) fn load_enabled(store: &Store) -> HashSet<String> {
    store
        .read_settings()
        .get("system_auth")
        .and_then(|v| v.as_array())
        .map(|ids| {
            ids.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default()
}

fn save_enabled(st: &Shared) {
    let state = st.borrow();
    let mut settings = state.store.read_settings();
    if !settings.is_object() {
        settings = serde_json::json!({});
    }
    let mut ids: Vec<&String> = state.system_auth.iter().collect();
    ids.sort();
    settings["system_auth"] = serde_json::json!(ids);
    let _ = state.store.write_settings(&settings);
}

/// Switches system authentication on or off for an account. Turning it on
/// needs the account unlocked, so its key can be kept.
pub(super) fn set_system_auth(win: &AppWindow, st: &Shared, account: usize, on: bool) {
    let Some((id, unlocked)) = st
        .borrow()
        .accounts
        .get(account)
        .map(|a| (a.profile.id.clone(), a.vault.is_some()))
    else {
        return;
    };
    if on && !unlocked {
        toast(win, st, "Unlock the account first");
        return;
    }
    {
        let mut state = st.borrow_mut();
        if on {
            state.system_auth.insert(id.clone());
            let _ = state.accounts[account]
                .worker
                .tx
                .send(Command::ExportUserKey);
        } else {
            state.system_auth.remove(&id);
            state.key_holder.forget(&id);
        }
        state.accounts[account].unlock.system_auth = on;
    }
    save_enabled(st);
}

/// After an unlock with the master password (or PIN), keep the key if the
/// account uses system authentication and none is kept yet.
pub(super) fn after_unlock(st: &Shared, account: usize) {
    let state = st.borrow();
    let Some(a) = state.accounts.get(account) else {
        return;
    };
    if state.system_auth.contains(&a.profile.id) && !state.key_holder.has(&a.profile.id) {
        let _ = a.worker.tx.send(Command::ExportUserKey);
    }
}

/// The worker handed over the user key: keep it if still wanted.
pub(super) fn key_arrived(st: &Shared, account: usize, key: Zeroizing<Vec<u8>>) {
    let state = st.borrow();
    let Some(a) = state.accounts.get(account) else {
        return;
    };
    if state.system_auth.contains(&a.profile.id) {
        state.key_holder.keep(&a.profile.id, key);
    }
}

/// Forgets the kept key, for log out and removal.
pub(super) fn forget(st: &Shared, account_id: &str) {
    st.borrow().key_holder.forget(account_id);
}

/// Whether the locked pane can offer system authentication for `account`.
pub(super) fn offered(state: &State, account: usize) -> bool {
    state.accounts.get(account).is_some_and(|a| {
        state.system_auth.contains(&a.profile.id)
            && state.key_holder.has(&a.profile.id)
            && !a.unlock.logged_out
    }) && state.desktop.system_auth_available()
}

pub(super) fn render(win: &AppWindow, st: &Shared, account: usize) {
    win.global::<UnlockData>()
        .set_system_auth_available(offered(&st.borrow(), account));
}

/// Asks the system to confirm the user on a background thread (the dialog
/// blocks), then unlocks with the kept key.
fn unlock_with_system(win: &AppWindow, st: &Shared) {
    let Shown::Locked(account) = st.borrow().shown.clone() else {
        return;
    };
    let (id, holder) = {
        let state = st.borrow();
        (
            state.accounts[account].profile.id.clone(),
            state.key_holder.clone(),
        )
    };
    win.set_unlock_error(SharedString::new());
    win.set_busy(true);
    std::thread::spawn(move || {
        let result = sysauth::system_authority()
            .map_err(UnlockError::from)
            .and_then(|authority| holder.unlock(&id, &authority, "Unlock Hushjar"));
        let _ = slint::invoke_from_event_loop(move || {
            CONTEXT.with(|c| {
                if let Some((weak, st)) = &*c.borrow()
                    && let Some(win) = weak.upgrade()
                {
                    finish(&win, st, &id, result);
                }
            });
        });
    });
}

fn finish(win: &AppWindow, st: &Shared, id: &str, result: Result<Zeroizing<Vec<u8>>, UnlockError>) {
    let Some(account) = st.borrow().account_index(id) else {
        return;
    };
    match result {
        Ok(key) => {
            let mut state = st.borrow_mut();
            state.accounts[account].busy = true;
            let _ = state.accounts[account]
                .worker
                .tx
                .send(Command::UnlockWithUserKey(key));
        }
        Err(error) => {
            win.set_busy(false);
            let message = match error {
                UnlockError::Denied => "System authentication was cancelled".to_string(),
                UnlockError::NoKey => {
                    "Unlock with your master password once after starting Hushjar".to_string()
                }
                UnlockError::Failed(e) => format!("System authentication failed: {e}"),
            };
            win.set_unlock_error(message.into());
        }
    }
}

pub(super) fn wire(w: &AppWindow, state: &Shared) {
    let weak = w.as_weak();
    let state = state.clone();
    w.global::<UnlockData>().on_unlock_with_system(move || {
        let Some(win) = weak.upgrade() else { return };
        state.borrow_mut().last_activity = Instant::now();
        unlock_with_system(&win, &state);
    });
}

/// The shared holder, created once for the app.
pub(super) fn new_holder() -> Arc<KeyHolder> {
    Arc::new(KeyHolder::new())
}

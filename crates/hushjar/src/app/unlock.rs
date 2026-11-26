//! Unlocking with a PIN: the locked pane's PIN form, and setting or
//! removing a PIN from the settings pane. The worker does the key
//! derivation and keeps a memory-only PIN.

use super::*;
use crate::{SettingsData, UnlockData};

/// The shortest PIN the settings pane accepts.
const MIN_PIN_CHARS: usize = 4;

/// Fills the locked pane's PIN options for `account`. The switch back to
/// the master password resets when another account is shown.
pub(super) fn render_unlock(win: &AppWindow, st: &Shared, account: usize) {
    let mut state = st.borrow_mut();
    let Some(a) = state.accounts.get(account) else {
        return;
    };
    let (id, pin) = (a.profile.id.clone(), a.unlock.pin);
    let data = win.global::<UnlockData>();
    data.set_pin_available(pin);
    if state.access.locked_shown.as_deref() != Some(id.as_str()) || !pin {
        data.set_use_password(false);
        state.access.locked_shown = Some(id);
    }
}

fn unlock_with_pin(win: &AppWindow, st: &Shared, pin: &str) {
    let Shown::Locked(account) = st.borrow().shown.clone() else {
        return;
    };
    if pin.is_empty() {
        win.set_unlock_error(s("Enter your PIN"));
        return;
    }
    win.set_unlock_error(SharedString::new());
    win.set_busy(true);
    let mut state = st.borrow_mut();
    state.accounts[account].busy = true;
    let _ = state.accounts[account]
        .worker
        .tx
        .send(Command::UnlockWithPin {
            pin: Zeroizing::new(pin.to_string()),
        });
}

/// Why a PIN cannot be set, if it cannot.
fn pin_problem(pin: &str, unlocked: bool) -> Option<&'static str> {
    if !unlocked {
        Some("Unlock the account to set a PIN")
    } else if pin.chars().count() < MIN_PIN_CHARS {
        Some("Use a PIN of 4 characters or more")
    } else {
        None
    }
}

/// Sets a PIN from the settings pane. It is stored with the account unless
/// "Ask for the master password after a restart" is on.
pub(super) fn set_pin(win: &AppWindow, st: &Shared, account: usize, pin: &str) {
    let persist = !win.global::<SettingsData>().get_pin_ask_after_restart();
    let state = st.borrow();
    let Some(a) = state.accounts.get(account) else {
        return;
    };
    if let Some(problem) = pin_problem(pin, a.vault.is_some()) {
        drop(state);
        return toast(win, st, problem);
    }
    let _ = a.worker.tx.send(Command::SetPin {
        pin: Zeroizing::new(pin.to_string()),
        persist,
    });
}

pub(super) fn remove_pin(_win: &AppWindow, st: &Shared, account: usize) {
    if let Some(a) = st.borrow().accounts.get(account) {
        let _ = a.worker.tx.send(Command::RemovePin);
    }
}

/// The worker reports whether PIN unlock is set up.
pub(super) fn pin_state_event(
    win: &AppWindow,
    st: &Shared,
    index: usize,
    stored: bool,
    held: bool,
) {
    let (before, shown) = {
        let mut state = st.borrow_mut();
        let unlock = &mut state.accounts[index].unlock;
        let before = unlock.pin;
        unlock.pin = stored || held;
        unlock.pin_in_memory = held && !stored;
        (before, state.shown.clone())
    };
    match shown {
        Shown::Settings => {
            render_settings(win, st);
            match (before, stored || held) {
                (false, true) => toast(win, st, "PIN set"),
                (true, false) => toast(win, st, "PIN removed"),
                _ => {}
            }
        }
        Shown::Locked(i) if i == index => render_unlock(win, st, index),
        _ => {}
    }
}

pub(super) fn wire_unlock(w: &AppWindow, state: &Shared) {
    let weak = w.as_weak();
    let st = state.clone();
    w.global::<UnlockData>().on_unlock_with_pin(move |pin| {
        let Some(win) = weak.upgrade() else { return };
        st.borrow_mut().last_activity = Instant::now();
        unlock_with_pin(&win, &st, &pin);
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pins_need_an_unlocked_account_and_four_characters() {
        assert!(pin_problem("1234", false).is_some());
        assert!(pin_problem("123", true).is_some());
        assert_eq!(pin_problem("1234", true), None);
        // Characters, not bytes.
        assert!(pin_problem("æø", true).is_some());
    }
}

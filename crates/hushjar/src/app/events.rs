//! Reacting to events from the account workers.

use super::*;

pub(super) fn handle_account_event(win: &AppWindow, st: &Shared, id: &str, event: Event) {
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

pub(super) fn handle_sign_in_event(win: &AppWindow, st: &Shared, event: Event) {
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
                    unlock: UnlockOptions::default(),
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

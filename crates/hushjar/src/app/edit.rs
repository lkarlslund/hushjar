//! Editing, saving and creating items.

use super::*;

pub(super) fn begin_edit(win: &AppWindow, st: &Shared) {
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

pub(super) fn edit_draft(win: &AppWindow, st: &Shared, change: impl FnOnce(&mut Item)) {
    let dirty = {
        let mut st = st.borrow_mut();
        let Some(d) = st.draft.as_mut() else { return };
        change(&mut d.item);
        d.dirty()
    };
    win.set_dirty(dirty);
}

/// Changes one shown field while editing and copies the edit into the draft.
pub(super) fn edit_shown_field(
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
pub(super) fn sync_draft_sections(win: &AppWindow, st: &Shared) {
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

pub(super) fn save(win: &AppWindow, st: &Shared) {
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
pub(super) fn quick_save(win: &AppWindow, st: &Shared, change: impl FnOnce(&mut core::Item)) {
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
pub(super) fn reselect_shown(win: &AppWindow, st: &Shared) {
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

pub(super) fn cancel(win: &AppWindow, st: &Shared) {
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

pub(super) fn run_pending(win: &AppWindow, st: &Shared) {
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
        Some(Pending::Settings) => show_settings(win, st),
        Some(Pending::Generator) => show_generator(win, st),
        Some(Pending::Sends) => show_sends(win, st),
        None => {}
    }
}

pub(super) fn lock_all(win: &AppWindow, st: &Shared) {
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
        s.generator.forget_history();
    }
    forget_sends(win, st);
    win.set_leave_pending(false);
}

/// Starts a new login in the selected account, folder or collection.
/// Returns false when no account is unlocked.
pub(super) fn new_item(win: &AppWindow, st: &Shared) -> bool {
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

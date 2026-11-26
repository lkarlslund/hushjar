//! Connects the window's callbacks to the app.

use super::*;

pub(super) fn wire(w: &AppWindow, state: &Shared) {
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
        let password = match st.borrow().generator.secret() {
            Ok(p) => p,
            Err(message) => {
                toast(
                    &win,
                    st,
                    &format!("{message} (see the generator's options)"),
                );
                return;
            }
        };
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
        st.borrow_mut().generator.remember_secret(&password);
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
        sign_in_code(&win, st, provider, &code, remember);
    });
    on!(on_sign_in_email, |win, st, provider: i32| {
        let _ = provider;
        send_email_code(st);
    });
    on!(on_sign_in_cancel, |win, st| {
        cancel_sign_in(&win, st);
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
    on!(on_open_generator, |win, st| {
        show_generator(&win, st);
    });
    on!(on_open_settings, |win, st| {
        show_settings(&win, st);
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

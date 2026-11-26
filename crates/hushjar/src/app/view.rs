//! Showing the tree and the right pane.

use super::*;

pub(super) fn sync_account(win: &AppWindow, st: &Shared, account: usize) {
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

pub(super) fn update_sync_text(win: &AppWindow, st: &Shared) {
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

pub(super) fn refresh_tree(win: &AppWindow, st: &Shared) {
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

pub(super) fn toggle(win: &AppWindow, st: &Shared, key: &str) {
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

pub(super) fn activate(win: &AppWindow, st: &Shared, key: &str) {
    let row = st.borrow().row(key).cloned();
    let Some(row) = row else { return };
    if row.locked {
        select(win, st, key);
        win.set_unlock_focus_request(win.get_unlock_focus_request() + 1);
    } else if row.expandable {
        toggle(win, st, key);
    }
}

pub(super) fn select(win: &AppWindow, st: &Shared, key: &str) {
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

pub(super) fn account_summary(a: &AccountState) -> AccountSummary {
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

pub(super) fn render(win: &AppWindow, st: &Shared) {
    let shown = st.borrow().shown.clone();
    let editing = st.borrow().editing_shown();
    render_extras(win, st);
    win.set_editing(editing);
    win.set_leave_pending(st.borrow().pending.is_some());
    win.set_dirty(st.borrow().draft.as_ref().is_some_and(Draft::dirty));
    win.set_busy(st.borrow().draft.as_ref().is_some_and(|d| d.saving) || matches!(shown, Shown::Locked(i) if st.borrow().accounts.get(i).is_some_and(|a| a.busy)));
    if shown != Shown::Transfer && st.borrow().transfer.is_active() {
        forget_transfer(win, st);
    }
    match shown {
        Shown::Nothing => win.set_mode(PaneMode::Empty),
        Shown::Transfer => {
            render_transfer(win, st);
            win.set_mode(PaneMode::Transfer);
        }
        Shown::Generator => {
            render_generator(win, st);
            win.set_mode(PaneMode::Generator);
        }
        Shown::Settings => {
            render_settings(win, st);
            win.set_mode(PaneMode::Settings);
        }
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
            let locked = stm.reprompt_locked(account, &id);
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
                        .map(|f| shown_detail(f, !editing, locked))
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

pub(super) fn render_header(win: &AppWindow, st: &Shared) {
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
pub(super) fn refresh_codes(st: &Shared) {
    let st = st.borrow();
    if st.editing_shown() {
        return;
    }
    if let Shown::Item { account, id } = &st.shown
        && st.reprompt_locked(*account, id)
    {
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

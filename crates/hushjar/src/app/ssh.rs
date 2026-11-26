//! The SSH agent's keys, per-key settings and approval prompts.

use super::*;

pub(super) fn ssh_key_id(account: &AccountState, item: &str) -> String {
    format!("{}/{}", account.profile.id, item)
}

pub(super) fn load_ssh_settings(store: &Store) -> HashMap<String, (bool, AskMode)> {
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

pub(super) fn save_ssh_settings(st: &Shared) {
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
pub(super) fn update_agent_keys(win: &AppWindow, st: &Shared) {
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
                .unwrap_or((true, state.prefs.ssh_default));
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

pub(super) fn render_ssh_settings(win: &AppWindow, st: &Shared) {
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
        .unwrap_or((true, state.prefs.ssh_default));
    win.set_ssh_enabled(enabled);
    win.set_ssh_mode(if mode == AskMode::EveryTime { 1 } else { 0 });
}

pub(super) fn change_ssh_setting(
    win: &AppWindow,
    st: &Shared,
    change: impl FnOnce(&mut (bool, AskMode)),
) {
    {
        let mut state = st.borrow_mut();
        let Shown::Item { account, id } = state.shown.clone() else {
            return;
        };
        let key = ssh_key_id(&state.accounts[account], &id);
        let default = state.prefs.ssh_default;
        let setting = state.ssh_settings.entry(key).or_insert((true, default));
        change(setting);
    }
    save_ssh_settings(st);
    update_agent_keys(win, st);
    render_ssh_settings(win, st);
}

pub(super) fn show_prompt(win: &AppWindow, st: &Shared, prompt: Prompt) {
    st.borrow_mut().prompts.push_back(prompt);
    render_prompt(win, st);
    use slint::winit_030::WinitWindowAccessor;
    win.window().with_winit_window(|w| {
        w.request_user_attention(Some(
            slint::winit_030::winit::window::UserAttentionType::Critical,
        ));
    });
}

pub(super) fn render_prompt(win: &AppWindow, st: &Shared) {
    let text = st
        .borrow()
        .prompts
        .front()
        .map(|p| p.text.clone())
        .unwrap_or_default();
    win.set_ssh_prompt(text.into());
}

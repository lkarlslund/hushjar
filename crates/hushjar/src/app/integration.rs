//! The app's view of desktop services: the tray, starting on login, screen
//! lock and sleep, and system authentication. Each one is optional: when the
//! desktop does not offer it, the matching settings are shown as unavailable
//! and the app carries on.

use super::*;
use crate::desktop::{autostart, notify, session_watch, sysauth, tray};

/// Desktop services the app uses, as far as this system has them.
pub struct Integration {
    tray: Option<tray::Tray>,
    _watch: Option<session_watch::SessionWatch>,
    window_visible: bool,
    notifier: Option<notify::Notifier>,
    /// The notification standing for the first SSH prompt, and its text.
    prompt_note: Option<(notify::NotificationId, String)>,
}

/// Runs `f` on the UI thread with the window and state, from any thread.
fn on_ui(f: impl FnOnce(&AppWindow, &Shared) + Send + 'static) {
    let _ = slint::invoke_from_event_loop(move || {
        CONTEXT.with(|c| {
            if let Some((weak, st)) = &*c.borrow()
                && let Some(win) = weak.upgrade()
            {
                f(&win, st);
            }
        });
    });
}

impl Integration {
    /// Starts watching for screen lock and sleep. The tray starts later,
    /// from the preferences.
    pub fn new() -> Self {
        let watch = session_watch::SessionWatch::start(|event| {
            on_ui(move |win, st| system_event(win, st, event));
        })
        .ok();
        Self {
            tray: None,
            _watch: watch,
            window_visible: true,
            notifier: None,
            prompt_note: None,
        }
    }

    /// Whether tray and start-up options can be offered at all.
    pub fn available(&self) -> bool {
        cfg!(target_os = "linux") && !crate::desktop::in_flatpak()
    }

    pub fn start_on_login(&self) -> bool {
        autostart::is_enabled()
    }

    pub fn set_start_on_login(&mut self, on: bool) -> Result<(), String> {
        if on == autostart::is_enabled() {
            return Ok(());
        }
        let result = if on {
            autostart::enable()
        } else {
            autostart::disable()
        };
        result.map_err(|e| format!("Could not change starting on login: {e}"))
    }

    /// Shows or removes the tray icon.
    pub fn show_tray(&mut self, on: bool) {
        if !on {
            self.tray = None;
            return;
        }
        if self.tray.as_ref().is_some_and(|t| t.is_running()) {
            return;
        }
        self.tray = tray::Tray::spawn(self.window_visible, |event| {
            on_ui(move |win, st| tray_event(win, st, event));
        })
        .ok();
    }

    /// Whether closing the window can leave Hushjar running in the tray.
    pub fn tray_running(&self) -> bool {
        self.tray.as_ref().is_some_and(|t| t.is_running())
    }

    /// Updates the tray's status line, e.g. "1 of 2 accounts unlocked".
    pub fn set_status(&self, unlocked: usize, total: usize) {
        if let Some(tray) = &self.tray {
            tray.set_status(tray::status_text(unlocked, total));
        }
    }

    pub fn set_needs_attention(&self, on: bool) {
        if let Some(tray) = &self.tray {
            tray.set_needs_attention(on);
        }
    }

    pub fn window_shown(&mut self, visible: bool) {
        self.window_visible = visible;
        if let Some(tray) = &self.tray {
            tray.set_window_visible(visible);
        }
    }

    pub fn is_window_visible(&self) -> bool {
        self.window_visible
    }

    /// Shows `text` as a notification with Allow and Deny, replacing any
    /// earlier one. Returns false when the desktop cannot show actions.
    fn notify_prompt(&mut self, text: &str) -> bool {
        if self.prompt_note.as_ref().is_some_and(|(_, t)| t == text) {
            return true;
        }
        self.close_prompt_note();
        if self.notifier.is_none() {
            self.notifier = notify::Notifier::connect().ok();
        }
        let Some(notifier) = self.notifier.as_ref().filter(|n| n.supports_actions()) else {
            return false;
        };
        let note = notify::Notification::approval("SSH key request", text);
        match notifier.show(&note, |response| {
            on_ui(move |win, st| prompt_note_answered(win, st, response));
        }) {
            Ok(id) => {
                self.prompt_note = Some((id, text.to_string()));
                true
            }
            Err(_) => false,
        }
    }

    fn close_prompt_note(&mut self) {
        if let (Some(notifier), Some((id, _))) = (&self.notifier, self.prompt_note.take()) {
            let _ = notifier.close(id);
        }
    }

    pub fn system_auth_available(&self) -> bool {
        sysauth::available()
    }

    /// Why system authentication is unavailable, for the settings pane.
    pub fn system_auth_note(&self) -> String {
        if cfg!(target_os = "linux") {
            "To unlock with your computer's password or fingerprint, install Hushjar's \
             system authentication rule: scripts/install-desktop.sh prints the command."
                .into()
        } else {
            "System authentication is not available on this system yet.".into()
        }
    }
}

/// Shows or hides the main window and tells the tray.
pub(super) fn set_window_visible(win: &AppWindow, st: &Shared, visible: bool) {
    let result = if visible { win.show() } else { win.hide() };
    if result.is_ok() {
        st.borrow_mut().desktop.window_shown(visible);
    }
}

fn tray_event(win: &AppWindow, st: &Shared, event: tray::TrayEvent) {
    match event {
        tray::TrayEvent::Activate => {
            let visible = st.borrow().desktop.is_window_visible();
            set_window_visible(win, st, !visible);
        }
        tray::TrayEvent::ShowWindow => set_window_visible(win, st, true),
        tray::TrayEvent::HideWindow => set_window_visible(win, st, false),
        tray::TrayEvent::LockAll => {
            lock_all(win, st);
        }
        tray::TrayEvent::Quit => {
            let _ = slint::quit_event_loop();
        }
    }
}

/// Locks accounts when the screen locks or the computer sleeps, if the
/// preferences say so.
fn system_event(win: &AppWindow, st: &Shared, event: session_watch::SystemEvent) {
    use session_watch::SystemEvent::*;
    let lock = {
        let p = &st.borrow().prefs;
        match event {
            ScreenLocked => p.lock_on_screen_lock,
            Sleeping => p.lock_on_sleep,
            ScreenUnlocked | Resumed => false,
        }
    };
    if lock && st.borrow().any_unlocked() {
        time_out_all(win, st);
    }
}

/// Keeps the tray's status line in step with the accounts.
pub(super) fn update_tray_status(st: &Shared) {
    let state = st.borrow();
    let unlocked = state.accounts.iter().filter(|a| a.vault.is_some()).count();
    state.desktop.set_status(unlocked, state.accounts.len());
    state.desktop.set_needs_attention(!state.prompts.is_empty());
}

/// What closing the window does: hide it when the tray keeps Hushjar
/// running, otherwise quit.
pub(super) fn close_requested(st: &Shared) -> slint::CloseRequestResponse {
    let keep = {
        let state = st.borrow();
        state.prefs.close_to_tray && state.desktop.tray_running()
    };
    if keep {
        st.borrow_mut().desktop.window_shown(false);
    } else {
        let _ = slint::quit_event_loop();
    }
    slint::CloseRequestResponse::HideWindow
}

/// Keeps the SSH prompt notification in step with the first waiting
/// prompt: shown while the window is hidden, closed once answered. When
/// notifications cannot carry buttons, the window is shown instead.
pub(super) fn sync_prompt_note(win: &AppWindow, st: &Shared) {
    let front = st.borrow().prompts.front().map(|p| p.text.clone());
    let visible = st.borrow().desktop.is_window_visible();
    match front {
        None => st.borrow_mut().desktop.close_prompt_note(),
        Some(_) if visible => st.borrow_mut().desktop.close_prompt_note(),
        Some(text) => {
            let shown = st.borrow_mut().desktop.notify_prompt(&text);
            if !shown {
                set_window_visible(win, st, true);
            }
        }
    }
}

fn prompt_note_answered(win: &AppWindow, st: &Shared, response: notify::Response) {
    st.borrow_mut().desktop.prompt_note = None;
    let allow = match response {
        notify::Response::Action(action) if action == notify::ALLOW => true,
        notify::Response::Action(action) if action == notify::DENY => false,
        notify::Response::Action(_) => {
            set_window_visible(win, st, true);
            return;
        }
        notify::Response::Closed(_) => false,
    };
    let prompt = st.borrow_mut().prompts.pop_front();
    if let Some(prompt) = prompt {
        prompt.answer(allow);
    }
    render_prompt(win, st);
}

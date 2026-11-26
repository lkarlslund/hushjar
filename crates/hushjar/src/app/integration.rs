//! The app's view of desktop services (tray, start on login, system
//! authentication). Each one is optional: when the desktop does not offer
//! it, the matching settings are shown as unavailable.

/// Desktop services the app uses, as far as this system has them.
#[derive(Default)]
pub struct Integration {}

impl Integration {
    pub fn new() -> Self {
        Self {}
    }

    /// Whether tray and start-up options can be offered at all.
    pub fn available(&self) -> bool {
        false
    }

    pub fn start_on_login(&self) -> bool {
        false
    }

    pub fn set_start_on_login(&mut self, on: bool) -> Result<(), String> {
        if on {
            Err("Starting on login is not available on this system".into())
        } else {
            Ok(())
        }
    }

    pub fn show_tray(&mut self, _on: bool) {}

    pub fn system_auth_available(&self) -> bool {
        false
    }

    /// Why system authentication is unavailable, for the settings pane.
    pub fn system_auth_note(&self) -> String {
        "System authentication is not available on this system.".into()
    }
}

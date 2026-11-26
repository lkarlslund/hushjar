//! App-wide preferences, kept in the store's settings.json next to other
//! settings (such as the SSH key switches).

use std::time::Duration;

use serde_json::{Value, json};

use crate::sshagent::AskMode;

/// "Lock after" choices, in the order the settings pane lists them.
pub const LOCK_AFTER: [(&str, Option<u64>); 7] = [
    ("1 minute", Some(60)),
    ("5 minutes", Some(5 * 60)),
    ("15 minutes", Some(15 * 60)),
    ("30 minutes", Some(30 * 60)),
    ("1 hour", Some(60 * 60)),
    ("4 hours", Some(4 * 60 * 60)),
    ("Only when Hushjar quits", None),
];

/// "Clear copied values after" choices.
pub const CLEAR_AFTER: [(&str, Option<u64>); 7] = [
    ("10 seconds", Some(10)),
    ("20 seconds", Some(20)),
    ("30 seconds", Some(30)),
    ("1 minute", Some(60)),
    ("2 minutes", Some(120)),
    ("5 minutes", Some(300)),
    ("Never", None),
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ThemeChoice {
    System,
    Light,
    Dark,
}

/// What happens to an account when its time runs out.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LockAction {
    Lock,
    /// Forget the session and the offline copy; signing in again is needed.
    LogOut,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Prefs {
    pub theme: ThemeChoice,
    /// Index into [`LOCK_AFTER`].
    pub lock_after: usize,
    pub lock_on_screen_lock: bool,
    pub lock_on_sleep: bool,
    pub lock_action: LockAction,
    /// Index into [`CLEAR_AFTER`].
    pub clear_after: usize,
    /// The approval setting for SSH keys that have none of their own.
    pub ssh_default: AskMode,
    pub tray: bool,
    pub close_to_tray: bool,
    pub start_in_tray: bool,
}

impl Default for Prefs {
    fn default() -> Self {
        Self {
            theme: ThemeChoice::System,
            lock_after: 2,
            lock_on_screen_lock: true,
            lock_on_sleep: true,
            lock_action: LockAction::Lock,
            clear_after: 2,
            ssh_default: AskMode::FirstTime,
            tray: false,
            close_to_tray: false,
            start_in_tray: false,
        }
    }
}

impl Prefs {
    /// Reads the "prefs" object of settings.json; unknown or missing values
    /// fall back to the defaults.
    pub fn from_settings(settings: &Value) -> Self {
        let d = Self::default();
        let Some(p) = settings.get("prefs") else {
            return d;
        };
        let flag =
            |key: &str, default: bool| p.get(key).and_then(Value::as_bool).unwrap_or(default);
        let index = |key: &str, default: usize, len: usize| {
            p.get(key)
                .and_then(Value::as_u64)
                .map(|v| v as usize)
                .filter(|v| *v < len)
                .unwrap_or(default)
        };
        let text = |key: &str| p.get(key).and_then(Value::as_str).unwrap_or_default();
        Self {
            theme: match text("theme") {
                "light" => ThemeChoice::Light,
                "dark" => ThemeChoice::Dark,
                _ => ThemeChoice::System,
            },
            lock_after: index("lock_after", d.lock_after, LOCK_AFTER.len()),
            lock_on_screen_lock: flag("lock_on_screen_lock", d.lock_on_screen_lock),
            lock_on_sleep: flag("lock_on_sleep", d.lock_on_sleep),
            lock_action: if text("lock_action") == "log_out" {
                LockAction::LogOut
            } else {
                LockAction::Lock
            },
            clear_after: index("clear_after", d.clear_after, CLEAR_AFTER.len()),
            ssh_default: AskMode::parse(text("ssh_default")),
            tray: flag("tray", d.tray),
            close_to_tray: flag("close_to_tray", d.close_to_tray),
            start_in_tray: flag("start_in_tray", d.start_in_tray),
        }
    }

    /// Writes these preferences into `settings`, keeping its other keys.
    pub fn store_into(&self, settings: &mut Value) {
        if !settings.is_object() {
            *settings = json!({});
        }
        settings["prefs"] = json!({
            "theme": match self.theme {
                ThemeChoice::System => "system",
                ThemeChoice::Light => "light",
                ThemeChoice::Dark => "dark",
            },
            "lock_after": self.lock_after,
            "lock_on_screen_lock": self.lock_on_screen_lock,
            "lock_on_sleep": self.lock_on_sleep,
            "lock_action": match self.lock_action {
                LockAction::Lock => "lock",
                LockAction::LogOut => "log_out",
            },
            "clear_after": self.clear_after,
            "ssh_default": self.ssh_default.as_str(),
            "tray": self.tray,
            "close_to_tray": self.close_to_tray,
            "start_in_tray": self.start_in_tray,
        });
    }

    /// How long without activity before accounts lock, if ever.
    pub fn idle_limit(&self) -> Option<Duration> {
        LOCK_AFTER[self.lock_after].1.map(Duration::from_secs)
    }

    /// How long copied secrets stay on the clipboard, if they are cleared.
    pub fn clear_delay(&self) -> Option<Duration> {
        CLEAR_AFTER[self.clear_after].1.map(Duration::from_secs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_keeps_other_settings() {
        let mut settings = json!({ "ssh_keys": { "a/b": { "enabled": false } } });
        let prefs = Prefs {
            theme: ThemeChoice::Dark,
            lock_after: 6,
            lock_on_screen_lock: false,
            lock_action: LockAction::LogOut,
            clear_after: 6,
            ssh_default: AskMode::EveryTime,
            tray: true,
            ..Prefs::default()
        };
        prefs.store_into(&mut settings);
        assert_eq!(Prefs::from_settings(&settings), prefs);
        assert_eq!(settings["ssh_keys"]["a/b"]["enabled"], false);
        assert_eq!(prefs.idle_limit(), None);
        assert_eq!(prefs.clear_delay(), None);
    }

    #[test]
    fn bad_values_fall_back_to_defaults() {
        let settings = json!({ "prefs": { "lock_after": 99, "theme": 3, "tray": "yes" } });
        assert_eq!(Prefs::from_settings(&settings), Prefs::default());
        assert_eq!(
            Prefs::default().idle_limit(),
            Some(Duration::from_secs(15 * 60))
        );
    }
}

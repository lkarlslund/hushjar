//! Desktop integration: system tray, start on login, lock and sleep signals,
//! system authentication and notifications.
//!
//! Each feature lives in its own module with a small API. On Linux they talk
//! to desktop services over D-Bus with zbus (on async-io, which runs its own
//! executor thread, so there is no tokio runtime). Every service is optional:
//! when one is missing the call returns an [`Error`] or `None` and the app
//! carries on without it. Other platforms get stubs that return
//! [`Error::Unsupported`] until they have their own implementations.
//!
//! Callbacks passed to these modules run on background threads. The app
//! forwards them to the UI with `slint::invoke_from_event_loop`.

pub mod autostart;
#[allow(dead_code, reason = "a complete API; the app uses part of it so far")]
pub mod notify;
#[allow(dead_code, reason = "a complete API; the app uses part of it so far")]
pub mod session_watch;
#[allow(dead_code, reason = "a complete API; the app uses part of it so far")]
pub mod sysauth;
pub mod tray;

/// Why a desktop integration call failed.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// This platform has no implementation yet.
    #[cfg_attr(
        target_os = "linux",
        allow(dead_code, reason = "used by the other platforms")
    )]
    #[error("not supported on this platform")]
    Unsupported,
    /// The desktop service needed for this is not running or not installed.
    #[cfg_attr(
        not(target_os = "linux"),
        allow(dead_code, reason = "only the Linux implementation uses it")
    )]
    #[error("{0} is not available")]
    Unavailable(String),
    /// A D-Bus call or connection failed.
    #[cfg_attr(
        not(target_os = "linux"),
        allow(dead_code, reason = "only the Linux implementation uses it")
    )]
    #[error("D-Bus: {0}")]
    Dbus(String),
    /// Reading or writing a file failed.
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

#[cfg(target_os = "linux")]
impl From<zbus::Error> for Error {
    fn from(error: zbus::Error) -> Self {
        Error::Dbus(error.to_string())
    }
}

#[cfg(target_os = "linux")]
impl From<zbus::fdo::Error> for Error {
    fn from(error: zbus::fdo::Error) -> Self {
        Error::Dbus(error.to_string())
    }
}

/// Whether Hushjar runs inside a Flatpak sandbox, where some services must
/// be reached through portals instead. Always false off Linux.
pub fn in_flatpak() -> bool {
    cfg!(target_os = "linux") && std::path::Path::new("/.flatpak-info").exists()
}

/// The user ID of this process, read from `/proc` so no libc call is needed.
#[cfg(target_os = "linux")]
fn current_uid() -> Option<u32> {
    use std::os::unix::fs::MetadataExt;
    std::fs::metadata("/proc/self").ok().map(|m| m.uid())
}

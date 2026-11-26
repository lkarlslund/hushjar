//! The Android entry point. The APK's NativeActivity loads this crate as
//! `libhushjar.so` and android-activity calls [`android_main`] on its own
//! thread; from there the app runs as on the desktop, with Slint's Android
//! backend in place of winit. See `scripts/build-android.sh`.
//!
//! Not on Android yet: the SSH agent, tray, notifications and other desktop
//! services (their modules return "not supported"), and file dialogs.

use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use slint::android::AndroidApp;
use slint::android::android_activity::ndk::configuration::UiModeNight;

/// The running activity, kept for reading its configuration later.
static APP: OnceLock<AndroidApp> = OnceLock::new();

/// Called by android-activity once the activity is created.
// Slint's Android backend (through android-activity) looks this function up
// by its unmangled name, which needs the `no_mangle` attribute; that
// attribute counts as unsafe code. The function body itself is safe Rust.
#[allow(unsafe_code)]
#[unsafe(no_mangle)]
fn android_main(app: AndroidApp) {
    let data = app.internal_data_path();
    if let Some(dir) = &data {
        set_panic_report(dir);
    }
    if let Err(error) = start(app, data) {
        report(&format!("Hushjar could not start: {error}"));
    }
}

fn start(app: AndroidApp, data: Option<PathBuf>) -> Result<(), Box<dyn std::error::Error>> {
    let root = data.ok_or("Android gave no folder for app data")?;
    let _ = APP.set(app.clone());
    slint::android::init(app)?;
    crate::run(root)?;
    // The activity is gone (Back on the tree, or the system closed it).
    // Android keeps the process and would call android_main again in it,
    // while the account workers and live-update threads of this run, with
    // their unlocked vaults, would still be alive. Ending the process drops
    // them all, so the next start begins locked and clean.
    std::process::exit(0)
}

/// Whether the system is in dark mode.
pub fn night_mode() -> bool {
    APP.get()
        .is_some_and(|app| app.config().ui_mode_night() == UiModeNight::Yes)
}

/// Where a startup failure or panic is written. Standard error goes nowhere
/// on Android, and logcat needs a native call; a debug build's file can be
/// read with `adb shell run-as <package> cat files/last-error.txt`.
static REPORT: OnceLock<PathBuf> = OnceLock::new();

fn set_panic_report(dir: &Path) {
    let _ = REPORT.set(dir.join("last-error.txt"));
    let default = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        report(&info.to_string());
        default(info);
    }));
}

/// Writes `message` to the report file. Messages never contain secrets:
/// they are startup errors and panic locations.
fn report(message: &str) {
    if let Some(path) = REPORT.get() {
        let _ = std::fs::write(path, message);
    }
}

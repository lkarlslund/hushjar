//! The Hushjar app. It is a library so that the desktop binary (`main.rs`)
//! and the Android shared library (`android.rs`) run the same code; each
//! picks its Slint backend and data folder, then calls [`run`].

slint::include_modules!();

#[cfg(target_os = "android")]
mod android;
mod app;
mod clipboard;
mod desktop;
mod dialogs;
mod exchange;
#[cfg(test)]
mod layout_tests;
#[cfg(test)]
mod mock;
mod model;
mod pacing;
mod platform;
mod prefs;
#[cfg(feature = "snapshot")]
mod snapshot;
mod sshagent;
mod tree;
mod worker;

/// The application ID: the Wayland app ID and X11 window class, matching
/// the desktop entry and icon names in `packaging/linux`.
pub const APP_ID: &str = "io.github.lkarlslund.Hushjar";

/// Opens the account store in `root`, shows the window and runs the event
/// loop until the app quits. The Slint backend must already be selected.
pub fn run(root: std::path::PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    let store = hushjar_core::store::Store::open(root)?;
    let app = app::App::new(store)?;

    match std::env::var("HUSHJAR_COLOR_SCHEME").as_deref() {
        Ok("light") => app
            .window
            .global::<Palette>()
            .set_color_scheme(slint::language::ColorScheme::Light),
        Ok("dark") => app
            .window
            .global::<Palette>()
            .set_color_scheme(slint::language::ColorScheme::Dark),
        _ => {}
    }

    #[cfg(feature = "snapshot")]
    let _snapshots =
        std::env::var_os("HUSHJAR_SNAPSHOT_DIR").map(|dir| snapshot::run(&app.window, dir.into()));

    // Start in the tray only when there is a tray to come back from.
    let hidden = desktop::autostart::started_hidden() && app.starts_in_tray();
    if hidden {
        app.note_hidden();
    } else {
        app.window.show()?;
    }
    slint::run_event_loop_until_quit()?;
    app.forget_opened_files();
    Ok(())
}

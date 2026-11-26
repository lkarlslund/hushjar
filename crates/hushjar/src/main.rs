// A release build on Windows is a GUI program: no console window opens.
#![cfg_attr(all(windows, not(debug_assertions)), windows_subsystem = "windows")]

slint::include_modules!();

mod app;
mod clipboard;
#[cfg(test)]
mod mock;
mod model;
#[cfg(feature = "snapshot")]
mod snapshot;
mod sshagent;
mod tree;
mod worker;

/// The application ID: the Wayland app ID and X11 window class, matching
/// the desktop entry and icon names in `packaging/linux`.
pub const APP_ID: &str = "io.github.lkarlslund.Hushjar";

/// Selects the winit backend and names the window after [`APP_ID`], so
/// desktops can match it to its desktop entry, icon and window rules.
fn select_backend() -> Result<(), slint::PlatformError> {
    slint::BackendSelector::new()
        .backend_name("winit".into())
        .with_winit_window_attributes_hook(|attributes| {
            #[cfg(all(unix, not(target_os = "macos")))]
            let attributes =
                slint::winit_030::winit::platform::wayland::WindowAttributesExtWayland::with_name(
                    attributes, APP_ID, "hushjar",
                );
            attributes
        })
        .select()
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    select_backend()?;
    let root = match std::env::var_os("HUSHJAR_DATA_DIR") {
        Some(dir) => std::path::PathBuf::from(dir),
        None => hushjar_core::store::default_root().ok_or("no home folder to keep data in")?,
    };
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

    app.window.run()?;
    Ok(())
}

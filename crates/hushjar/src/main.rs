// A release build on Windows is a GUI program: no console window opens.
#![cfg_attr(all(windows, not(debug_assertions)), windows_subsystem = "windows")]

//! The desktop entry point. Android starts from `android_main` in the
//! library instead (see `scripts/build-android.sh`).

/// Selects the winit backend and names the window after [`hushjar::APP_ID`],
/// so desktops can match it to its desktop entry, icon and window rules.
#[cfg(not(target_os = "android"))]
fn select_backend() -> Result<(), slint::PlatformError> {
    slint::BackendSelector::new()
        .backend_name("winit".into())
        .with_winit_window_attributes_hook(|attributes| {
            #[cfg(all(unix, not(target_os = "macos")))]
            let attributes =
                slint::winit_030::winit::platform::wayland::WindowAttributesExtWayland::with_name(
                    attributes,
                    hushjar::APP_ID,
                    "hushjar",
                );
            attributes
        })
        .select()
}

#[cfg(not(target_os = "android"))]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    select_backend()?;
    let root = match std::env::var_os("HUSHJAR_DATA_DIR") {
        Some(dir) => std::path::PathBuf::from(dir),
        None => hushjar_core::store::default_root().ok_or("no home folder to keep data in")?,
    };
    hushjar::run(root)
}

/// Android has no command-line program: the app is the shared library that
/// the APK loads.
#[cfg(target_os = "android")]
fn main() {
    eprintln!("On Android, Hushjar runs from its APK; see scripts/build-android.sh");
}

//! Window-system details that differ between the desktop, where Slint runs
//! on winit, and Android, where it runs on a NativeActivity.

use slint::language::ColorScheme;

use crate::AppWindow;

/// The system's light or dark preference.
#[cfg(not(target_os = "android"))]
pub fn system_scheme(win: &AppWindow) -> ColorScheme {
    use slint::ComponentHandle;
    use slint::winit_030::{WinitWindowAccessor, winit::window::Theme};
    let theme = win.window().with_winit_window(|w| w.theme()).flatten();
    match theme {
        Some(Theme::Dark) => ColorScheme::Dark,
        _ => ColorScheme::Light,
    }
}

/// The system's light or dark preference, from the activity's configuration.
#[cfg(target_os = "android")]
pub fn system_scheme(_win: &AppWindow) -> ColorScheme {
    if crate::android::night_mode() {
        ColorScheme::Dark
    } else {
        ColorScheme::Light
    }
}

/// Asks the desktop to draw attention to the window, for a prompt that
/// needs an answer. Android has no equivalent for a foreground app.
pub fn request_attention(win: &AppWindow) {
    #[cfg(not(target_os = "android"))]
    {
        use slint::ComponentHandle;
        use slint::winit_030::WinitWindowAccessor;
        win.window().with_winit_window(|w| {
            w.request_user_attention(Some(
                slint::winit_030::winit::window::UserAttentionType::Critical,
            ));
        });
    }
    #[cfg(target_os = "android")]
    let _ = win;
}

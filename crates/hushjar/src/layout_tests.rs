//! The single-pane layout for narrow windows (`compact` in ui/app.slint),
//! checked headless with Slint's testing backend: no window opens.

use std::cell::Cell;

use i_slint_backend_testing::ElementHandle;
use slint::{ComponentHandle, LogicalSize};

use crate::AppWindow;

thread_local! {
    /// The testing backend can be set once per thread.
    static BACKEND: Cell<bool> = const { Cell::new(false) };
}

/// A window of the given logical width, on the testing backend.
fn window(width: f32) -> AppWindow {
    BACKEND.with(|ready| {
        if !ready.replace(true) {
            i_slint_backend_testing::init_no_event_loop();
        }
    });
    let win = AppWindow::new().expect("create the window");
    win.window().set_size(LogicalSize::new(width, 800.0));
    win
}

/// How many elements carry this accessible label right now.
fn count(win: &AppWindow, label: &str) -> usize {
    ElementHandle::find_by_accessible_label(win, label).count()
}

/// Presses the element with this label, as a screen reader would.
fn press(win: &AppWindow, label: &str) {
    ElementHandle::find_by_accessible_label(win, label)
        .next()
        .unwrap_or_else(|| panic!("no element labelled {label}"))
        .invoke_accessible_default_action();
}

#[test]
fn narrow_windows_are_compact() {
    assert!(window(400.0).get_compact());
    assert!(window(639.0).get_compact());
    assert!(!window(640.0).get_compact());
    assert!(!window(1180.0).get_compact());
}

#[test]
fn compact_top_bar_moves_secondary_buttons_into_a_menu() {
    let narrow = window(400.0);
    assert_eq!(count(&narrow, "More"), 1);
    assert_eq!(count(&narrow, "Settings"), 0);
    assert_eq!(count(&narrow, "Send"), 0);
    assert_eq!(count(&narrow, "Hide sidebar"), 0);

    let wide = window(1180.0);
    assert_eq!(count(&wide, "More"), 0);
    assert_eq!(count(&wide, "Settings"), 1);
    assert_eq!(count(&wide, "Send"), 1);
    assert_eq!(count(&wide, "Hide sidebar"), 1);
}

#[test]
fn compact_shows_details_then_back_returns_to_the_tree() {
    let win = window(400.0);
    assert!(!win.get_details_open());
    assert_eq!(count(&win, "Back"), 0);

    press(&win, "Add account");
    assert!(win.get_details_open());
    assert_eq!(count(&win, "Back"), 1);

    press(&win, "Back");
    assert!(!win.get_details_open());
    assert_eq!(count(&win, "Back"), 0);
}

#[test]
fn wide_window_offers_no_back_button() {
    let win = window(1180.0);
    press(&win, "Add account");
    assert_eq!(count(&win, "Back"), 0);
}

#[test]
fn file_and_agent_features_follow_the_platform() {
    let win = window(1180.0);
    let platform = win.global::<crate::Platform>();
    assert_eq!(count(&win, "SSH agent is not running"), 1);
    platform.set_ssh_agent(false);
    assert_eq!(count(&win, "SSH agent is not running"), 0);
}

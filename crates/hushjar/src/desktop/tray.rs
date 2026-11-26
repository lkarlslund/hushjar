//! The system tray icon and its menu.
//!
//! On Linux this is a StatusNotifierItem, served with `ksni` (already in the
//! build through Slint). KDE Plasma shows these natively; GNOME needs the
//! AppIndicator extension, and without a tray host [`Tray::spawn`] fails and
//! the app should keep its window instead of hiding to the tray.
//!
//! The menu reads:
//!
//! ```text
//! 2 accounts unlocked      (status line, greyed out)
//! ─────────────
//! Hide Hushjar             (or "Show Hushjar" while the window is hidden)
//! Lock all
//! ─────────────
//! Quit
//! ```
//!
//! A left click on the icon sends [`TrayEvent::Activate`]; the app toggles
//! the window.

use super::Error;

/// Something the user did in the tray. Delivered on the tray's thread.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrayEvent {
    /// The icon itself was clicked: show the window, or hide it if shown.
    Activate,
    ShowWindow,
    HideWindow,
    LockAll,
    Quit,
}

/// What the tray shows; the app updates it through [`Tray`]'s setters.
#[derive(Debug, Clone, PartialEq, Eq)]
struct TrayState {
    status: String,
    window_visible: bool,
    needs_attention: bool,
}

/// One menu entry: a label and the event it sends, or `None` for an entry
/// that cannot be chosen. `None` for the whole entry is a separator.
type MenuEntry = Option<(String, Option<TrayEvent>)>;

/// The menu for `state`, as plain data so it can be tested.
fn menu_model(state: &TrayState) -> Vec<MenuEntry> {
    let mut entries = Vec::new();
    if !state.status.is_empty() {
        entries.push(Some((state.status.clone(), None)));
        entries.push(None);
    }
    entries.push(Some(if state.window_visible {
        ("Hide Hushjar".to_owned(), Some(TrayEvent::HideWindow))
    } else {
        ("Show Hushjar".to_owned(), Some(TrayEvent::ShowWindow))
    }));
    entries.push(Some(("Lock all".to_owned(), Some(TrayEvent::LockAll))));
    entries.push(None);
    entries.push(Some(("Quit".to_owned(), Some(TrayEvent::Quit))));
    entries
}

/// The text for the status line, such as "2 accounts unlocked".
pub fn status_text(unlocked: usize, total: usize) -> String {
    match (unlocked, total) {
        (_, 0) => "No accounts".to_owned(),
        (0, _) => "All accounts locked".to_owned(),
        (1, _) => "1 account unlocked".to_owned(),
        (n, _) => format!("{n} accounts unlocked"),
    }
}

/// A tray icon that is showing. Dropping it removes the icon.
pub struct Tray {
    inner: imp::Inner,
}

impl std::fmt::Debug for Tray {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Tray").finish_non_exhaustive()
    }
}

impl Tray {
    /// Shows the tray icon. `on_event` runs on the tray's own thread.
    /// `window_visible` sets whether the menu starts with Hide or Show.
    /// Blocks briefly while registering. Fails when the desktop has no tray.
    pub fn spawn(
        window_visible: bool,
        on_event: impl Fn(TrayEvent) + Send + Sync + 'static,
    ) -> Result<Self, Error> {
        let state = TrayState {
            status: String::new(),
            window_visible,
            needs_attention: false,
        };
        Ok(Self {
            inner: imp::Inner::spawn(state, Box::new(on_event))?,
        })
    }

    /// Sets the greyed-out status line at the top of the menu, and the
    /// tooltip. An empty string hides the line. See [`status_text`].
    pub fn set_status(&self, status: impl Into<String>) {
        let status = status.into();
        self.inner.update(move |state| state.status = status);
    }

    /// Tells the tray whether the window is showing, so the menu offers
    /// Hide or Show.
    pub fn set_window_visible(&self, visible: bool) {
        self.inner
            .update(move |state| state.window_visible = visible);
    }

    /// Marks the icon as needing attention, for example while SSH requests
    /// wait for approval. How it shows depends on the desktop.
    pub fn set_needs_attention(&self, needs_attention: bool) {
        self.inner
            .update(move |state| state.needs_attention = needs_attention);
    }

    /// Whether the tray service is still running. It stops if the desktop's
    /// tray host goes away for good.
    pub fn is_running(&self) -> bool {
        self.inner.is_running()
    }
}

#[cfg(target_os = "linux")]
mod imp {
    use super::{Error, TrayEvent, TrayState, menu_model};
    use crate::APP_ID;
    use ksni::blocking::TrayMethods;
    use std::sync::Arc;

    type Callback = Arc<dyn Fn(TrayEvent) + Send + Sync>;

    /// The SVG the icon pixmaps are drawn from, for when the icon theme has
    /// no `io.github.lkarlslund.Hushjar` (before scripts/install-desktop.sh).
    const ICON_SVG: &[u8] =
        include_bytes!("../../../../packaging/linux/io.github.lkarlslund.Hushjar.svg");
    const ICON_SIZES: [u32; 4] = [22, 32, 48, 64];

    struct HushjarTray {
        state: TrayState,
        pixmaps: Arc<Vec<ksni::Icon>>,
        on_event: Callback,
    }

    impl ksni::Tray for HushjarTray {
        fn id(&self) -> String {
            APP_ID.into()
        }

        fn title(&self) -> String {
            "Hushjar".into()
        }

        fn category(&self) -> ksni::Category {
            ksni::Category::ApplicationStatus
        }

        fn status(&self) -> ksni::Status {
            if self.state.needs_attention {
                ksni::Status::NeedsAttention
            } else {
                ksni::Status::Active
            }
        }

        fn icon_name(&self) -> String {
            APP_ID.into()
        }

        fn icon_pixmap(&self) -> Vec<ksni::Icon> {
            self.pixmaps.as_ref().clone()
        }

        fn attention_icon_name(&self) -> String {
            APP_ID.into()
        }

        fn attention_icon_pixmap(&self) -> Vec<ksni::Icon> {
            self.pixmaps.as_ref().clone()
        }

        fn tool_tip(&self) -> ksni::ToolTip {
            ksni::ToolTip {
                title: "Hushjar".into(),
                description: self.state.status.clone(),
                ..Default::default()
            }
        }

        fn activate(&mut self, _x: i32, _y: i32) {
            (self.on_event)(TrayEvent::Activate);
        }

        fn menu(&self) -> Vec<ksni::MenuItem<Self>> {
            menu_model(&self.state)
                .into_iter()
                .map(|entry| match entry {
                    None => ksni::MenuItem::Separator,
                    Some((label, event)) => ksni::menu::StandardItem {
                        label,
                        enabled: event.is_some(),
                        activate: Box::new(move |tray: &mut Self| {
                            if let Some(event) = event {
                                (tray.on_event)(event);
                            }
                        }),
                        ..Default::default()
                    }
                    .into(),
                })
                .collect()
        }
    }

    pub struct Inner {
        handle: ksni::blocking::Handle<HushjarTray>,
    }

    impl Inner {
        pub fn spawn(
            state: TrayState,
            on_event: Box<dyn Fn(TrayEvent) + Send + Sync>,
        ) -> Result<Self, Error> {
            let tray = HushjarTray {
                state,
                pixmaps: Arc::new(render_icons()),
                on_event: Arc::from(on_event),
            };
            let handle = tray
                .disable_dbus_name(super::super::in_flatpak())
                .spawn()
                .map_err(|error| match error {
                    ksni::Error::Dbus(error) => Error::from(error),
                    other => Error::Unavailable(format!("a system tray ({other})")),
                })?;
            Ok(Self { handle })
        }

        pub fn update(&self, change: impl FnOnce(&mut TrayState)) {
            self.handle.update(|tray| change(&mut tray.state));
        }

        pub fn is_running(&self) -> bool {
            !self.handle.is_closed()
        }
    }

    impl Drop for Inner {
        fn drop(&mut self) {
            // Do not wait: the service thread unregisters on its own.
            drop(self.handle.shutdown());
        }
    }

    /// Draws the app icon at the usual tray sizes as ARGB32 pixmaps.
    /// Returns none if the SVG cannot be read, leaving only the icon name.
    pub(super) fn render_icons() -> Vec<ksni::Icon> {
        let Ok(tree) = resvg::usvg::Tree::from_data(ICON_SVG, &resvg::usvg::Options::default())
        else {
            return Vec::new();
        };
        ICON_SIZES
            .iter()
            .filter_map(|&size| {
                let mut pixmap = resvg::tiny_skia::Pixmap::new(size, size)?;
                let scale = size as f32 / tree.size().width().max(tree.size().height());
                resvg::render(
                    &tree,
                    resvg::tiny_skia::Transform::from_scale(scale, scale),
                    &mut pixmap.as_mut(),
                );
                Some(ksni::Icon {
                    width: size as i32,
                    height: size as i32,
                    data: premultiplied_rgba_to_argb(pixmap.data()),
                })
            })
            .collect()
    }

    /// Converts tiny-skia's premultiplied RGBA to the straight ARGB32, in
    /// network byte order, that StatusNotifierItem pixmaps use.
    pub(super) fn premultiplied_rgba_to_argb(rgba: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(rgba.len());
        for pixel in rgba.chunks_exact(4) {
            let alpha = pixel[3];
            let unmultiply = |c: u8| {
                if alpha == 0 {
                    0
                } else {
                    ((u16::from(c) * 255 + u16::from(alpha) / 2) / u16::from(alpha)).min(255) as u8
                }
            };
            out.extend_from_slice(&[
                alpha,
                unmultiply(pixel[0]),
                unmultiply(pixel[1]),
                unmultiply(pixel[2]),
            ]);
        }
        out
    }
}

#[cfg(not(target_os = "linux"))]
mod imp {
    use super::{Error, TrayEvent, TrayState};

    pub struct Inner;

    impl Inner {
        pub fn spawn(
            _state: TrayState,
            _on_event: Box<dyn Fn(TrayEvent) + Send + Sync>,
        ) -> Result<Self, Error> {
            Err(Error::Unsupported)
        }

        pub fn update(&self, _change: impl FnOnce(&mut TrayState)) {}

        pub fn is_running(&self) -> bool {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn labels(state: &TrayState) -> Vec<String> {
        menu_model(state)
            .into_iter()
            .map(|entry| match entry {
                None => "---".to_owned(),
                Some((label, None)) => format!("({label})"),
                Some((label, Some(_))) => label,
            })
            .collect()
    }

    #[test]
    fn menu_offers_hide_while_the_window_shows() {
        let state = TrayState {
            status: "2 accounts unlocked".into(),
            window_visible: true,
            needs_attention: false,
        };
        assert_eq!(
            labels(&state),
            [
                "(2 accounts unlocked)",
                "---",
                "Hide Hushjar",
                "Lock all",
                "---",
                "Quit"
            ]
        );
    }

    #[test]
    fn menu_offers_show_while_hidden_and_skips_an_empty_status() {
        let state = TrayState {
            status: String::new(),
            window_visible: false,
            needs_attention: false,
        };
        let model = menu_model(&state);
        assert_eq!(labels(&state), ["Show Hushjar", "Lock all", "---", "Quit"]);
        assert_eq!(model[0].as_ref().unwrap().1, Some(TrayEvent::ShowWindow));
        assert_eq!(model[1].as_ref().unwrap().1, Some(TrayEvent::LockAll));
        assert_eq!(model[3].as_ref().unwrap().1, Some(TrayEvent::Quit));
    }

    #[test]
    fn status_text_counts_accounts() {
        assert_eq!(status_text(0, 0), "No accounts");
        assert_eq!(status_text(0, 2), "All accounts locked");
        assert_eq!(status_text(1, 2), "1 account unlocked");
        assert_eq!(status_text(2, 3), "2 accounts unlocked");
    }

    /// Shows the icon for a moment and checks that the desktop's
    /// StatusNotifierWatcher lists it. Puts an icon in the panel briefly,
    /// so it only runs by hand: `cargo test -p hushjar tray_registers_by_hand
    /// -- --ignored --nocapture`.
    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "shows an icon in the desktop's tray for a second"]
    fn tray_registers_by_hand() {
        let tray = Tray::spawn(false, |event| eprintln!("{event:?}")).unwrap();
        tray.set_status(status_text(1, 2));
        tray.set_window_visible(true);
        std::thread::sleep(std::time::Duration::from_millis(500));
        let connection = zbus::blocking::Connection::session().unwrap();
        let watcher = zbus::blocking::Proxy::new(
            &connection,
            "org.kde.StatusNotifierWatcher",
            "/StatusNotifierWatcher",
            "org.kde.StatusNotifierWatcher",
        )
        .unwrap();
        let items: Vec<String> = watcher
            .get_property("RegisteredStatusNotifierItems")
            .unwrap();
        let pid = std::process::id().to_string();
        eprintln!("registered: {items:?}");
        let item = items
            .iter()
            .find(|item| item.contains(&pid))
            .and_then(|item| item.split_once('/'))
            .expect("our item is registered")
            .0;
        // Read the menu back the way the panel does.
        let menu = zbus::blocking::Proxy::new(
            &connection,
            item.to_owned(),
            "/MenuBar",
            "com.canonical.dbusmenu",
        )
        .unwrap();
        let layout = menu
            .call_method("GetLayout", &(0i32, -1i32, Vec::<&str>::new()))
            .unwrap();
        let layout = format!(
            "{:?}",
            layout.body().deserialize::<zbus::zvariant::Structure>()
        );
        for label in ["1 account unlocked", "Hide Hushjar", "Lock all", "Quit"] {
            assert!(layout.contains(label), "{label} missing from {layout}");
        }
        assert!(tray.is_running());
        drop(tray);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn pixels_are_unpremultiplied_into_argb() {
        // Opaque red, half-transparent premultiplied white, fully clear.
        let rgba = [255, 0, 0, 255, 128, 128, 128, 128, 0, 0, 0, 0];
        assert_eq!(
            imp::premultiplied_rgba_to_argb(&rgba),
            [255, 255, 0, 0, 128, 255, 255, 255, 0, 0, 0, 0]
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn the_app_icon_renders_at_tray_sizes() {
        let icons = imp::render_icons();
        assert_eq!(
            icons.iter().map(|i| i.width).collect::<Vec<_>>(),
            [22, 32, 48, 64]
        );
        for icon in &icons {
            assert_eq!(icon.data.len(), (icon.width * icon.height * 4) as usize);
            // Something was drawn: some pixels are opaque.
            assert!(icon.data.chunks_exact(4).any(|p| p[0] == 255));
        }
    }
}

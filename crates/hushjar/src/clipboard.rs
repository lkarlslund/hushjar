//! Copying secrets: marked so clipboard managers skip them (on Linux), and
//! cleared after a delay if the clipboard still holds what we put there.

use std::time::Duration;

use slint::{Timer, TimerMode};
use zeroize::Zeroizing;

use crate::AppWindow;

pub struct Clipboard {
    system: System,
    /// How long a copied value stays, or None to leave it.
    pub clear_after: Option<Duration>,
    last: Option<Zeroizing<String>>,
    timer: Timer,
}

impl Clipboard {
    pub fn new(window: &AppWindow) -> Self {
        Self {
            system: System::new(window),
            clear_after: Some(Duration::from_secs(30)),
            last: None,
            timer: Timer::default(),
        }
    }

    /// Copies `text`. Returns an error message when no clipboard is available.
    pub fn copy(this: &std::rc::Rc<std::cell::RefCell<Self>>, text: &str) -> Result<(), String> {
        let mut me = this.borrow_mut();
        me.system.set(text)?;
        me.last = Some(Zeroizing::new(text.to_string()));
        let Some(delay) = me.clear_after else {
            me.timer.stop();
            return Ok(());
        };
        let weak = std::rc::Rc::downgrade(this);
        me.timer.start(TimerMode::SingleShot, delay, move || {
            if let Some(this) = weak.upgrade() {
                this.borrow_mut().clear_if_ours();
            }
        });
        Ok(())
    }

    /// Clears the clipboard if it still holds the last value we copied.
    pub fn clear_if_ours(&mut self) {
        let Some(last) = self.last.take() else { return };
        self.system.clear_if(&last);
    }
}

/// The system clipboard on the desktop, through arboard.
#[cfg(not(target_os = "android"))]
struct System(Option<arboard::Clipboard>);

#[cfg(not(target_os = "android"))]
impl System {
    fn new(_window: &AppWindow) -> Self {
        Self(arboard::Clipboard::new().ok())
    }

    fn set(&mut self, text: &str) -> Result<(), String> {
        let clipboard = self.0.as_mut().ok_or("No clipboard is available")?;
        #[cfg(target_os = "linux")]
        let result = {
            use arboard::SetExtLinux;
            clipboard.set().exclude_from_history().text(text)
        };
        #[cfg(target_os = "windows")]
        let result = {
            use arboard::SetExtWindows;
            clipboard
                .set()
                .exclude_from_history()
                .exclude_from_cloud()
                .exclude_from_monitoring()
                .text(text)
        };
        #[cfg(target_os = "macos")]
        let result = {
            use arboard::SetExtApple;
            clipboard.set().exclude_from_history().text(text)
        };
        #[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
        let result = clipboard.set().text(text);
        result.map_err(|e| format!("Could not copy: {e}"))
    }

    fn clear_if(&mut self, last: &str) {
        if let Some(clipboard) = self.0.as_mut()
            && clipboard
                .get_text()
                .map(Zeroizing::new)
                .is_ok_and(|current| current.as_str() == last)
        {
            let _ = clipboard.clear();
        }
    }
}

/// The system clipboard on Android, through Slint's backend: the window
/// copies from a hidden text input (`copy-to-clipboard` in app.slint), as
/// Slint has no direct clipboard call.
///
/// Reading the clipboard back would leave the secret in that input's undo
/// history, so clearing does not check whether the value is still ours: it
/// overwrites the clipboard with a space once the delay is over, even if
/// something else was copied in between.
#[cfg(target_os = "android")]
struct System(slint::Weak<AppWindow>);

#[cfg(target_os = "android")]
impl System {
    fn new(window: &AppWindow) -> Self {
        use slint::ComponentHandle;
        Self(window.as_weak())
    }

    fn set(&mut self, text: &str) -> Result<(), String> {
        let window = self.0.upgrade().ok_or("No clipboard is available")?;
        window.invoke_copy_to_clipboard(text.into());
        Ok(())
    }

    fn clear_if(&mut self, _last: &str) {
        if let Some(window) = self.0.upgrade() {
            window.invoke_copy_to_clipboard(" ".into());
        }
    }
}

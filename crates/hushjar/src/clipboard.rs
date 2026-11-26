//! Copying secrets: marked so clipboard managers skip them (on Linux), and
//! cleared after a delay if the clipboard still holds what we put there.

use std::time::Duration;

use slint::{Timer, TimerMode};
use zeroize::Zeroizing;

pub const CLEAR_AFTER: Duration = Duration::from_secs(30);

pub struct Clipboard {
    inner: Option<arboard::Clipboard>,
    last: Option<Zeroizing<String>>,
    timer: Timer,
}

impl Clipboard {
    pub fn new() -> Self {
        Self {
            inner: arboard::Clipboard::new().ok(),
            last: None,
            timer: Timer::default(),
        }
    }

    /// Copies `text`. Returns an error message when no clipboard is available.
    pub fn copy(this: &std::rc::Rc<std::cell::RefCell<Self>>, text: &str) -> Result<(), String> {
        let mut me = this.borrow_mut();
        let clipboard = me.inner.as_mut().ok_or("No clipboard is available")?;
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
        result.map_err(|e| format!("Could not copy: {e}"))?;
        me.last = Some(Zeroizing::new(text.to_string()));
        let weak = std::rc::Rc::downgrade(this);
        me.timer.start(TimerMode::SingleShot, CLEAR_AFTER, move || {
            if let Some(this) = weak.upgrade() {
                this.borrow_mut().clear_if_ours();
            }
        });
        Ok(())
    }

    /// Clears the clipboard if it still holds the last value we copied.
    pub fn clear_if_ours(&mut self) {
        let Some(last) = self.last.take() else { return };
        if let Some(clipboard) = self.inner.as_mut()
            && clipboard
                .get_text()
                .map(Zeroizing::new)
                .is_ok_and(|current| *current == *last)
        {
            let _ = clipboard.clear();
        }
    }
}

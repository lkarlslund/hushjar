//! Desktop notifications with buttons, used for SSH agent approval prompts
//! while the window is hidden.
//!
//! On Linux this is `org.freedesktop.Notifications` on the session bus. KDE
//! Plasma and GNOME show actions as buttons. The action [`DEFAULT`] is not
//! shown as a button: it fires when the user clicks the notification itself.

use super::Error;
use std::time::Duration;

/// The action key for clicking the notification body.
pub const DEFAULT: &str = "default";
/// The action key for the Allow button of an approval prompt.
pub const ALLOW: &str = "allow";
/// The action key for the Deny button of an approval prompt.
pub const DENY: &str = "deny";

/// How urgent a notification is. Critical ones stay until answered on most
/// desktops.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Urgency {
    Low,
    Normal,
    Critical,
}

/// A notification to show.
#[derive(Debug, Clone)]
pub struct Notification {
    /// The title line.
    pub summary: String,
    /// Plain text; it is escaped where the desktop reads markup.
    pub body: String,
    /// `(key, label)` pairs, in order. Use [`DEFAULT`] for clicks on the
    /// notification itself.
    pub actions: Vec<(String, String)>,
    pub urgency: Urgency,
    /// How long until it expires; `None` leaves it until it is answered or
    /// closed.
    pub timeout: Option<Duration>,
}

impl Notification {
    /// An approval prompt with Allow and Deny buttons, where clicking the
    /// notification itself answers [`DEFAULT`] (show the window). It does
    /// not expire on its own; the app closes it with [`Notifier::close`]
    /// when its own timeout denies the request.
    pub fn approval(summary: impl Into<String>, body: impl Into<String>) -> Self {
        Self {
            summary: summary.into(),
            body: body.into(),
            actions: vec![
                (ALLOW.into(), "Allow".into()),
                (DENY.into(), "Deny".into()),
                (DEFAULT.into(), "Show Hushjar".into()),
            ],
            urgency: Urgency::Critical,
            timeout: None,
        }
    }
}

/// Why a notification closed without an action being chosen.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CloseReason {
    Expired,
    Dismissed,
    /// Closed by a `CloseNotification` call; not reported for
    /// [`Notifier::close`], which drops the callback first.
    Closed,
    Unknown,
}

impl CloseReason {
    /// Decodes the reason code of the `NotificationClosed` signal.
    pub fn from_code(code: u32) -> Self {
        match code {
            1 => Self::Expired,
            2 => Self::Dismissed,
            3 => Self::Closed,
            _ => Self::Unknown,
        }
    }
}

/// What happened to a notification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Response {
    /// The user chose the action with this key.
    Action(String),
    /// It closed without an action.
    Closed(CloseReason),
}

/// The ID the notification server gave a notification.
pub type NotificationId = u32;

type Callback = Box<dyn FnOnce(Response) + Send>;

/// A connection to the notification server. Create one and keep it for the
/// app's lifetime; dropping it stops listening for answers.
pub struct Notifier {
    inner: imp::Inner,
}

impl std::fmt::Debug for Notifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Notifier").finish_non_exhaustive()
    }
}

impl Notifier {
    /// Connects to the notification server and starts listening for answers
    /// on a background thread.
    pub fn connect() -> Result<Self, Error> {
        Ok(Self {
            inner: imp::Inner::connect()?,
        })
    }

    /// Whether the server shows action buttons.
    pub fn supports_actions(&self) -> bool {
        self.inner.supports_actions()
    }

    /// Shows `notification` and calls `on_response` once, on a background
    /// thread, with the action chosen or why it closed. Blocks for one
    /// D-Bus round trip.
    pub fn show(
        &self,
        notification: &Notification,
        on_response: impl FnOnce(Response) + Send + 'static,
    ) -> Result<NotificationId, Error> {
        self.inner.show(notification, Box::new(on_response))
    }

    /// Closes a notification, for example when the request was answered in
    /// the window or timed out. Its callback is dropped without being
    /// called.
    pub fn close(&self, id: NotificationId) -> Result<(), Error> {
        self.inner.close(id)
    }
}

/// Escapes text for servers that read the body as markup.
fn escape_markup(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            c => out.push(c),
        }
    }
    out
}

/// The flat `[key, label, key, label, ...]` list the D-Bus API wants.
fn flatten_actions(actions: &[(String, String)]) -> Vec<&str> {
    actions
        .iter()
        .flat_map(|(key, label)| [key.as_str(), label.as_str()])
        .collect()
}

/// The `expire_timeout` argument: milliseconds, 0 for never.
fn expire_timeout(timeout: Option<Duration>) -> i32 {
    timeout.map_or(0, |t| {
        i32::try_from(t.as_millis()).unwrap_or(i32::MAX).max(1)
    })
}

#[cfg(target_os = "linux")]
mod imp {
    use super::{
        Callback, CloseReason, Error, Notification, NotificationId, Response, Urgency,
        escape_markup, expire_timeout, flatten_actions,
    };
    use crate::APP_ID;
    use futures_lite::StreamExt;
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex, MutexGuard};
    use zbus::Proxy;
    use zbus::zvariant::Value;

    type Pending = Arc<Mutex<HashMap<NotificationId, Callback>>>;

    /// A signal from the server about one notification.
    enum Answer {
        Action(NotificationId, String),
        Closed(NotificationId, u32),
    }

    pub struct Inner {
        proxy: Proxy<'static>,
        pending: Pending,
        capabilities: Vec<String>,
        stop: Option<async_channel::Sender<()>>,
        thread: Option<std::thread::JoinHandle<()>>,
    }

    fn lock(pending: &Pending) -> MutexGuard<'_, HashMap<NotificationId, Callback>> {
        pending
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    impl Inner {
        pub fn connect() -> Result<Self, Error> {
            let (proxy, capabilities) = zbus::block_on(async {
                let connection = zbus::Connection::session().await?;
                let proxy = Proxy::new(
                    &connection,
                    "org.freedesktop.Notifications",
                    "/org/freedesktop/Notifications",
                    "org.freedesktop.Notifications",
                )
                .await?;
                let capabilities: Vec<String> = proxy.call("GetCapabilities", &()).await?;
                Ok::<_, Error>((proxy, capabilities))
            })?;
            let pending = Pending::default();
            let (stop_tx, stop_rx) = async_channel::bounded::<()>(1);
            let (ready_tx, ready_rx) = std::sync::mpsc::channel();
            let listener = proxy.clone();
            let listener_pending = pending.clone();
            let thread = std::thread::Builder::new()
                .name("hushjar-notify".into())
                .spawn(move || {
                    zbus::block_on(async move {
                        let mut answers = match subscribe(&listener).await {
                            Ok(answers) => {
                                let _ = ready_tx.send(None);
                                Box::pin(answers)
                            }
                            Err(error) => {
                                let _ = ready_tx.send(Some(error));
                                return;
                            }
                        };
                        let listen = async {
                            while let Some(answer) = answers.next().await {
                                dispatch(&listener_pending, answer);
                            }
                        };
                        let stop = async {
                            let _ = stop_rx.recv().await;
                        };
                        futures_lite::future::or(listen, stop).await;
                    });
                })?;
            if let Ok(Some(error)) = ready_rx.recv() {
                let _ = thread.join();
                return Err(error);
            }
            Ok(Self {
                proxy,
                pending,
                capabilities,
                stop: Some(stop_tx),
                thread: Some(thread),
            })
        }

        pub fn supports_actions(&self) -> bool {
            self.capabilities.iter().any(|c| c == "actions")
        }

        pub fn show(
            &self,
            notification: &Notification,
            on_response: Callback,
        ) -> Result<NotificationId, Error> {
            let body = if self.capabilities.iter().any(|c| c == "body-markup") {
                escape_markup(&notification.body)
            } else {
                notification.body.clone()
            };
            let urgency: u8 = match notification.urgency {
                Urgency::Low => 0,
                Urgency::Normal => 1,
                Urgency::Critical => 2,
            };
            let mut hints: HashMap<&str, Value> = HashMap::new();
            hints.insert("desktop-entry", Value::from(APP_ID));
            hints.insert("urgency", Value::from(urgency));
            let actions = flatten_actions(&notification.actions);
            // Hold the lock across the call, so an answer that arrives
            // before the ID is recorded waits for it instead of being lost.
            let mut pending = lock(&self.pending);
            let id: NotificationId = zbus::block_on(self.proxy.call(
                "Notify",
                &(
                    "Hushjar",
                    0u32,
                    APP_ID,
                    notification.summary.as_str(),
                    body.as_str(),
                    actions,
                    hints,
                    expire_timeout(notification.timeout),
                ),
            ))?;
            pending.insert(id, on_response);
            Ok(id)
        }

        pub fn close(&self, id: NotificationId) -> Result<(), Error> {
            lock(&self.pending).remove(&id);
            zbus::block_on(self.proxy.call::<_, _, ()>("CloseNotification", &(id,)))?;
            Ok(())
        }
    }

    impl Drop for Inner {
        fn drop(&mut self) {
            drop(self.stop.take());
            if let Some(thread) = self.thread.take() {
                let _ = thread.join();
            }
        }
    }

    /// Subscribes to the server's answer signals as one stream.
    async fn subscribe(
        proxy: &Proxy<'static>,
    ) -> Result<impl futures_lite::Stream<Item = Answer> + use<>, Error> {
        let actions = proxy
            .receive_signal("ActionInvoked")
            .await?
            .filter_map(|message| {
                let (id, key) = message.body().deserialize::<(u32, String)>().ok()?;
                Some(Answer::Action(id, key))
            });
        let closed = proxy
            .receive_signal("NotificationClosed")
            .await?
            .filter_map(|message| {
                let (id, reason) = message.body().deserialize::<(u32, u32)>().ok()?;
                Some(Answer::Closed(id, reason))
            });
        Ok(actions.or(closed))
    }

    /// Calls the callback waiting for this notification, if any. The
    /// server also reports a close after an action, which finds no callback
    /// and is ignored.
    fn dispatch(pending: &Pending, answer: Answer) {
        let (id, response) = match answer {
            Answer::Action(id, key) => (id, Response::Action(key)),
            Answer::Closed(id, code) => (id, Response::Closed(CloseReason::from_code(code))),
        };
        let callback = lock(pending).remove(&id);
        if let Some(callback) = callback {
            callback(response);
        }
    }
}

#[cfg(not(target_os = "linux"))]
mod imp {
    use super::{Callback, Error, Notification, NotificationId};

    pub struct Inner;

    impl Inner {
        pub fn connect() -> Result<Self, Error> {
            Err(Error::Unsupported)
        }

        pub fn supports_actions(&self) -> bool {
            false
        }

        pub fn show(&self, _: &Notification, _: Callback) -> Result<NotificationId, Error> {
            Err(Error::Unsupported)
        }

        pub fn close(&self, _: NotificationId) -> Result<(), Error> {
            Err(Error::Unsupported)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn markup_is_escaped() {
        assert_eq!(
            escape_markup("ssh <b>&\"x\"'"),
            "ssh &lt;b&gt;&amp;&quot;x&quot;&apos;"
        );
    }

    #[test]
    fn actions_are_flattened_in_order() {
        let prompt = Notification::approval("Use key?", "body");
        assert_eq!(
            flatten_actions(&prompt.actions),
            ["allow", "Allow", "deny", "Deny", "default", "Show Hushjar"]
        );
    }

    #[test]
    fn timeouts_are_milliseconds_with_zero_for_never() {
        assert_eq!(expire_timeout(None), 0);
        assert_eq!(expire_timeout(Some(Duration::from_secs(30))), 30_000);
        // A zero duration must not turn into "never".
        assert_eq!(expire_timeout(Some(Duration::ZERO)), 1);
        assert_eq!(
            expire_timeout(Some(Duration::from_secs(u64::MAX))),
            i32::MAX
        );
    }

    #[test]
    fn close_reasons_are_decoded() {
        assert_eq!(CloseReason::from_code(1), CloseReason::Expired);
        assert_eq!(CloseReason::from_code(2), CloseReason::Dismissed);
        assert_eq!(CloseReason::from_code(3), CloseReason::Closed);
        assert_eq!(CloseReason::from_code(9), CloseReason::Unknown);
    }

    /// Connects and reads the server's capabilities without showing
    /// anything. Skips where there is no notification server (CI).
    #[cfg(target_os = "linux")]
    #[test]
    fn connects_to_a_real_server_without_notifying() {
        match Notifier::connect() {
            Ok(notifier) => eprintln!("actions supported: {}", notifier.supports_actions()),
            Err(error) => eprintln!("no notification server ({error}); skipped"),
        }
    }
}

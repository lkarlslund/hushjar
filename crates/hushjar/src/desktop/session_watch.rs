//! Watches for the screen locking and the computer going to sleep, so vault
//! timeouts "on system lock" and "on sleep" can lock accounts.
//!
//! On Linux it listens to three sources, any of which may be missing:
//!
//! - logind's `PrepareForSleep(true/false)` on the system bus;
//! - this user's logind session: its `Lock` and `Unlock` signals (requests,
//!   for example from `loginctl lock-session`) and its `LockedHint` property,
//!   which KDE Plasma and GNOME set while the lock screen is up;
//! - `org.freedesktop.ScreenSaver`'s `ActiveChanged` on the session bus,
//!   which KDE Plasma emits when the lock screen starts and ends.
//!
//! The same lock usually arrives from several sources, so events are
//! reported only when the state changes.

use super::Error;

/// A change in the session that may lock accounts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SystemEvent {
    /// The screen locked, or locking was requested.
    ScreenLocked,
    /// The screen unlocked.
    ScreenUnlocked,
    /// The computer is about to suspend or hibernate.
    Sleeping,
    /// The computer woke up.
    Resumed,
}

/// A source of events that the watcher managed to subscribe to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    /// logind's `PrepareForSleep` signal.
    LogindSleep,
    /// The user's logind session: `Lock`, `Unlock` and `LockedHint`.
    LogindSession,
    /// `org.freedesktop.ScreenSaver`'s `ActiveChanged` signal.
    ScreenSaver,
}

/// A raw signal from one of the sources, before deduplication.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Signal {
    PrepareForSleep(bool),
    SessionLock,
    SessionUnlock,
    LockedHint(bool),
    ScreenSaverActive(bool),
}

/// Turns raw signals into [`SystemEvent`]s, reporting each lock, unlock,
/// sleep and wake once however many sources announce it.
#[derive(Debug, Default)]
struct Dedupe {
    locked: bool,
    sleeping: bool,
}

impl Dedupe {
    fn feed(&mut self, signal: Signal) -> Option<SystemEvent> {
        use Signal::*;
        match signal {
            SessionLock | LockedHint(true) | ScreenSaverActive(true) => {
                (!std::mem::replace(&mut self.locked, true)).then_some(SystemEvent::ScreenLocked)
            }
            SessionUnlock | LockedHint(false) | ScreenSaverActive(false) => {
                std::mem::replace(&mut self.locked, false).then_some(SystemEvent::ScreenUnlocked)
            }
            PrepareForSleep(true) => {
                (!std::mem::replace(&mut self.sleeping, true)).then_some(SystemEvent::Sleeping)
            }
            PrepareForSleep(false) => {
                std::mem::replace(&mut self.sleeping, false).then_some(SystemEvent::Resumed)
            }
        }
    }
}

/// A running watcher. Dropping it stops watching.
pub struct SessionWatch {
    sources: Vec<Source>,
    #[cfg(target_os = "linux")]
    stop: Option<async_channel::Sender<()>>,
    #[cfg(target_os = "linux")]
    thread: Option<std::thread::JoinHandle<()>>,
}

impl std::fmt::Debug for SessionWatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionWatch")
            .field("sources", &self.sources)
            .finish_non_exhaustive()
    }
}

impl SessionWatch {
    /// Starts watching on a background thread and calls `on_event` on that
    /// thread for each event. If the screen is already locked, the first
    /// event is [`SystemEvent::ScreenLocked`]. Blocks briefly while
    /// subscribing. Fails only when no source at all could be subscribed to.
    pub fn start(on_event: impl Fn(SystemEvent) + Send + 'static) -> Result<Self, Error> {
        imp::start(Box::new(on_event))
    }

    /// The sources this watcher is subscribed to.
    pub fn sources(&self) -> &[Source] {
        &self.sources
    }
}

#[cfg(target_os = "linux")]
impl Drop for SessionWatch {
    fn drop(&mut self) {
        // Closing the channel ends the watcher's loop.
        drop(self.stop.take());
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

#[cfg(target_os = "linux")]
mod imp {
    use super::{Dedupe, Error, SessionWatch, Signal, Source, SystemEvent};
    use futures_lite::{Stream, StreamExt};
    use std::collections::HashMap;
    use std::pin::Pin;
    use zbus::zvariant::{OwnedObjectPath, OwnedValue};
    use zbus::{Connection, Proxy};

    type Signals = Pin<Box<dyn Stream<Item = Signal> + Send>>;
    type Callback = Box<dyn Fn(SystemEvent) + Send>;

    const LOGIN1: &str = "org.freedesktop.login1";
    const SESSION_INTERFACE: &str = "org.freedesktop.login1.Session";

    pub fn start(on_event: Callback) -> Result<SessionWatch, Error> {
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();
        let (stop_tx, stop_rx) = async_channel::bounded::<()>(1);
        let thread = std::thread::Builder::new()
            .name("hushjar-session-watch".into())
            .spawn(move || {
                zbus::block_on(async move {
                    let (sources, streams) = subscribe().await;
                    let _ = ready_tx.send(sources);
                    let Some(mut signals) = streams.into_iter().reduce(|a, b| Box::pin(a.or(b)))
                    else {
                        return;
                    };
                    let watch = async {
                        let mut dedupe = Dedupe::default();
                        while let Some(signal) = signals.next().await {
                            if let Some(event) = dedupe.feed(signal) {
                                on_event(event);
                            }
                        }
                    };
                    let stop = async {
                        let _ = stop_rx.recv().await;
                    };
                    futures_lite::future::or(watch, stop).await;
                });
            })?;
        let sources = ready_rx.recv().unwrap_or_default();
        let watch = SessionWatch {
            sources,
            stop: Some(stop_tx),
            thread: Some(thread),
        };
        if watch.sources.is_empty() {
            return Err(Error::Unavailable(
                "logind and the screen saver service".into(),
            ));
        }
        Ok(watch)
    }

    /// Subscribes to every source it can, skipping those that fail.
    async fn subscribe() -> (Vec<Source>, Vec<Signals>) {
        let mut sources = Vec::new();
        let mut streams = Vec::new();
        if let Ok(system) = Connection::system().await {
            if let Ok(stream) = sleep_signals(&system).await {
                sources.push(Source::LogindSleep);
                streams.push(stream);
            }
            if let Ok(mut session) = session_signals(&system).await {
                sources.push(Source::LogindSession);
                streams.append(&mut session);
            }
        }
        if let Ok(session_bus) = Connection::session().await
            && let Ok(stream) = screensaver_signals(&session_bus).await
        {
            sources.push(Source::ScreenSaver);
            streams.push(stream);
        }
        (sources, streams)
    }

    async fn sleep_signals(system: &Connection) -> Result<Signals, Error> {
        let manager = manager(system).await?;
        let stream = manager.receive_signal("PrepareForSleep").await?;
        Ok(Box::pin(stream.filter_map(|message| {
            message
                .body()
                .deserialize::<bool>()
                .ok()
                .map(Signal::PrepareForSleep)
        })))
    }

    async fn session_signals(system: &Connection) -> Result<Vec<Signals>, Error> {
        let path = session_path(system).await?;
        let session = Proxy::new(system, LOGIN1, path, SESSION_INTERFACE).await?;
        let lock = session
            .receive_signal("Lock")
            .await?
            .map(|_| Signal::SessionLock);
        let unlock = session
            .receive_signal("Unlock")
            .await?
            .map(|_| Signal::SessionUnlock);
        let properties = Proxy::new(
            system,
            LOGIN1,
            session.path().to_owned(),
            "org.freedesktop.DBus.Properties",
        )
        .await?;
        let hint = properties
            .receive_signal("PropertiesChanged")
            .await?
            .filter_map(|message| {
                let (interface, changed, _invalidated) = message
                    .body()
                    .deserialize::<(String, HashMap<String, OwnedValue>, Vec<String>)>()
                    .ok()?;
                locked_hint_change(&interface, &changed).map(Signal::LockedHint)
            });
        // Start from the current state, subscribing first so no change is
        // missed in between.
        let now = session.get_property::<bool>("LockedHint").await?;
        let hint = futures_lite::stream::once(Signal::LockedHint(now)).chain(hint);
        Ok(vec![Box::pin(lock), Box::pin(unlock), Box::pin(hint)])
    }

    /// The new `LockedHint` in a session's `PropertiesChanged` signal, if
    /// the signal carries one.
    pub(super) fn locked_hint_change(
        interface: &str,
        changed: &HashMap<String, OwnedValue>,
    ) -> Option<bool> {
        if interface != SESSION_INTERFACE {
            return None;
        }
        bool::try_from(changed.get("LockedHint")?).ok()
    }

    async fn screensaver_signals(session_bus: &Connection) -> Result<Signals, Error> {
        let screensaver = Proxy::new(
            session_bus,
            "org.freedesktop.ScreenSaver",
            "/org/freedesktop/ScreenSaver",
            "org.freedesktop.ScreenSaver",
        )
        .await?;
        let stream = screensaver.receive_signal("ActiveChanged").await?;
        // Subscribing succeeds even when nobody owns the name; asking for
        // the current state checks that the service answers.
        let now = screensaver.call::<_, _, bool>("GetActive", &()).await?;
        let changes = stream.filter_map(|message| {
            message
                .body()
                .deserialize::<bool>()
                .ok()
                .map(Signal::ScreenSaverActive)
        });
        Ok(Box::pin(
            futures_lite::stream::once(Signal::ScreenSaverActive(now)).chain(changes),
        ))
    }

    async fn manager(system: &Connection) -> Result<Proxy<'static>, Error> {
        Ok(Proxy::new(
            system,
            LOGIN1,
            "/org/freedesktop/login1",
            "org.freedesktop.login1.Manager",
        )
        .await?)
    }

    /// Finds this user's graphical logind session. Apps started by KDE and
    /// GNOME run in systemd user units outside any session, so looking the
    /// session up by process ID fails; use `XDG_SESSION_ID` when it is set
    /// and else the user's display session.
    pub(super) async fn session_path(system: &Connection) -> Result<OwnedObjectPath, Error> {
        let manager = manager(system).await?;
        if let Some(id) = std::env::var("XDG_SESSION_ID")
            .ok()
            .filter(|id| !id.is_empty())
            && let Ok(path) = manager
                .call::<_, _, OwnedObjectPath>("GetSession", &(id.as_str(),))
                .await
        {
            return Ok(path);
        }
        let uid = super::super::current_uid()
            .ok_or_else(|| Error::Unavailable("the current user ID".into()))?;
        let user: OwnedObjectPath = manager.call("GetUser", &(uid,)).await?;
        let user = Proxy::new(system, LOGIN1, user, "org.freedesktop.login1.User").await?;
        let (_id, path): (String, OwnedObjectPath) = user.get_property("Display").await?;
        if path.as_str() == "/" {
            return Err(Error::Unavailable("a graphical logind session".into()));
        }
        Ok(path)
    }

    /// Reads the session's `LockedHint` once, for tests and diagnostics.
    pub(super) fn locked_hint() -> Result<bool, Error> {
        zbus::block_on(async {
            let system = Connection::system().await?;
            let path = session_path(&system).await?;
            let session = Proxy::new(&system, LOGIN1, path, SESSION_INTERFACE).await?;
            Ok(session.get_property::<bool>("LockedHint").await?)
        })
    }
}

#[cfg(not(target_os = "linux"))]
mod imp {
    use super::{Error, SessionWatch, SystemEvent};

    pub fn start(_on_event: Box<dyn Fn(SystemEvent) + Send>) -> Result<SessionWatch, Error> {
        Err(Error::Unsupported)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_lock_from_several_sources_is_reported_once() {
        let mut dedupe = Dedupe::default();
        assert_eq!(
            dedupe.feed(Signal::SessionLock),
            Some(SystemEvent::ScreenLocked)
        );
        assert_eq!(dedupe.feed(Signal::ScreenSaverActive(true)), None);
        assert_eq!(dedupe.feed(Signal::LockedHint(true)), None);
        assert_eq!(
            dedupe.feed(Signal::ScreenSaverActive(false)),
            Some(SystemEvent::ScreenUnlocked)
        );
        assert_eq!(dedupe.feed(Signal::LockedHint(false)), None);
        assert_eq!(
            dedupe.feed(Signal::LockedHint(true)),
            Some(SystemEvent::ScreenLocked)
        );
    }

    #[test]
    fn unlocking_when_not_locked_is_ignored() {
        let mut dedupe = Dedupe::default();
        assert_eq!(dedupe.feed(Signal::LockedHint(false)), None);
        assert_eq!(dedupe.feed(Signal::SessionUnlock), None);
    }

    #[test]
    fn sleep_and_wake_are_reported_once_each() {
        let mut dedupe = Dedupe::default();
        assert_eq!(dedupe.feed(Signal::PrepareForSleep(false)), None);
        assert_eq!(
            dedupe.feed(Signal::PrepareForSleep(true)),
            Some(SystemEvent::Sleeping)
        );
        assert_eq!(dedupe.feed(Signal::PrepareForSleep(true)), None);
        assert_eq!(
            dedupe.feed(Signal::PrepareForSleep(false)),
            Some(SystemEvent::Resumed)
        );
    }

    /// Subscribes to the real services without locking or suspending
    /// anything. Skips quietly where there is no desktop session (CI).
    #[cfg(target_os = "linux")]
    #[test]
    fn subscribes_on_a_real_desktop() {
        let Ok(watch) = SessionWatch::start(|_| {}) else {
            eprintln!("no logind or screen saver service; skipped");
            return;
        };
        eprintln!("sources: {:?}", watch.sources());
        assert!(!watch.sources().is_empty());
        if watch.sources().contains(&Source::LogindSession) {
            let hint = imp::locked_hint();
            eprintln!("LockedHint: {hint:?}");
            assert!(hint.is_ok());
        }
        drop(watch);
    }

    /// Prints events as they happen, for checking by hand: run with
    /// `HUSHJAR_WATCH_SECS=120 cargo test -p hushjar watch_session_by_hand
    /// -- --ignored --nocapture`, then lock and unlock the screen.
    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "watches the real session for a while"]
    fn watch_session_by_hand() {
        let secs = std::env::var("HUSHJAR_WATCH_SECS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(60);
        let start = std::time::Instant::now();
        let watch = SessionWatch::start(move |event| {
            eprintln!("{:>6.1}s {event:?}", start.elapsed().as_secs_f32());
        })
        .unwrap();
        eprintln!("watching {:?} for {secs} s", watch.sources());
        std::thread::sleep(std::time::Duration::from_secs(secs));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn locked_hint_is_read_from_session_property_changes() {
        use std::collections::HashMap;
        use zbus::zvariant::{OwnedValue, Value};
        let value = |v: Value<'static>| OwnedValue::try_from(v).unwrap();
        let mut changed = HashMap::new();
        changed.insert("LockedHint".to_owned(), value(Value::from(true)));
        changed.insert("IdleHint".to_owned(), value(Value::from(false)));
        let session = "org.freedesktop.login1.Session";
        assert_eq!(imp::locked_hint_change(session, &changed), Some(true));
        assert_eq!(imp::locked_hint_change("org.example.Other", &changed), None);
        changed.remove("LockedHint");
        assert_eq!(imp::locked_hint_change(session, &changed), None);
        changed.insert("LockedHint".to_owned(), value(Value::from("yes")));
        assert_eq!(imp::locked_hint_change(session, &changed), None);
    }
}

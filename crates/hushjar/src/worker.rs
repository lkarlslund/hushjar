//! One worker thread per account. It owns the account's session, runs
//! network and key-derivation work off the UI thread, and reports back with
//! [`Event`]s delivered on the Slint event loop.

use std::sync::Arc;
use std::sync::mpsc::{Receiver, RecvTimeoutError, Sender, channel};
use std::time::{Duration, Instant};

use hushjar_core::api::{SecondFactor, Server, TwoFactorProvider};
use hushjar_core::notifications::{Listener, Notification};
use hushjar_core::policy::Policies;
use hushjar_core::session::{Session, SessionError};
use hushjar_core::store::{Profile, Store};
use hushjar_core::vault::{Item, Vault};
use zeroize::Zeroizing;

use crate::pacing::{Debounce, WATCH_EVERY, Watch};

/// How long the notification listener waits for the worker to hand over a
/// fresh access token (the worker may be in the middle of a long sync).
const TOKEN_WAIT: Duration = Duration::from_secs(30);

pub enum Command {
    SignIn {
        server: Server,
        email: String,
        password: Zeroizing<String>,
        second: Option<(TwoFactorProvider, String, bool)>,
    },
    SendEmailCode {
        server: Server,
        email: String,
        password: Zeroizing<String>,
    },
    Unlock {
        password: Zeroizing<String>,
    },
    Reconnect {
        password: Zeroizing<String>,
        second: Option<(TwoFactorProvider, String, bool)>,
    },
    Sync,
    Save(Box<Item>),
    Trash(String),
    Restore(String),
    Delete(String),
    CreateFolder(String),
    Lock,
    /// Locks and forgets the session and offline copy.
    LogOut,
    Remove,
    /// From the notification listener: asks for a current access token.
    /// Answered with `None` when there is no session or no token to be had.
    Token(Sender<Option<Zeroizing<String>>>),
    /// From the notification listener: something the server announced.
    Remote(Notification),
}

/// What happened, for the UI. `vault` copies are the decrypted state after
/// the change.
pub enum Event {
    SignedIn {
        profile: Box<Profile>,
        vault: Vault,
        synced_at: Option<u64>,
    },
    TwoFactorRequired {
        providers: Vec<TwoFactorProvider>,
    },
    EmailSent,
    Unlocked {
        vault: Vault,
        synced_at: Option<u64>,
    },
    Synced {
        vault: Vault,
        synced_at: Option<u64>,
    },
    /// The account works offline but must sign in again to sync.
    NeedsSignIn {
        two_factor: Vec<TwoFactorProvider>,
    },
    Saved {
        item: Box<Item>,
        vault: Vault,
    },
    Changed {
        vault: Vault,
        message: String,
    },
    Failed {
        message: String,
    },
    /// A save may or may not have reached the server.
    SaveUncertain {
        message: String,
    },
    Locked,
    Removed,
    /// The organisation policies that apply to the account, sent with each
    /// vault that comes from a sync.
    Policies(Box<Policies>),
    /// Another device asks to be approved for signing in.
    LoginRequest {
        #[allow(dead_code)] // The sign-in job's check reads the pending requests itself.
        id: String,
    },
    /// The server ended the account's sessions (password or key change).
    /// The vault is locked and the offline copy forgotten.
    LoggedOutByServer,
    /// Whether live updates are failing repeatedly, and why.
    LiveStatus {
        problem: Option<String>,
    },
}

pub struct Worker {
    pub tx: Sender<Command>,
}

impl Worker {
    /// Starts a worker. `profile` is `None` for an account being added.
    /// `emit` receives the account's local ID (empty while adding) with each event.
    pub fn spawn(
        store: Arc<Store>,
        profile: Option<Profile>,
        emit: impl Fn(String, Event) + Send + 'static,
    ) -> Self {
        let (tx, rx) = channel();
        let own = tx.clone();
        std::thread::Builder::new()
            .name("hushjar-account".into())
            .spawn(move || run(store, profile, own, rx, emit))
            .expect("start account worker");
        Self { tx }
    }
}

fn second_factor(second: &Option<(TwoFactorProvider, String, bool)>) -> Option<SecondFactor<'_>> {
    second
        .as_ref()
        .map(|(provider, token, remember)| SecondFactor {
            provider: *provider,
            token: token.trim(),
            remember: *remember,
        })
}

fn describe(error: &SessionError) -> String {
    error.to_string()
}

/// Emits the account's policies and then the synced vault.
fn synced(session: &Session, emit: &dyn Fn(Event)) {
    emit(Event::Policies(Box::new(session.policies())));
    emit(Event::Synced {
        vault: session.vault.clone(),
        synced_at: session.synced_at,
    });
}

/// Starts the notification listener for a session. It asks the worker (over
/// the worker's own command channel) for tokens, so the session stays owned by
/// the worker thread, and hands every notification back the same way.
fn start_listener(session: &Session, tx: &Sender<Command>) -> Listener {
    let (token_tx, event_tx) = (tx.clone(), tx.clone());
    Listener::start(
        &session.profile.server,
        &session.profile.device.identifier,
        move || {
            let (reply, answer) = channel();
            token_tx.send(Command::Token(reply)).ok()?;
            answer.recv_timeout(TOKEN_WAIT).ok().flatten()
        },
        move |notification| {
            let _ = event_tx.send(Command::Remote(notification));
        },
    )
}

/// Live-update bookkeeping that lives next to the session.
struct Live {
    listener: Option<Listener>,
    debounce: Debounce,
    watch: Watch,
    watch_at: Option<Instant>,
}

impl Live {
    /// When the worker next has to wake up without a command.
    fn wake_in(&self, now: Instant) -> Duration {
        [self.debounce.deadline(), self.watch_at]
            .into_iter()
            .flatten()
            .min()
            .map_or(Duration::from_secs(3600), |t| {
                t.saturating_duration_since(now)
            })
    }

    /// Makes the listener exist exactly while there is a session.
    fn follow(&mut self, session: Option<&Session>, tx: &Sender<Command>) {
        match (session, self.listener.is_some()) {
            (Some(s), false) => {
                self.listener = Some(start_listener(s, tx));
                self.watch = Watch::default();
                self.watch_at = Some(Instant::now() + WATCH_EVERY);
            }
            (None, true) => self.stop(),
            _ => {}
        }
    }

    /// Drops the listener and any waiting sync.
    fn stop(&mut self) {
        drop(self.listener.take());
        self.debounce.clear();
        self.watch_at = None;
    }

    /// A look at the connection; the status to show when it changed.
    fn look(&mut self, now: Instant) -> Option<Option<String>> {
        if self.watch_at.is_none_or(|t| now < t) {
            return None;
        }
        self.watch_at = self.listener.as_ref().map(|_| now + WATCH_EVERY);
        let listener = self.listener.as_ref()?;
        self.watch.look(listener.is_connected(), listener.problem())
    }
}

fn run(
    store: Arc<Store>,
    mut profile: Option<Profile>,
    tx: Sender<Command>,
    rx: Receiver<Command>,
    emit_to: impl Fn(String, Event),
) {
    let mut session: Option<Session> = None;
    let mut live = Live {
        listener: None,
        debounce: Debounce::default(),
        watch: Watch::default(),
        watch_at: None,
    };

    // Brings an unlocked session online, signing in again with the password
    // when the stored tokens no longer work.
    let go_online =
        |session: &mut Session, password: Option<&str>, emit: &dyn Fn(Event)| match session
            .sync(&store)
        {
            Ok(()) => synced(session, emit),
            Err(SessionError::SignInRequired) => {
                match password.map(|p| session.reconnect(&store, p, None)) {
                    Some(Ok(())) => match session.sync(&store) {
                        Ok(()) => synced(session, emit),
                        Err(e) => emit(Event::Failed {
                            message: describe(&e),
                        }),
                    },
                    Some(Err(SessionError::TwoFactorRequired(p))) => emit(Event::NeedsSignIn {
                        two_factor: p.providers,
                    }),
                    _ => emit(Event::NeedsSignIn { two_factor: vec![] }),
                }
            }
            Err(e) => emit(Event::Failed {
                message: format!("Working offline: {}", describe(&e)),
            }),
        };

    loop {
        live.follow(session.as_ref(), &tx);
        let received = rx.recv_timeout(live.wake_in(Instant::now()));
        // Events go out under the ID the account had when the command arrived,
        // so a finished sign-in still reaches the add-account form.
        let id = profile.as_ref().map(|p| p.id.clone()).unwrap_or_default();
        let emit = |event: Event| emit_to(id.clone(), event);
        let command = match received {
            Ok(command) => command,
            Err(RecvTimeoutError::Timeout) => {
                let now = Instant::now();
                if live.debounce.due(now) {
                    live.debounce.clear();
                    if let Some(s) = session.as_mut() {
                        go_online(s, None, &emit);
                    }
                }
                if let Some(problem) = live.look(now) {
                    emit(Event::LiveStatus { problem });
                }
                continue;
            }
            Err(RecvTimeoutError::Disconnected) => return,
        };
        match command {
            Command::SignIn {
                server,
                email,
                password,
                second,
            } => {
                match Session::sign_in(
                    &store,
                    server,
                    &email,
                    &password,
                    second_factor(&second),
                    profile.as_ref(),
                ) {
                    Ok(s) => {
                        live.stop();
                        profile = Some(s.profile.clone());
                        emit(Event::SignedIn {
                            profile: Box::new(s.profile.clone()),
                            vault: s.vault.clone(),
                            synced_at: s.synced_at,
                        });
                        // The account now has its own ID; the app has created
                        // it by the time this arrives.
                        emit_to(
                            s.profile.id.clone(),
                            Event::Policies(Box::new(s.policies())),
                        );
                        session = Some(s);
                    }
                    Err(SessionError::TwoFactorRequired(challenge)) => {
                        emit(Event::TwoFactorRequired {
                            providers: challenge.providers,
                        })
                    }
                    Err(e) => emit(Event::Failed {
                        message: describe(&e),
                    }),
                }
            }
            Command::SendEmailCode {
                server,
                email,
                password,
            } => {
                let device = profile
                    .as_ref()
                    .map(|p| p.device.clone())
                    .unwrap_or_default();
                match Session::send_email_code(&server, &email, &password, &device) {
                    Ok(()) => emit(Event::EmailSent),
                    Err(e) => emit(Event::Failed {
                        message: describe(&e),
                    }),
                }
            }
            Command::Unlock { password } => {
                let Some(p) = profile.clone() else { continue };
                match Session::unlock(&store, &p, &password) {
                    Ok(mut s) => {
                        live.stop();
                        emit(Event::Policies(Box::new(s.policies())));
                        emit(Event::Unlocked {
                            vault: s.vault.clone(),
                            synced_at: s.synced_at,
                        });
                        go_online(&mut s, Some(&password), &emit);
                        session = Some(s);
                    }
                    Err(SessionError::NoOfflineCopy) => {
                        match Session::sign_in(
                            &store,
                            p.server.clone(),
                            &p.email,
                            &password,
                            None,
                            Some(&p),
                        ) {
                            Ok(s) => {
                                emit(Event::Policies(Box::new(s.policies())));
                                emit(Event::Unlocked {
                                    vault: s.vault.clone(),
                                    synced_at: s.synced_at,
                                });
                                session = Some(s);
                            }
                            Err(e) => emit(Event::Failed {
                                message: describe(&e),
                            }),
                        }
                    }
                    Err(e) => emit(Event::Failed {
                        message: describe(&e),
                    }),
                }
            }
            Command::Reconnect { password, second } => {
                let Some(s) = session.as_mut() else { continue };
                match s.reconnect(&store, &password, second_factor(&second)) {
                    Ok(()) => go_online(s, None, &emit),
                    Err(SessionError::TwoFactorRequired(p)) => emit(Event::NeedsSignIn {
                        two_factor: p.providers,
                    }),
                    Err(e) => emit(Event::Failed {
                        message: describe(&e),
                    }),
                }
            }
            Command::Sync => {
                if let Some(s) = session.as_mut() {
                    go_online(s, None, &emit);
                }
            }
            Command::Save(item) => {
                let Some(s) = session.as_mut() else { continue };
                match s.save(&store, &item) {
                    Ok(saved) => emit(Event::Saved {
                        item: Box::new(saved),
                        vault: s.vault.clone(),
                    }),
                    Err(SessionError::SaveUncertain) => {
                        let message = describe(&SessionError::SaveUncertain);
                        let _ = s.sync(&store);
                        emit(Event::SaveUncertain { message });
                        synced(s, &emit);
                    }
                    Err(SessionError::SignInRequired) => {
                        emit(Event::NeedsSignIn { two_factor: vec![] })
                    }
                    Err(e) => emit(Event::Failed {
                        message: describe(&e),
                    }),
                }
            }
            Command::Trash(id) | Command::Restore(id) | Command::Delete(id)
                if session.is_none() =>
            {
                let _ = id;
            }
            Command::Trash(id) => change(&mut session, &store, &emit, "Moved to trash", |s, st| {
                s.trash(st, &id)
            }),
            Command::Restore(id) => change(&mut session, &store, &emit, "Restored", |s, st| {
                s.restore(st, &id)
            }),
            Command::Delete(id) => change(
                &mut session,
                &store,
                &emit,
                "Deleted permanently",
                |s, st| s.delete(st, &id),
            ),
            Command::CreateFolder(name) => {
                change(&mut session, &store, &emit, "Folder created", |s, st| {
                    s.create_folder(st, &name).map(|_| ())
                })
            }
            Command::Lock => {
                live.stop();
                session = None;
                emit(Event::Locked);
            }
            Command::LogOut => {
                live.stop();
                log_out(&mut session, profile.as_ref(), &store);
                emit(Event::Locked);
            }
            Command::Remove => {
                live.stop();
                drop(session.take());
                if let Some(p) = &profile {
                    let _ = store.remove(&p.id);
                }
                emit(Event::Removed);
                return;
            }
            Command::Token(reply) => {
                let token = session.as_mut().and_then(|s| s.access_token().ok());
                let _ = reply.send(token);
            }
            Command::Remote(notification) => {
                // Only a live listener's news counts; a stopped one may still
                // have left a message in the queue.
                if live.listener.is_some() {
                    remote(
                        notification,
                        &mut session,
                        &mut live,
                        profile.as_ref(),
                        &store,
                        &emit,
                    );
                }
            }
        }
    }
}

/// Locks and forgets the session and the offline copy.
fn log_out(session: &mut Option<Session>, profile: Option<&Profile>, store: &Store) {
    *session = None;
    if let Some(p) = profile {
        let _ = store.forget_offline_copy(&p.id);
    }
}

/// Acts on something the server announced.
fn remote(
    notification: Notification,
    session: &mut Option<Session>,
    live: &mut Live,
    profile: Option<&Profile>,
    store: &Store,
    emit: &dyn Fn(Event),
) {
    match notification {
        Notification::VaultChanged => live.debounce.note(Instant::now()),
        Notification::LogOut => {
            live.stop();
            log_out(session, profile, store);
            emit(Event::LoggedOutByServer);
        }
        Notification::AuthRequest { id } => emit(Event::LoginRequest { id }),
        Notification::AuthRequestResponse { .. } | Notification::Other(_) => {}
    }
}

fn change(
    session: &mut Option<Session>,
    store: &Store,
    emit: &dyn Fn(Event),
    message: &str,
    action: impl FnOnce(&mut Session, &Store) -> Result<(), SessionError>,
) {
    let Some(s) = session.as_mut() else { return };
    match action(s, store) {
        Ok(()) => emit(Event::Changed {
            vault: s.vault.clone(),
            message: message.into(),
        }),
        Err(SessionError::SignInRequired) => emit(Event::NeedsSignIn { two_factor: vec![] }),
        Err(e) => emit(Event::Failed {
            message: describe(&e),
        }),
    }
}

/// Tests against a real Vaultwarden server; they run only when
/// HUSHJAR_INTEROP is set to its address (see tests/interop/README.md).
#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use hushjar_core::crypto::{self, HashPurpose, Kdf, SymmetricKey};
    use hushjar_core::vault::{Item as CoreItem, ItemKind};
    use serde_json::json;

    use super::*;

    const PASSWORD: &str = "invented worker password";
    const KDF: Kdf = Kdf::Pbkdf2 {
        iterations: 600_000,
    };

    fn register(base: &str, email: &str) {
        let master = crypto::master_key(PASSWORD, email, KDF).unwrap();
        let hash = crypto::password_hash(&master, PASSWORD, HashPurpose::Server);
        let wrapped = crypto::stretch(&master).wrap_key(&SymmetricKey::generate());
        let body = json!({
            "email": email,
            "name": "Hushjar worker test",
            "masterPasswordHash": hash.as_str(),
            "key": wrapped,
            "kdf": 0,
            "kdfIterations": 600_000,
        });
        let response = ureq::post(format!("{base}/identity/accounts/register"))
            .send_json(&body)
            .unwrap();
        assert_eq!(response.status().as_u16(), 200, "registration failed");
    }

    fn temp_store() -> (Arc<Store>, std::path::PathBuf) {
        let dir =
            std::env::temp_dir().join(format!("hushjar-worker-{}", uuid::Uuid::new_v4().simple()));
        (Arc::new(Store::open(dir.clone()).unwrap()), dir)
    }

    /// Waits for an event that `pick` accepts, ignoring the others.
    fn wait_for<T>(
        events: &Receiver<Event>,
        limit: Duration,
        what: &str,
        mut pick: impl FnMut(Event) -> Option<T>,
    ) -> T {
        let deadline = Instant::now() + limit;
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            match events.recv_timeout(left) {
                Ok(event) => {
                    if let Some(found) = pick(event) {
                        return found;
                    }
                }
                Err(_) => panic!("no {what} within {limit:?}"),
            }
        }
    }

    #[test]
    fn a_change_on_another_device_is_synced_by_itself() {
        let Ok(base) = std::env::var("HUSHJAR_INTEROP") else {
            eprintln!("skipped: set HUSHJAR_INTEROP to a Vaultwarden test server");
            return;
        };
        let email = format!("worker-{}@example.invalid", uuid::Uuid::new_v4().simple());
        register(&base, &email);
        let server = Server::parse(&base).unwrap();

        // This installation: a worker for a new account.
        let (store, dir) = temp_store();
        let (events_tx, events) = channel();
        let events_tx = std::sync::Mutex::new(events_tx);
        let worker = Worker::spawn(store, None, move |_id, event| {
            let _ = events_tx.lock().unwrap().send(event);
        });
        worker
            .tx
            .send(Command::SignIn {
                server: server.clone(),
                email: email.clone(),
                password: Zeroizing::new(PASSWORD.into()),
                second: None,
            })
            .unwrap();
        wait_for(&events, Duration::from_secs(60), "sign-in", |e| {
            matches!(e, Event::SignedIn { .. }).then_some(())
        });
        // The worker sends the account's policies after signing in.
        wait_for(&events, Duration::from_secs(5), "policies", |e| {
            matches!(e, Event::Policies(_)).then_some(())
        });

        // Another device adds an item.
        let (other_store, other_dir) = temp_store();
        let mut other =
            Session::sign_in(&other_store, server, &email, PASSWORD, None, None).unwrap();
        let mut item = CoreItem::new(ItemKind::SecureNote, None, None);
        item.name = "Added elsewhere".into();
        item.notes = "invented".into();
        std::thread::sleep(Duration::from_secs(2)); // Let the hub connect.
        let started = Instant::now();
        other.save(&other_store, &item).unwrap();

        // The worker syncs without being asked.
        wait_for(&events, Duration::from_secs(20), "live sync", |e| match e {
            Event::Synced { vault, .. } => vault
                .items
                .iter()
                .any(|i| i.name == "Added elsewhere")
                .then_some(()),
            _ => None,
        });
        eprintln!("live sync after {:?}", started.elapsed());

        // Removing the account stops the listener without hanging.
        let started = Instant::now();
        worker.tx.send(Command::Remove).unwrap();
        wait_for(&events, Duration::from_secs(10), "removal", |e| {
            matches!(e, Event::Removed).then_some(())
        });
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "stop took {:?}",
            started.elapsed()
        );
        let _ = std::fs::remove_dir_all(dir);
        let _ = std::fs::remove_dir_all(other_dir);
    }
}

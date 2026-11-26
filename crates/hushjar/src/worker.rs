//! One worker thread per account. It owns the account's session, runs
//! network and key-derivation work off the UI thread, and reports back with
//! [`Event`]s delivered on the Slint event loop.

use std::sync::Arc;
use std::sync::mpsc::{Receiver, Sender, channel};

use hushjar_core::api::{SecondFactor, Server, TwoFactorProvider};
use hushjar_core::session::{Session, SessionError};
use hushjar_core::store::{Profile, Store};
use hushjar_core::vault::{Item, Vault};
use zeroize::Zeroizing;

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
        std::thread::Builder::new()
            .name("hushjar-account".into())
            .spawn(move || run(store, profile, rx, emit))
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

fn run(
    store: Arc<Store>,
    mut profile: Option<Profile>,
    rx: Receiver<Command>,
    emit_to: impl Fn(String, Event),
) {
    let mut session: Option<Session> = None;

    // Brings an unlocked session online, signing in again with the password
    // when the stored tokens no longer work.
    let go_online =
        |session: &mut Session, password: Option<&str>, emit: &dyn Fn(Event)| match session
            .sync(&store)
        {
            Ok(()) => emit(Event::Synced {
                vault: session.vault.clone(),
                synced_at: session.synced_at,
            }),
            Err(SessionError::SignInRequired) => {
                match password.map(|p| session.reconnect(&store, p, None)) {
                    Some(Ok(())) => match session.sync(&store) {
                        Ok(()) => emit(Event::Synced {
                            vault: session.vault.clone(),
                            synced_at: session.synced_at,
                        }),
                        Err(e) => emit(Event::Failed {
                            message: describe(&e),
                        }),
                    },
                    Some(Err(SessionError::TwoFactorRequired(p))) => {
                        emit(Event::NeedsSignIn { two_factor: p })
                    }
                    _ => emit(Event::NeedsSignIn { two_factor: vec![] }),
                }
            }
            Err(e) => emit(Event::Failed {
                message: format!("Working offline: {}", describe(&e)),
            }),
        };

    for command in rx {
        // Events go out under the ID the account had when the command arrived,
        // so a finished sign-in still reaches the add-account form.
        let id = profile.as_ref().map(|p| p.id.clone()).unwrap_or_default();
        let emit = |event: Event| emit_to(id.clone(), event);
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
                        profile = Some(s.profile.clone());
                        emit(Event::SignedIn {
                            profile: Box::new(s.profile.clone()),
                            vault: s.vault.clone(),
                            synced_at: s.synced_at,
                        });
                        session = Some(s);
                    }
                    Err(SessionError::TwoFactorRequired(providers)) => {
                        emit(Event::TwoFactorRequired { providers })
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
                    Err(SessionError::TwoFactorRequired(p)) => {
                        emit(Event::NeedsSignIn { two_factor: p })
                    }
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
                        emit(Event::Synced {
                            vault: s.vault.clone(),
                            synced_at: s.synced_at,
                        });
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
                session = None;
                emit(Event::Locked);
            }
            Command::LogOut => {
                session = None;
                if let Some(p) = &profile {
                    let _ = store.forget_offline_copy(&p.id);
                }
                emit(Event::Locked);
            }
            Command::Remove => {
                drop(session.take());
                if let Some(p) = &profile {
                    let _ = store.remove(&p.id);
                }
                emit(Event::Removed);
                return;
            }
        }
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

//! One worker thread per account. It owns the account's session, runs
//! network and key-derivation work off the UI thread, and reports back with
//! [`Event`]s delivered on the Slint event loop.

use std::sync::Arc;
use std::sync::mpsc::{Receiver, Sender, channel};

use hushjar_core::api::{
    AuthRequest, Device, SecondFactor, Server, TwoFactorChallenge, TwoFactorProvider,
};
use hushjar_core::session::{Session, SessionError};
use hushjar_core::store::{Profile, Store};
use hushjar_core::vault::{Item, Vault};
use zeroize::Zeroizing;

mod login;

pub use login::{Second, SignInRequest};

pub enum Command {
    SignIn(Box<SignInRequest>),
    SendEmailCode {
        server: Server,
        email: String,
        password: Zeroizing<String>,
        /// The device signing in, so the code is asked for as that device.
        device: Option<Device>,
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
    /// Asks Bitwarden to email another new-device code; `second` is unused.
    ResendNewDeviceCode(Box<SignInRequest>),
    /// Starts logging in with another device.
    StartDeviceLogin {
        server: Server,
        email: String,
        device: Option<Device>,
    },
    /// Checks once whether the login request was answered.
    PollDeviceLogin,
    /// Finishes an approved device login that needs two-step login.
    FinishDeviceLogin {
        server: Server,
        second: Option<Second>,
    },
    CancelDeviceLogin,
    /// Fetches other devices' login requests for this unlocked account.
    CheckLoginRequests,
    AnswerLoginRequest {
        request: Box<AuthRequest>,
        approve: bool,
    },
    /// Sets a PIN; without `persist` it is kept in memory only.
    SetPin {
        pin: Zeroizing<String>,
        persist: bool,
    },
    RemovePin,
    UnlockWithPin {
        pin: Zeroizing<String>,
    },
    /// Reports the account's fingerprint phrase.
    AccountFingerprint,
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
        challenge: Box<TwoFactorChallenge>,
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
    /// Sign in again with the code Bitwarden emailed to confirm this device.
    NewDeviceRequired,
    /// Unlocking a logged-out account signed in online and needs two-step
    /// login (`challenge`) or a new-device code (`None`): continue on the
    /// sign-in form with the same password.
    UnlockNeedsSignIn {
        challenge: Option<Box<TwoFactorChallenge>>,
        password: Zeroizing<String>,
    },
    /// A login request went out; show `phrase` to compare.
    DeviceLoginStarted {
        phrase: String,
    },
    /// The login request is still waiting for an answer.
    DeviceLoginWaiting,
    /// The login request was denied or expired.
    DeviceLoginEnded {
        message: String,
    },
    /// Other devices' pending login requests with their fingerprint phrases.
    LoginRequests {
        requests: Vec<(String, AuthRequest)>,
    },
    LoginRequestAnswered {
        approved: bool,
    },
    /// Whether PIN unlock is set up: stored on disk, or held in memory.
    PinState {
        stored: bool,
        held: bool,
    },
    AccountFingerprint {
        phrase: String,
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
    let mut kept = login::Kept::default();
    if let Some(p) = &profile {
        emit_to(p.id.clone(), login::pin_state(&store, p, &kept));
    }

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

    for command in rx {
        // Events go out under the ID the account had when the command arrived,
        // so a finished sign-in still reaches the add-account form.
        let id = profile.as_ref().map(|p| p.id.clone()).unwrap_or_default();
        let emit = |event: Event| emit_to(id.clone(), event);
        match command {
            Command::SignIn(request) => {
                login::sign_in(&store, *request, &mut profile, &mut session, &emit)
            }
            Command::SendEmailCode {
                server,
                email,
                password,
                device,
            } => {
                let device = profile
                    .as_ref()
                    .map(|p| p.device.clone())
                    .or(device)
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
                            Err(e) => emit(login::unlock_sign_in_failed(e, &password)),
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
            Command::ResendNewDeviceCode(request) => {
                login::resend_new_device_code(&request, profile.as_ref(), &emit)
            }
            Command::StartDeviceLogin {
                server,
                email,
                device,
            } => login::start_device_login(
                server,
                &email,
                device,
                profile.as_ref(),
                &mut kept,
                &emit,
            ),
            Command::PollDeviceLogin => {
                login::poll_device_login(&store, &mut kept, &mut profile, &mut session, &emit)
            }
            Command::FinishDeviceLogin { server, second } => login::finish_device_login(
                &store,
                &server,
                second,
                &mut kept,
                &mut profile,
                &mut session,
                &emit,
            ),
            Command::CancelDeviceLogin => login::cancel_device_login(&mut kept),
            Command::CheckLoginRequests => login::check_login_requests(session.as_mut(), &emit),
            Command::AnswerLoginRequest { request, approve } => {
                login::answer_login_request(session.as_mut(), &request, approve, &emit)
            }
            Command::SetPin { pin, persist } => {
                login::set_pin(&store, session.as_ref(), &pin, persist, &mut kept, &emit)
            }
            Command::RemovePin => {
                if let Some(p) = &profile {
                    login::remove_pin(&store, p, &mut kept, &emit);
                }
            }
            Command::UnlockWithPin { pin } => {
                let Some(p) = profile.clone() else { continue };
                if let Some(mut s) = login::unlock_with_pin(&store, &p, &pin, &mut kept, &emit) {
                    emit(Event::Unlocked {
                        vault: s.vault.clone(),
                        synced_at: s.synced_at,
                    });
                    go_online(&mut s, None, &emit);
                    session = Some(s);
                }
            }
            Command::AccountFingerprint => login::account_fingerprint(session.as_ref(), &emit),
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

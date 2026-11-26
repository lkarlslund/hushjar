//! One worker thread per account. It owns the account's session, runs
//! network and key-derivation work off the UI thread, and reports back with
//! [`Event`]s delivered on the Slint event loop.

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::mpsc::{Receiver, RecvTimeoutError, Sender, channel};
use std::time::{Duration, Instant};

use hushjar_core::api::{
    AuthRequest, Device, SecondFactor, Server, TwoFactorChallenge, TwoFactorProvider,
};
use hushjar_core::exchange::ExchangeError;
use hushjar_core::exchange::export::Scope;
use hushjar_core::exchange::import::{Format, ImportSummary, ParsedImport};
use hushjar_core::notifications::{Listener, Notification};
use hushjar_core::policy::Policies;
use hushjar_core::send::SendEntry;
use hushjar_core::session::{Session, SessionError};
use hushjar_core::store::{Profile, Store};
use hushjar_core::vault::{Item, Vault};
use zeroize::Zeroizing;

mod login;

pub use login::{Second, SignInRequest};

use crate::exchange::{ExportFormat, ExportScope};
use crate::pacing::{Debounce, WATCH_EVERY, Watch};

/// How long the notification listener waits for the worker to hand over a
/// fresh access token (the worker may be in the middle of a long sync).
const TOKEN_WAIT: Duration = Duration::from_secs(30);

mod items;

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
    /// Hands the user key to the app, for unlocking with system authentication.
    ExportUserKey,
    /// Unlocks with a user key the app kept (system authentication).
    UnlockWithUserKey(Zeroizing<Vec<u8>>),
    /// Checks the master password, for actions that ask for it again.
    VerifyPassword {
        password: Zeroizing<String>,
    },
    /// Writes an export file to `path`.
    Export {
        scope: ExportScope,
        format: ExportFormat,
        /// The file password of a password-protected export.
        password: Option<Zeroizing<String>>,
        path: PathBuf,
    },
    ParseImport {
        bytes: Zeroizing<Vec<u8>>,
        format: Option<Format>,
        /// The password of a protected import file.
        password: Option<Zeroizing<String>>,
    },
    Import {
        parsed: Box<ParsedImport>,
    },
    /// Saves a text Send, or the settings of a file Send. A new Send is
    /// posted once and never retried. `remove_password` clears the access
    /// password after the save.
    SaveSend {
        send: Box<SendEntry>,
        password: Option<Zeroizing<String>>,
        remove_password: bool,
    },
    /// Creates a file Send and uploads the file.
    CreateFileSend {
        send: Box<SendEntry>,
        file_name: String,
        bytes: Zeroizing<Vec<u8>>,
        password: Option<Zeroizing<String>>,
    },
    DeleteSend(String),
    /// From the notification listener: asks for a current access token.
    /// Answered with `None` when there is no session or no token to be had.
    Token(Sender<Option<Zeroizing<String>>>),
    /// From the notification listener: something the server announced.
    Remote(Notification),
    // Item and folder actions; see `items`.
    Archive(String),
    Unarchive(String),
    RemovePasskey {
        item: String,
        credential: String,
    },
    MoveToOrganization {
        item: String,
        organization: String,
        collections: Vec<String>,
    },
    SetCollections {
        item: String,
        collections: Vec<String>,
    },
    RenameFolder {
        id: String,
        name: String,
    },
    /// Renames a folder and the folders nested in it.
    RenameFolderTree {
        old: String,
        new: String,
    },
    DeleteFolder(String),
    /// Downloads an attachment and writes it, readable by its owner only,
    /// to `path`; `open` is passed back so the UI can open it.
    DownloadAttachment {
        item: String,
        attachment: String,
        path: PathBuf,
        open: bool,
    },
    /// Reads the file at `path` and attaches it to the item.
    AddAttachment {
        item: String,
        path: PathBuf,
    },
    DeleteAttachment {
        item: String,
        attachment: String,
    },
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
    /// `offline_copy` says whether there is an offline copy for the PIN to
    /// open (after logging out there is none), when the worker looked.
    PinState {
        stored: bool,
        held: bool,
        offline_copy: Option<bool>,
    },
    /// The account's user key, for system authentication.
    UserKey(Zeroizing<Vec<u8>>),
    AccountFingerprint {
        phrase: String,
    },
    /// The master password was right.
    PasswordVerified,
    /// The master password was wrong.
    PasswordRejected,
    Exported {
        path: PathBuf,
    },
    ImportParsed {
        parsed: Box<ParsedImport>,
    },
    /// The import file needs its password (`wrong`: the one given failed).
    ImportPasswordNeeded {
        wrong: bool,
    },
    Imported {
        summary: ImportSummary,
        vault: Vault,
    },
    /// An export or import step failed; the message is for the transfer pane.
    TransferFailed {
        message: String,
    },
    /// A Send was saved. `link` is its share link (it carries the key).
    SendSaved {
        send: Box<SendEntry>,
        vault: Vault,
        link: Option<Zeroizing<String>>,
    },
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
    /// An item or folder action finished; the message is for a toast.
    ItemActionDone {
        vault: Vault,
        message: String,
    },
    /// An item or folder action failed. An empty message has already been
    /// explained (for example by [`Event::NeedsSignIn`]).
    ItemActionFailed {
        message: String,
    },
    AttachmentWritten {
        path: PathBuf,
        open: bool,
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
    let mut kept = login::Kept::default();
    if let Some(p) = &profile {
        let offline_copy = store.read_cache(&p.id).is_ok();
        emit_to(
            p.id.clone(),
            login::pin_state(&store, p, &kept, Some(offline_copy)),
        );
    }
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
            Command::SignIn(request) => {
                let done = login::sign_in(&store, *request, &mut profile, &mut session, &emit);
                after_sign_in(done, &session, &mut live, &emit_to);
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
                if let Some(p) = &profile {
                    emit(login::pin_state(&store, p, &kept, Some(false)));
                }
            }
            Command::VerifyPassword { password } => emit(verify_password(&profile, &password)),
            Command::Export {
                scope,
                format,
                password,
                path,
            } => emit(export_file(
                session.as_ref(),
                &scope,
                format,
                password,
                &path,
            )),
            Command::ParseImport {
                bytes,
                format,
                password,
            } => emit(parse_import(session.as_ref(), &bytes, format, password)),
            Command::Import { parsed } => import_items(&mut session, &store, &emit, &parsed),
            Command::SaveSend {
                send,
                password,
                remove_password,
            } => {
                let Some(s) = session.as_mut() else { continue };
                let result = s
                    .save_send(&store, &send, password.as_ref().map(|p| p.as_str()))
                    .and_then(|saved| {
                        if remove_password && password.is_none() && saved.has_password {
                            s.remove_send_password(&store, &saved.id)
                        } else {
                            Ok(saved)
                        }
                    });
                finish_send(s, &store, &emit, result);
            }
            Command::CreateFileSend {
                send,
                file_name,
                bytes,
                password,
            } => {
                let Some(s) = session.as_mut() else { continue };
                let result = s.create_file_send(
                    &store,
                    &send,
                    &file_name,
                    &bytes,
                    password.as_ref().map(|p| p.as_str()),
                );
                finish_send(s, &store, &emit, result);
            }
            Command::DeleteSend(id) => {
                change(&mut session, &store, &emit, "Send deleted", |s, st| {
                    s.delete_send(st, &id)
                })
            }
            command @ (Command::Archive(_)
            | Command::Unarchive(_)
            | Command::RemovePasskey { .. }
            | Command::MoveToOrganization { .. }
            | Command::SetCollections { .. }
            | Command::RenameFolder { .. }
            | Command::RenameFolderTree { .. }
            | Command::DeleteFolder(_)
            | Command::DownloadAttachment { .. }
            | Command::AddAttachment { .. }
            | Command::DeleteAttachment { .. }) => {
                items::run(session.as_mut(), &store, &emit, command)
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
                let done =
                    login::poll_device_login(&store, &mut kept, &mut profile, &mut session, &emit);
                after_sign_in(done, &session, &mut live, &emit_to);
            }
            Command::FinishDeviceLogin { server, second } => {
                let done = login::finish_device_login(
                    &store,
                    &server,
                    second,
                    &mut kept,
                    &mut profile,
                    &mut session,
                    &emit,
                );
                after_sign_in(done, &session, &mut live, &emit_to);
            }
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
                    live.stop();
                    emit(Event::Policies(Box::new(s.policies())));
                    emit(Event::Unlocked {
                        vault: s.vault.clone(),
                        synced_at: s.synced_at,
                    });
                    go_online(&mut s, None, &emit);
                    session = Some(s);
                }
            }
            Command::AccountFingerprint => login::account_fingerprint(session.as_ref(), &emit),
            Command::ExportUserKey => {
                if let Some(s) = &session {
                    emit(Event::UserKey(s.export_user_key()));
                }
            }
            Command::UnlockWithUserKey(key) => {
                let Some(p) = profile.clone() else { continue };
                match Session::unlock_with_user_key(&store, &p, &key) {
                    Ok(mut s) => {
                        live.stop();
                        emit(Event::Policies(Box::new(s.policies())));
                        emit(Event::Unlocked {
                            vault: s.vault.clone(),
                            synced_at: s.synced_at,
                        });
                        go_online(&mut s, None, &emit);
                        session = Some(s);
                    }
                    Err(e) => emit(Event::Failed {
                        message: describe(&e),
                    }),
                }
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

/// After a sign-in: the previous live connection goes, and the account's
/// policies go out under its own ID (the app has created the account by the
/// time they arrive).
fn after_sign_in(
    signed_in: bool,
    session: &Option<Session>,
    live: &mut Live,
    emit_to: &dyn Fn(String, Event),
) {
    if let (true, Some(s)) = (signed_in, session) {
        live.stop();
        emit_to(
            s.profile.id.clone(),
            Event::Policies(Box::new(s.policies())),
        );
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
fn failed(message: impl Into<String>) -> Event {
    Event::TransferFailed {
        message: message.into(),
    }
}

/// Derives the key from the master password and tries to open the account's
/// user key with it, as unlocking does.
fn verify_password(profile: &Option<Profile>, password: &str) -> Event {
    let Some(p) = profile else {
        return Event::PasswordRejected;
    };
    let opened = hushjar_core::crypto::master_key(password, &p.email, p.kdf)
        .ok()
        .and_then(|master| {
            hushjar_core::crypto::stretch(&master)
                .unwrap_key(&p.encrypted_user_key)
                .ok()
        });
    if opened.is_some() {
        Event::PasswordVerified
    } else {
        Event::PasswordRejected
    }
}

fn export_text(
    session: &Session,
    scope: &ExportScope,
    format: ExportFormat,
    password: Option<&str>,
) -> Result<Zeroizing<String>, ExchangeError> {
    let scope = match scope {
        ExportScope::Personal => Scope::Personal,
        ExportScope::Organization(id) => Scope::Organization(id),
    };
    match format {
        ExportFormat::Json => session.export_json(scope),
        ExportFormat::EncryptedJson => session.export_encrypted_json(scope),
        ExportFormat::PasswordProtectedJson => {
            session.export_password_protected_json(scope, password.unwrap_or_default())
        }
        ExportFormat::Csv => session.export_csv(scope),
    }
}

fn export_file(
    session: Option<&Session>,
    scope: &ExportScope,
    format: ExportFormat,
    password: Option<Zeroizing<String>>,
    path: &std::path::Path,
) -> Event {
    let Some(session) = session else {
        return failed("Unlock the account first");
    };
    let text = match export_text(
        session,
        scope,
        format,
        password.as_deref().map(String::as_str),
    ) {
        Ok(text) => text,
        Err(e) => return failed(e.to_string()),
    };
    match crate::exchange::write_private(path, text.as_bytes()) {
        Ok(()) => Event::Exported {
            path: path.to_path_buf(),
        },
        Err(e) => failed(format!("Could not write the file: {e}")),
    }
}

fn parse_import(
    session: Option<&Session>,
    bytes: &[u8],
    format: Option<Format>,
    password: Option<Zeroizing<String>>,
) -> Event {
    let Some(session) = session else {
        return failed("Unlock the account first");
    };
    let Ok(text) = std::str::from_utf8(bytes) else {
        return failed("This is not a text file, so it cannot be imported");
    };
    let text = text.trim_start_matches('\u{feff}');
    let given = password.is_some();
    match session.parse_import(text, format, password.as_deref().map(String::as_str)) {
        Ok(parsed) => Event::ImportParsed {
            parsed: Box::new(parsed),
        },
        Err(ExchangeError::PasswordRequired) => Event::ImportPasswordNeeded { wrong: false },
        Err(ExchangeError::WrongPassword) if given => Event::ImportPasswordNeeded { wrong: true },
        Err(e) => failed(e.to_string()),
    }
}

fn import_items(
    session: &mut Option<Session>,
    store: &Store,
    emit: &dyn Fn(Event),
    parsed: &ParsedImport,
) {
    let Some(s) = session.as_mut() else { return };
    match s.import(store, parsed) {
        Ok(summary) => emit(Event::Imported {
            summary,
            vault: s.vault.clone(),
        }),
        Err(SessionError::SaveUncertain) => {
            let _ = s.sync(store);
            emit(Event::Synced {
                vault: s.vault.clone(),
                synced_at: s.synced_at,
            });
            emit(failed(describe(&SessionError::SaveUncertain)));
        }
        Err(SessionError::SignInRequired) => emit(Event::NeedsSignIn { two_factor: vec![] }),
        Err(e) => emit(failed(describe(&e))),
    }
}

/// Reports the result of saving a Send. A lost reply is not retried: the
/// vault is synced so the list shows whether the Send arrived.
fn finish_send(
    s: &mut Session,
    store: &Store,
    emit: &dyn Fn(Event),
    result: Result<SendEntry, SessionError>,
) {
    match result {
        Ok(saved) => {
            let link = s.send_link(&saved).map(Zeroizing::new);
            emit(Event::SendSaved {
                send: Box::new(saved),
                vault: s.vault.clone(),
                link,
            });
        }
        Err(SessionError::SaveUncertain) => {
            let message = describe(&SessionError::SaveUncertain);
            let _ = s.sync(store);
            emit(Event::SaveUncertain { message });
            emit(Event::Synced {
                vault: s.vault.clone(),
                synced_at: s.synced_at,
            });
        }
        Err(SessionError::SignInRequired) => emit(Event::NeedsSignIn { two_factor: vec![] }),
        Err(e) => emit(Event::Failed {
            message: describe(&e),
        }),
    }
}

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
            .send(Command::SignIn(Box::new(SignInRequest {
                server: server.clone(),
                email: email.clone(),
                password: Zeroizing::new(PASSWORD.into()),
                second: None,
                new_device_code: None,
                device: None,
            })))
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

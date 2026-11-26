//! Sign-in work for the account worker: second factors (including a USB
//! security key), new-device codes, logging in with another device,
//! approving other devices' logins, PIN unlock and the account fingerprint.

use hushjar_core::api::{AuthRequest, Device, SecondFactor, Server, TwoFactorProvider};
use hushjar_core::crypto::normalize_email;
use hushjar_core::fingerprint;
use hushjar_core::session::{
    DeviceLogin, DeviceLoginStatus, PinUnlock, Session, SessionError, SignInOptions,
    request_public_key,
};
use hushjar_core::store::{Profile, Store};
use hushjar_core::webauthn::{self, Cancel, WebAuthnError};
use serde_json::Value;
use zeroize::Zeroizing;

use super::{Event, describe};

/// The second step of a two-step login.
pub enum Second {
    /// A typed code: the method, the code, and whether to remember this
    /// device.
    Code(TwoFactorProvider, String, bool),
    /// Asks the USB security key, with the server's WebAuthn options. The
    /// worker waits until the key is touched, it times out, or `cancel` is
    /// triggered from the UI.
    SecurityKey {
        options: Value,
        remember: bool,
        cancel: Cancel,
    },
}

/// One attempt at a password sign-in.
pub struct SignInRequest {
    pub server: Server,
    pub email: String,
    pub password: Zeroizing<String>,
    pub second: Option<Second>,
    /// The emailed code after [`Event::NewDeviceRequired`].
    pub new_device_code: Option<String>,
    /// The device a new account signs in as. The UI keeps it the same
    /// across the retries of one sign-in, since new-device codes and
    /// remembered two-step logins are tied to it.
    pub device: Option<Device>,
}

/// What a worker keeps between commands besides the session.
#[derive(Default)]
pub(super) struct Kept {
    /// A login request this device made, until it is answered.
    device_login: Option<DeviceLogin>,
    /// PIN unlock kept only in memory ("ask for the master password after
    /// a restart").
    held_pin: Option<PinUnlock>,
}

/// A second factor ready to send.
struct Factor {
    provider: TwoFactorProvider,
    token: Zeroizing<String>,
    remember: bool,
}

impl Factor {
    fn second(&self) -> SecondFactor<'_> {
        SecondFactor {
            provider: self.provider,
            token: self.token.trim(),
            remember: self.remember,
        }
    }
}

/// Turns the UI's choice into a token, asking the security key if needed.
fn resolve(second: Option<Second>, server: &Server) -> Result<Option<Factor>, WebAuthnError> {
    Ok(match second {
        None => None,
        Some(Second::Code(provider, code, remember)) => Some(Factor {
            provider,
            token: Zeroizing::new(code),
            remember,
        }),
        Some(Second::SecurityKey {
            options,
            remember,
            cancel,
        }) => {
            let key = webauthn::usb_key()?;
            let token = webauthn::sign(&options, server, &*key, &cancel)?;
            Some(Factor {
                provider: TwoFactorProvider::WebAuthn,
                token,
                remember,
            })
        }
    })
}

/// Reports a finished sign-in attempt and keeps the session on success.
fn report(
    result: Result<Session, SessionError>,
    profile: &mut Option<Profile>,
    session: &mut Option<Session>,
    emit: &dyn Fn(Event),
) {
    match result {
        Ok(s) => {
            *profile = Some(s.profile.clone());
            emit(Event::SignedIn {
                profile: Box::new(s.profile.clone()),
                vault: s.vault.clone(),
                synced_at: s.synced_at,
            });
            *session = Some(s);
        }
        Err(SessionError::TwoFactorRequired(challenge)) => emit(Event::TwoFactorRequired {
            challenge: Box::new(challenge),
        }),
        Err(SessionError::NewDeviceVerificationRequired) => emit(Event::NewDeviceRequired),
        Err(e) => emit(Event::Failed {
            message: describe(&e),
        }),
    }
}

/// Signs in with a password, a second factor and a new-device code as
/// given. A saved account (`profile`) keeps its own device.
pub(super) fn sign_in(
    store: &Store,
    request: SignInRequest,
    profile: &mut Option<Profile>,
    session: &mut Option<Session>,
    emit: &dyn Fn(Event),
) {
    let SignInRequest {
        server,
        email,
        password,
        second,
        new_device_code,
        device,
    } = request;
    let factor = match resolve(second, &server) {
        Ok(factor) => factor,
        Err(e) => {
            return emit(Event::Failed {
                message: e.to_string(),
            });
        }
    };
    let options = SignInOptions {
        second: factor.as_ref().map(Factor::second),
        new_device_code: new_device_code
            .as_deref()
            .map(str::trim)
            .filter(|c| !c.is_empty()),
        device: device.as_ref(),
    };
    let result = Session::sign_in_with(store, server, &email, &password, options, profile.as_ref());
    report(result, profile, session, emit);
}

/// Asks for another new-device code, as the same device.
pub(super) fn resend_new_device_code(
    request: &SignInRequest,
    profile: Option<&Profile>,
    emit: &dyn Fn(Event),
) {
    let device = profile
        .map(|p| p.device.clone())
        .or_else(|| request.device.clone())
        .unwrap_or_default();
    match Session::resend_new_device_code(
        &request.server,
        &request.email,
        &request.password,
        &device,
    ) {
        Ok(()) => emit(Event::EmailSent),
        Err(e) => emit(Event::Failed {
            message: describe(&e),
        }),
    }
}

/// What the locked pane should do when signing in for a logged-out account
/// stopped: continue on the sign-in form, or show the error.
pub(super) fn unlock_sign_in_failed(error: SessionError, password: &Zeroizing<String>) -> Event {
    match error {
        SessionError::TwoFactorRequired(challenge) => Event::UnlockNeedsSignIn {
            challenge: Some(Box::new(challenge)),
            password: password.clone(),
        },
        SessionError::NewDeviceVerificationRequired => Event::UnlockNeedsSignIn {
            challenge: None,
            password: password.clone(),
        },
        e => Event::Failed {
            message: describe(&e),
        },
    }
}

/// Explains a failed login request. Vaultwarden only takes requests from a
/// device that has signed in to the account before.
fn device_login_error(error: &SessionError) -> String {
    match error {
        SessionError::Api(_) => format!(
            "Could not ask your other devices ({}). The server may only allow \
             this from a computer that has signed in to this account before: \
             sign in with your master password once first.",
            describe(error)
        ),
        other => describe(other),
    }
}

/// Starts logging in with another device and reports the fingerprint
/// phrase to compare.
pub(super) fn start_device_login(
    server: Server,
    email: &str,
    device: Option<Device>,
    profile: Option<&Profile>,
    kept: &mut Kept,
    emit: &dyn Fn(Event),
) {
    match Session::start_device_login(server, email, device.as_ref(), profile) {
        Ok(request) => {
            let phrase =
                fingerprint::phrase(request.fingerprint_material(), request.public_key_der());
            kept.device_login = Some(request);
            emit(Event::DeviceLoginStarted { phrase });
        }
        Err(e) => emit(Event::Failed {
            message: device_login_error(&e),
        }),
    }
}

/// Checks the login request once; signs in when it was approved.
pub(super) fn poll_device_login(
    store: &Store,
    kept: &mut Kept,
    profile: &mut Option<Profile>,
    session: &mut Option<Session>,
    emit: &dyn Fn(Event),
) {
    let Some(request) = kept.device_login.as_mut() else {
        return;
    };
    let ended = |message: &str| Event::DeviceLoginEnded {
        message: message.into(),
    };
    match request.poll() {
        Ok(DeviceLoginStatus::Pending) => emit(Event::DeviceLoginWaiting),
        Ok(DeviceLoginStatus::Approved) => {
            let result = Session::finish_device_login(store, request, None, profile.as_ref());
            if result.is_ok() {
                kept.device_login = None;
            }
            report(result, profile, session, emit);
        }
        Ok(DeviceLoginStatus::Denied) => {
            kept.device_login = None;
            emit(ended("The login request was denied on the other device."));
        }
        Ok(DeviceLoginStatus::Expired) => {
            kept.device_login = None;
            emit(ended(
                "The login request expired. Start again to send a new one.",
            ));
        }
        // A network hiccup: keep waiting, the next poll may work.
        Err(e) => emit(Event::Failed {
            message: describe(&e),
        }),
    }
}

/// Finishes an approved device login that also needs two-step login.
pub(super) fn finish_device_login(
    store: &Store,
    server: &Server,
    second: Option<Second>,
    kept: &mut Kept,
    profile: &mut Option<Profile>,
    session: &mut Option<Session>,
    emit: &dyn Fn(Event),
) {
    let Some(request) = kept.device_login.as_ref() else {
        return emit(Event::DeviceLoginEnded {
            message: "The login request is gone. Start again.".into(),
        });
    };
    let factor = match resolve(second, server) {
        Ok(factor) => factor,
        Err(e) => {
            return emit(Event::Failed {
                message: e.to_string(),
            });
        }
    };
    let result = Session::finish_device_login(
        store,
        request,
        factor.as_ref().map(Factor::second),
        profile.as_ref(),
    );
    if result.is_ok() {
        kept.device_login = None;
    }
    report(result, profile, session, emit);
}

pub(super) fn cancel_device_login(kept: &mut Kept) {
    kept.device_login = None;
}

/// Fetches other devices' login requests with their fingerprint phrases.
/// Reports the list even when empty, so the app can drop requests that
/// were answered elsewhere; stays quiet when the account is offline.
pub(super) fn check_login_requests(session: Option<&mut Session>, emit: &dyn Fn(Event)) {
    let Some(s) = session else { return };
    let Ok(list) = s.pending_login_requests() else {
        return;
    };
    let email = normalize_email(&s.profile.email);
    let requests = list
        .into_iter()
        .filter_map(|r| {
            let der = request_public_key(&r).ok()?;
            Some((fingerprint::phrase(&email, &der), r))
        })
        .collect();
    emit(Event::LoginRequests { requests });
}

pub(super) fn answer_login_request(
    session: Option<&mut Session>,
    request: &AuthRequest,
    approve: bool,
    emit: &dyn Fn(Event),
) {
    let Some(s) = session else {
        return emit(Event::Failed {
            message: "Unlock the account to answer the login request".into(),
        });
    };
    match s.answer_login_request(request, approve) {
        Ok(()) => emit(Event::LoginRequestAnswered { approved: approve }),
        Err(e) => emit(Event::Failed {
            message: describe(&e),
        }),
    }
}

/// Whether PIN unlock is set up, on disk or in memory.
pub(super) fn pin_state(store: &Store, profile: &Profile, kept: &Kept) -> Event {
    Event::PinState {
        stored: Session::has_stored_pin(store, profile),
        held: kept.held_pin.is_some(),
    }
}

/// Sets a PIN. Without `persist` it lives only in this worker's memory.
pub(super) fn set_pin(
    store: &Store,
    session: Option<&Session>,
    pin: &str,
    persist: bool,
    kept: &mut Kept,
    emit: &dyn Fn(Event),
) {
    let Some(s) = session else {
        return emit(Event::Failed {
            message: "Unlock the account to set a PIN".into(),
        });
    };
    match s.enable_pin(store, pin, persist) {
        Ok(unlock) => {
            kept.held_pin = (!persist).then_some(unlock);
            emit(pin_state(store, &s.profile, kept));
        }
        Err(e) => emit(Event::Failed {
            message: describe(&e),
        }),
    }
}

pub(super) fn remove_pin(store: &Store, profile: &Profile, kept: &mut Kept, emit: &dyn Fn(Event)) {
    kept.held_pin = None;
    if let Err(e) = Session::disable_pin(store, profile) {
        emit(Event::Failed {
            message: describe(&e),
        });
    }
    emit(pin_state(store, profile, kept));
}

/// The message for a wrong PIN.
pub(crate) fn wrong_pin_message(attempts_left: u32) -> String {
    match attempts_left {
        1 => "Wrong PIN. 1 try left before PIN unlock turns off.".into(),
        n => format!("Wrong PIN. {n} tries left."),
    }
}

/// Unlocks with a PIN. Returns the session, or reports why not.
pub(super) fn unlock_with_pin(
    store: &Store,
    profile: &Profile,
    pin: &str,
    kept: &mut Kept,
    emit: &dyn Fn(Event),
) -> Option<Session> {
    let failed = |message: String| emit(Event::Failed { message });
    match Session::unlock_with_pin(store, profile, pin, kept.held_pin.as_mut()) {
        Ok(s) => return Some(s),
        Err(SessionError::WrongPin { attempts_left }) => failed(wrong_pin_message(attempts_left)),
        Err(SessionError::PinUnavailable) => {
            kept.held_pin = None;
            emit(pin_state(store, profile, kept));
            failed("PIN unlock is off now. Unlock with your master password.".into());
        }
        Err(SessionError::NoOfflineCopy) => {
            failed("This account is logged out. Unlock with your master password.".into())
        }
        Err(e) => failed(describe(&e)),
    }
    None
}

/// The account's fingerprint phrase, from its ID and public key. Empty for
/// an account without a key pair.
pub(super) fn account_fingerprint(session: Option<&Session>, emit: &dyn Fn(Event)) {
    let Some(s) = session else { return };
    let phrase = s
        .account_public_key()
        .map(|der| fingerprint::phrase(s.user_id(), &der))
        .unwrap_or_default();
    emit(Event::AccountFingerprint { phrase });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wrong_pin_counts_down() {
        assert_eq!(wrong_pin_message(4), "Wrong PIN. 4 tries left.");
        assert!(wrong_pin_message(1).contains("1 try left"));
    }

    #[test]
    fn typed_codes_need_no_key() {
        let server = Server::parse("http://127.0.0.1:1").unwrap();
        let factor = resolve(
            Some(Second::Code(
                TwoFactorProvider::YubiKey,
                " cccc ".into(),
                true,
            )),
            &server,
        )
        .unwrap()
        .unwrap();
        let second = factor.second();
        assert_eq!(second.token, "cccc");
        assert_eq!(second.provider, TwoFactorProvider::YubiKey);
        assert!(second.remember);
        assert!(resolve(None, &server).unwrap().is_none());
    }

    #[test]
    fn unusable_key_options_fail_before_asking_a_key() {
        let server = Server::parse("http://127.0.0.1:1").unwrap();
        let cancel = Cancel::new();
        cancel.cancel();
        // Options without allowed keys are refused before any device is asked.
        let result = resolve(
            Some(Second::SecurityKey {
                options: serde_json::json!({ "challenge": "AAAA" }),
                remember: false,
                cancel,
            }),
            &server,
        );
        assert!(result.is_err());
    }

    #[test]
    fn logged_out_unlock_moves_to_the_sign_in_form() {
        let password = Zeroizing::new("pw".to_string());
        let event = unlock_sign_in_failed(SessionError::NewDeviceVerificationRequired, &password);
        assert!(matches!(
            event,
            Event::UnlockNeedsSignIn { challenge: None, ref password } if password.as_str() == "pw"
        ));
        let event = unlock_sign_in_failed(SessionError::WrongPassword, &password);
        assert!(matches!(event, Event::Failed { .. }));
    }
}

/// Runs the worker's sign-in commands against a Vaultwarden test server
/// (set HUSHJAR_INTEROP), with invented accounts.
#[cfg(test)]
mod interop {
    use std::sync::Arc;
    use std::sync::mpsc::{Receiver, channel};
    use std::time::Duration;

    use hushjar_core::crypto::{self, HashPurpose, Kdf, SymmetricKey};
    use serde_json::json;

    use super::*;
    use crate::worker::{Command, Worker};

    const PASSWORD: &str = "invented interop password";
    const KDF: Kdf = Kdf::Pbkdf2 {
        iterations: 600_000,
    };

    fn server() -> Option<String> {
        let url = std::env::var("HUSHJAR_INTEROP").ok();
        if url.is_none() {
            eprintln!("skipped: set HUSHJAR_INTEROP to a Vaultwarden test server");
        }
        url
    }

    fn random_hex() -> String {
        let mut bytes = [0u8; 12];
        getrandom::fill(&mut bytes).unwrap();
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    fn register(base: &str, email: &str) {
        let master = crypto::master_key(PASSWORD, email, KDF).unwrap();
        let hash = crypto::password_hash(&master, PASSWORD, HashPurpose::Server);
        let wrapped = crypto::stretch(&master).wrap_key(&SymmetricKey::generate());
        let Kdf::Pbkdf2 { iterations } = KDF else {
            unreachable!()
        };
        let response = ureq::post(format!("{base}/identity/accounts/register"))
            .send_json(json!({
                "email": email,
                "name": "Hushjar app interop test",
                "masterPasswordHash": hash.as_str(),
                "key": wrapped,
                "kdf": 0,
                "kdfIterations": iterations,
            }))
            .unwrap();
        assert_eq!(response.status().as_u16(), 200, "registration failed");
    }

    fn store() -> Arc<Store> {
        let dir = std::env::temp_dir().join(format!("hushjar-app-interop-{}", random_hex()));
        Arc::new(Store::open(dir).unwrap())
    }

    fn worker(store: Arc<Store>) -> (Worker, Receiver<Event>) {
        let (tx, rx) = channel();
        let worker = Worker::spawn(store, None, move |_, event| {
            let _ = tx.send(event);
        });
        (worker, rx)
    }

    /// Waits for the first event `wanted` accepts, failing on `Failed`.
    fn wait(rx: &Receiver<Event>, what: &str, wanted: impl Fn(&Event) -> bool) -> Event {
        loop {
            let event = rx
                .recv_timeout(Duration::from_secs(60))
                .unwrap_or_else(|_| panic!("no {what} event"));
            if let Event::Failed { message } = &event {
                panic!("waiting for {what}: {message}");
            }
            if wanted(&event) {
                return event;
            }
        }
    }

    fn failure(rx: &Receiver<Event>) -> String {
        loop {
            match rx.recv_timeout(Duration::from_secs(60)) {
                Ok(Event::Failed { message }) => return message,
                Ok(_) => {}
                Err(_) => panic!("no failure event"),
            }
        }
    }

    fn sign_in(worker: &Worker, server: &Server, email: &str, device: &Device) {
        let _ = worker.tx.send(Command::SignIn(Box::new(SignInRequest {
            server: server.clone(),
            email: email.into(),
            password: Zeroizing::new(PASSWORD.into()),
            second: None,
            new_device_code: None,
            device: Some(device.clone()),
        })));
    }

    fn signed_in(event: &Event) -> bool {
        matches!(event, Event::SignedIn { .. })
    }

    #[test]
    fn approves_a_device_login_and_unlocks_with_a_pin() {
        let Some(base) = server() else { return };
        let email = format!("app-device-{}@example.invalid", random_hex());
        register(&base, &email);
        let server = Server::parse(&base).unwrap();

        // The approving account, and a second device that signed in once
        // (Vaultwarden takes login requests only from known devices).
        let (a, a_events) = worker(store());
        sign_in(&a, &server, &email, &Device::new());
        wait(&a_events, "sign-in", signed_in);
        let known = Device::new();
        let (b, b_events) = worker(store());
        sign_in(&b, &server, &email, &known);
        wait(&b_events, "second sign-in", signed_in);
        drop(b);

        // A device the server has not seen is turned away, with a hint.
        let (d, d_events) = worker(store());
        let _ = d.tx.send(Command::StartDeviceLogin {
            server: server.clone(),
            email: email.clone(),
            device: Some(Device::new()),
        });
        let message = failure(&d_events);
        assert!(
            message.contains("signed in to this account before"),
            "{message}"
        );

        // Log in with a device from the known device.
        let (c, c_events) = worker(store());
        let _ = c.tx.send(Command::StartDeviceLogin {
            server: server.clone(),
            email: email.to_uppercase(),
            device: Some(known),
        });
        let Event::DeviceLoginStarted { phrase } = wait(&c_events, "login request", |e| {
            matches!(e, Event::DeviceLoginStarted { .. })
        }) else {
            unreachable!()
        };
        let _ = c.tx.send(Command::PollDeviceLogin);
        wait(&c_events, "pending", |e| {
            matches!(e, Event::DeviceLoginWaiting)
        });

        // The approving side sees the same phrase.
        let _ = a.tx.send(Command::CheckLoginRequests);
        let Event::LoginRequests { requests } = wait(&a_events, "requests", |e| {
            matches!(e, Event::LoginRequests { .. })
        }) else {
            unreachable!()
        };
        let (shown, request) = requests.into_iter().next().expect("a pending request");
        assert_eq!(shown, phrase);
        let _ = a.tx.send(Command::AnswerLoginRequest {
            request: Box::new(request),
            approve: true,
        });
        wait(&a_events, "answer", |e| {
            matches!(e, Event::LoginRequestAnswered { approved: true })
        });
        let _ = c.tx.send(Command::PollDeviceLogin);
        wait(&c_events, "device sign-in", signed_in);

        // PIN unlock, stored and then held in memory.
        let _ = a.tx.send(Command::SetPin {
            pin: Zeroizing::new("2468".into()),
            persist: true,
        });
        wait(&a_events, "stored PIN", |e| {
            matches!(
                e,
                Event::PinState {
                    stored: true,
                    held: false
                }
            )
        });
        let _ = a.tx.send(Command::Lock);
        wait(&a_events, "lock", |e| matches!(e, Event::Locked));
        let _ = a.tx.send(Command::UnlockWithPin {
            pin: Zeroizing::new("0000".into()),
        });
        assert_eq!(failure(&a_events), wrong_pin_message(4));
        let _ = a.tx.send(Command::UnlockWithPin {
            pin: Zeroizing::new("2468".into()),
        });
        wait(&a_events, "PIN unlock", |e| {
            matches!(e, Event::Unlocked { .. })
        });
        let _ = a.tx.send(Command::SetPin {
            pin: Zeroizing::new("1357".into()),
            persist: false,
        });
        wait(&a_events, "held PIN", |e| {
            matches!(
                e,
                Event::PinState {
                    stored: false,
                    held: true
                }
            )
        });
        let _ = a.tx.send(Command::Lock);
        wait(&a_events, "lock", |e| matches!(e, Event::Locked));
        let _ = a.tx.send(Command::UnlockWithPin {
            pin: Zeroizing::new("1357".into()),
        });
        wait(&a_events, "held PIN unlock", |e| {
            matches!(e, Event::Unlocked { .. })
        });
        let _ = a.tx.send(Command::RemovePin);
        wait(&a_events, "no PIN", |e| {
            matches!(
                e,
                Event::PinState {
                    stored: false,
                    held: false
                }
            )
        });
    }
}

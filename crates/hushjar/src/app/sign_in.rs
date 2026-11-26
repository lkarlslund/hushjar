//! The add-account and sign-in form: the master password, two-step login
//! (authenticator app, email, YubiKey, security key), the code that confirms
//! a new device, and logging in with another device. It also finishes
//! signing in for a logged-out account whose unlock needed more than the
//! password.

use std::sync::mpsc::Sender;

use super::*;
use crate::SignInData;
use crate::worker::{Second, SignInRequest};

/// Form stages, as `SignInForm.stage` numbers them.
pub(super) const CREDENTIALS: i32 = 0;
pub(super) const TWO_STEP: i32 = 1;
pub(super) const NEW_DEVICE: i32 = 2;
pub(super) const DEVICE_LOGIN: i32 = 3;

/// The form's number for each method (`SignInForm.kinds`).
fn kind(provider: TwoFactorProvider) -> i32 {
    match provider {
        TwoFactorProvider::Authenticator | TwoFactorProvider::Other(_) => 0,
        TwoFactorProvider::Email => 1,
        TwoFactorProvider::YubiKey => 2,
        TwoFactorProvider::WebAuthn => 3,
    }
}

fn label(provider: TwoFactorProvider) -> &'static str {
    match provider {
        TwoFactorProvider::Authenticator => "Authenticator",
        TwoFactorProvider::Email => "Email",
        TwoFactorProvider::YubiKey => "YubiKey",
        TwoFactorProvider::WebAuthn => "Security key",
        TwoFactorProvider::Other(_) => "Other",
    }
}

/// The method to show first, by Bitwarden's order of preference: security
/// key (when the server sent its options), YubiKey, authenticator app,
/// email.
fn default_provider(providers: &[TwoFactorProvider], key_ready: bool) -> usize {
    let rank = |p: &TwoFactorProvider| match p {
        TwoFactorProvider::WebAuthn if key_ready => 4,
        TwoFactorProvider::YubiKey => 3,
        TwoFactorProvider::Authenticator => 2,
        TwoFactorProvider::Email => 1,
        _ => 0,
    };
    providers
        .iter()
        .enumerate()
        .max_by_key(|(i, p)| (rank(p), std::cmp::Reverse(*i)))
        .map(|(i, _)| i)
        .unwrap_or(0)
}

/// Codes are typed or pasted with spaces ("123 456"); a YubiKey's code is
/// used as it is typed.
fn clean_code(provider: TwoFactorProvider, code: &str) -> String {
    match provider {
        TwoFactorProvider::YubiKey => code.trim().to_string(),
        _ => code.split_whitespace().collect(),
    }
}

/// The server choice and address to show for a saved server.
fn server_choice(server: &Server) -> (i32, String) {
    match server.name.as_str() {
        "bitwarden.com" => (0, String::new()),
        "bitwarden.eu" => (1, String::new()),
        other => (2, other.to_string()),
    }
}

fn parse_server(choice: i32, url: &str) -> Result<Server, String> {
    match choice {
        0 => Server::parse("bitwarden.com"),
        1 => Server::parse("bitwarden.eu"),
        _ if url.trim().is_empty() => return Err("Enter your server's address".into()),
        _ => Server::parse(url),
    }
    .map_err(|e| e.to_string())
}

/// Where this sign-in's commands go: the saved account's own worker when
/// signing in again, otherwise the form's worker (started on first use).
fn flow_tx(state: &mut State) -> Option<Sender<Command>> {
    if let Some(id) = state.sign_in.existing.clone() {
        let index = state.account_index(&id)?;
        return Some(state.accounts[index].worker.tx.clone());
    }
    if state.sign_in.worker.is_none() {
        state.sign_in.worker = Some(Worker::spawn(state.store.clone(), None, emitter()));
    }
    state.sign_in.worker.as_ref().map(|w| w.tx.clone())
}

/// The form's credentials as a sign-in attempt without a second factor.
fn request(si: &SignIn) -> Option<SignInRequest> {
    Some(SignInRequest {
        server: si.server.clone()?,
        email: si.email.clone(),
        password: si.password.clone(),
        second: None,
        new_device_code: None,
        device: Some(si.device.clone()),
    })
}

/// Sends a command for this sign-in and marks the form busy.
fn send(win: &AppWindow, st: &Shared, command: Command) {
    {
        let mut state = st.borrow_mut();
        match flow_tx(&mut state) {
            Some(tx) => {
                let _ = tx.send(command);
                state.sign_in.busy = true;
                state.sign_in.error.clear();
            }
            None => state.sign_in.error = "This account is no longer here".into(),
        }
    }
    render_sign_in(win, st);
}

fn set_error(win: &AppWindow, st: &Shared, message: &str) {
    st.borrow_mut().sign_in.error = message.into();
    render_sign_in(win, st);
}

/// Reads the server and email from the first stage; false after showing
/// what is missing.
fn read_account(win: &AppWindow, st: &Shared, choice: i32, url: &str, email: &str) -> bool {
    let server = parse_server(choice, url);
    let problem = {
        let mut state = st.borrow_mut();
        let si = &mut state.sign_in;
        si.server_choice = choice;
        si.url = url.to_string();
        si.email = email.trim().to_string();
        match server {
            Err(e) => Some(e),
            Ok(_) if !email.contains('@') => Some("Enter your email address".to_string()),
            Ok(server) => {
                si.server = Some(server);
                None
            }
        }
    };
    match problem {
        Some(message) => {
            set_error(win, st, &message);
            false
        }
        None => true,
    }
}

pub(super) fn sign_in_submit(
    win: &AppWindow,
    st: &Shared,
    choice: i32,
    url: &str,
    email: &str,
    password: &str,
) {
    if !read_account(win, st, choice, url, email) {
        return;
    }
    if password.is_empty() {
        return set_error(win, st, "Enter your master password");
    }
    let command = {
        let mut state = st.borrow_mut();
        state.sign_in.password = Zeroizing::new(password.to_string());
        request(&state.sign_in).map(|r| Command::SignIn(Box::new(r)))
    };
    if let Some(command) = command {
        send(win, st, command);
    }
}

/// Sends a typed two-step login code.
pub(super) fn sign_in_code(win: &AppWindow, st: &Shared, index: i32, code: &str, remember: bool) {
    let (provider, via_device, request) = {
        let state = st.borrow();
        let si = &state.sign_in;
        let Some(provider) = si.providers.get(index.max(0) as usize).copied() else {
            return;
        };
        (provider, si.via_device, request(si))
    };
    let code = clean_code(provider, code);
    if code.is_empty() {
        return set_error(win, st, "Enter the code");
    }
    let second = Second::Code(provider, code, remember);
    if let Some(command) = second_command(via_device, request, second) {
        send(win, st, command);
    }
}

/// A sign-in attempt with a second factor, by password or after another
/// device approved.
fn second_command(
    via_device: bool,
    request: Option<SignInRequest>,
    second: Second,
) -> Option<Command> {
    let mut request = request?;
    Some(if via_device {
        Command::FinishDeviceLogin {
            server: request.server,
            second: Some(second),
        }
    } else {
        request.second = Some(second);
        Command::SignIn(Box::new(request))
    })
}

/// Asks for a two-step login code by email, as this sign-in's device.
pub(super) fn send_email_code(st: &Shared) {
    let mut state = st.borrow_mut();
    let si = &state.sign_in;
    let Some(server) = si.server.clone() else {
        return;
    };
    let command = Command::SendEmailCode {
        server,
        email: si.email.clone(),
        password: si.password.clone(),
        device: Some(si.device.clone()),
    };
    if let Some(tx) = flow_tx(&mut state) {
        let _ = tx.send(command);
    }
}

/// Asks the security key; the worker waits for the touch.
fn use_security_key(win: &AppWindow, st: &Shared, remember: bool) {
    let options = st
        .borrow()
        .sign_in
        .challenge
        .as_ref()
        .and_then(|c| c.webauthn_options())
        .cloned();
    let Some(options) = options else {
        return set_error(win, st, "This server sent no security key details");
    };
    let cancel = Cancel::new();
    let (via_device, request) = {
        let mut state = st.borrow_mut();
        state.sign_in.key_cancel = Some(cancel.clone());
        (state.sign_in.via_device, request(&state.sign_in))
    };
    let second = Second::SecurityKey {
        options,
        remember,
        cancel,
    };
    if let Some(command) = second_command(via_device, request, second) {
        send(win, st, command);
    }
}

fn stop_security_key(win: &AppWindow, st: &Shared) {
    if let Some(cancel) = st.borrow_mut().sign_in.key_cancel.take() {
        cancel.cancel();
    }
    render_sign_in(win, st);
}

fn start_device_login(win: &AppWindow, st: &Shared, choice: i32, url: &str, email: &str) {
    if !read_account(win, st, choice, url, email) {
        return;
    }
    let command = {
        let state = st.borrow();
        let si = &state.sign_in;
        si.server.clone().map(|server| Command::StartDeviceLogin {
            server,
            email: si.email.clone(),
            device: Some(si.device.clone()),
        })
    };
    if let Some(command) = command {
        send(win, st, command);
    }
}

fn submit_device_code(win: &AppWindow, st: &Shared, code: &str) {
    let code: String = code.split_whitespace().collect();
    if code.is_empty() {
        return set_error(win, st, "Enter the code from the email");
    }
    let request = request(&st.borrow().sign_in);
    if let Some(mut request) = request {
        request.new_device_code = Some(code);
        send(win, st, Command::SignIn(Box::new(request)));
    }
}

fn resend_device_code(win: &AppWindow, st: &Shared) {
    let request = request(&st.borrow().sign_in);
    if let Some(request) = request {
        send(win, st, Command::ResendNewDeviceCode(Box::new(request)));
    }
}

fn pick_provider(win: &AppWindow, st: &Shared, index: i32) {
    {
        let mut state = st.borrow_mut();
        let si = &mut state.sign_in;
        if index >= 0 && (index as usize) < si.providers.len() && si.key_cancel.is_none() {
            si.provider_index = index as usize;
            si.error.clear();
        }
    }
    render_sign_in(win, st);
}

/// Leaves the form: stops a security key wait and a login request, and
/// goes back to the account being signed in again, or the first account.
pub(super) fn cancel_sign_in(win: &AppWindow, st: &Shared) {
    let target = {
        let mut state = st.borrow_mut();
        if let Some(cancel) = state.sign_in.key_cancel.take() {
            cancel.cancel();
        }
        if (state.sign_in.stage == DEVICE_LOGIN || state.sign_in.via_device)
            && let Some(tx) = flow_tx(&mut state)
        {
            let _ = tx.send(Command::CancelDeviceLogin);
        }
        let existing = state.sign_in.existing.take();
        state.sign_in = SignIn::default();
        existing.or_else(|| state.accounts.first().map(|a| a.profile.id.clone()))
    };
    match target {
        Some(key) => select(win, st, &key),
        None => show_sign_in(win, st),
    }
}

/// While logging in with a device, asks the worker whether the request
/// was answered. Called every few seconds.
pub(super) fn poll_device_login(st: &Shared) {
    let mut state = st.borrow_mut();
    if state.sign_in.stage != DEVICE_LOGIN || state.sign_in.polling {
        return;
    }
    if let Some(tx) = flow_tx(&mut state) {
        let _ = tx.send(Command::PollDeviceLogin);
        state.sign_in.polling = true;
    }
}

pub(super) fn show_sign_in(win: &AppWindow, st: &Shared) {
    {
        let mut state = st.borrow_mut();
        if state.draft.as_ref().is_some_and(Draft::dirty) {
            return;
        }
        state.draft = None;
        state.shown = Shown::SignIn;
        state.selected = None;
    }
    win.set_selected_key(SharedString::new());
    win.set_selected_index(-1);
    render(win, st);
}

pub(super) fn render_sign_in(win: &AppWindow, st: &Shared) {
    let state = st.borrow();
    let si = &state.sign_in;
    let labels: Vec<SharedString> = si.providers.iter().map(|p| s(label(*p))).collect();
    let kinds: Vec<i32> = si.providers.iter().map(|p| kind(*p)).collect();
    let challenge = si.challenge.as_ref();
    win.set_sign_in(SignInForm {
        stage: si.stage,
        server_choice: si.server_choice,
        url: s(&si.url),
        email: s(&si.email),
        error: s(&si.error),
        busy: si.busy,
        providers: ModelRc::new(VecModel::from(labels)),
        provider_index: si.provider_index as i32,
        kinds: ModelRc::new(VecModel::from(kinds)),
        email_hint: s(challenge.and_then(|c| c.email_hint()).unwrap_or_default()),
        key_ready: challenge.is_some_and(|c| c.webauthn_options().is_some()),
        key_waiting: si.key_cancel.is_some(),
        phrase: s(&si.phrase),
        reconnect: si.existing.is_some(),
    });
    if state.shown == Shown::SignIn {
        win.set_mode(PaneMode::SignIn);
    }
}

/// Moves the form to two-step login with what the server asked for.
fn apply_challenge(si: &mut SignIn, challenge: TwoFactorChallenge) {
    let supported: Vec<_> = challenge
        .providers
        .iter()
        .copied()
        .filter(|p| p.supported())
        .collect();
    if si.stage == TWO_STEP {
        si.error = if si.key_cancel.is_some() {
            "The security key was not accepted".into()
        } else {
            "That code was not accepted".into()
        };
    } else if supported.is_empty() {
        si.stage = CREDENTIALS;
        si.error = "This account uses a two-step login method Hushjar does not support yet".into();
    } else {
        if si.stage == DEVICE_LOGIN {
            si.via_device = true;
        }
        si.stage = TWO_STEP;
        si.error.clear();
        let key_ready = challenge.webauthn_options().is_some();
        si.provider_index = default_provider(&supported, key_ready);
    }
    if !supported.is_empty() {
        si.providers = supported;
        si.challenge = Some(challenge);
    }
    si.key_cancel = None;
}

/// Whether an event from a saved account's worker belongs to this form,
/// because the form is signing that account in again. A finished sign-in
/// always does; the rest only while the form is shown, so the locked pane
/// gets its own errors once the user has moved on.
pub(super) fn sign_in_takes(st: &Shared, id: &str, event: &Event) -> bool {
    let state = st.borrow();
    if state.sign_in.existing.as_deref() != Some(id) {
        return false;
    }
    matches!(event, Event::SignedIn { .. })
        || state.shown == Shown::SignIn
            && matches!(
                event,
                Event::TwoFactorRequired { .. }
                    | Event::NewDeviceRequired
                    | Event::EmailSent
                    | Event::Failed { .. }
                    | Event::DeviceLoginStarted { .. }
                    | Event::DeviceLoginWaiting
                    | Event::DeviceLoginEnded { .. }
            )
}

/// Unlocking a logged-out account needs more than the password: continue
/// on the sign-in form with the same server, email and password.
pub(super) fn continue_unlock_on_form(
    win: &AppWindow,
    st: &Shared,
    index: usize,
    challenge: Option<Box<TwoFactorChallenge>>,
    password: Zeroizing<String>,
) {
    {
        let mut state = st.borrow_mut();
        let a = &mut state.accounts[index];
        a.busy = false;
        let profile = a.profile.clone();
        let (server_choice, url) = server_choice(&profile.server);
        let mut si = SignIn {
            server_choice,
            url,
            email: profile.email.clone(),
            password,
            server: Some(profile.server.clone()),
            existing: Some(profile.id.clone()),
            device: profile.device.clone(),
            stage: NEW_DEVICE,
            ..SignIn::default()
        };
        if let Some(challenge) = challenge {
            si.stage = CREDENTIALS;
            apply_challenge(&mut si, *challenge);
        }
        state.sign_in = si;
        state.shown = Shown::SignIn;
        state.selected = None;
    }
    win.set_busy(false);
    win.set_selected_key(SharedString::new());
    win.set_selected_index(-1);
    render(win, st);
}

pub(super) fn handle_sign_in_event(win: &AppWindow, st: &Shared, event: Event) {
    match event {
        Event::SignedIn {
            profile,
            vault,
            synced_at,
        } => signed_in(win, st, *profile, vault, synced_at),
        Event::TwoFactorRequired { challenge } => {
            {
                let mut state = st.borrow_mut();
                state.sign_in.busy = false;
                apply_challenge(&mut state.sign_in, *challenge);
            }
            render_sign_in(win, st);
        }
        Event::NewDeviceRequired => {
            {
                let mut state = st.borrow_mut();
                let si = &mut state.sign_in;
                si.busy = false;
                if si.stage == NEW_DEVICE {
                    si.error = "That code was not accepted".into();
                } else {
                    si.stage = NEW_DEVICE;
                    si.error.clear();
                }
            }
            render_sign_in(win, st);
        }
        Event::EmailSent => {
            st.borrow_mut().sign_in.busy = false;
            render_sign_in(win, st);
            toast(win, st, "A code is on its way to your email");
        }
        Event::DeviceLoginStarted { phrase } => {
            {
                let mut state = st.borrow_mut();
                let si = &mut state.sign_in;
                si.busy = false;
                si.error.clear();
                si.stage = DEVICE_LOGIN;
                si.phrase = phrase;
                si.polling = false;
            }
            render_sign_in(win, st);
        }
        Event::DeviceLoginWaiting => {
            let had_error = {
                let mut state = st.borrow_mut();
                state.sign_in.polling = false;
                !std::mem::take(&mut state.sign_in.error).is_empty()
            };
            if had_error {
                render_sign_in(win, st);
            }
        }
        Event::DeviceLoginEnded { message } => {
            {
                let mut state = st.borrow_mut();
                let si = &mut state.sign_in;
                si.busy = false;
                si.polling = false;
                si.via_device = false;
                si.stage = CREDENTIALS;
                si.phrase.clear();
                si.error = message;
            }
            render_sign_in(win, st);
        }
        Event::Failed { message } => {
            {
                let mut state = st.borrow_mut();
                let si = &mut state.sign_in;
                si.busy = false;
                si.polling = false;
                si.key_cancel = None;
                si.error = message;
            }
            render_sign_in(win, st);
        }
        _ => {}
    }
}

/// A finished sign-in: a new account joins the list; an account signed in
/// again is unlocked.
fn signed_in(win: &AppWindow, st: &Shared, profile: Profile, vault: Vault, synced_at: Option<u64>) {
    let key = profile.id.clone();
    let email = profile.email.clone();
    let existing = st.borrow_mut().sign_in.existing.take();
    if existing.is_some() {
        st.borrow_mut().sign_in = SignIn::default();
        handle_account_event(win, st, &key, Event::Unlocked { vault, synced_at });
        toast(win, st, &format!("Signed in as {email}"));
        return;
    }
    {
        let mut state = st.borrow_mut();
        // The worker that signed in keeps the session and becomes
        // this account's worker; it now reports under the account's ID.
        let Some(worker) = state.sign_in.worker.take() else {
            return;
        };
        state.sign_in = SignIn::default();
        if let Some(existing) = state.account_index(&key) {
            state.accounts.remove(existing);
        }
        let view = Account::from_vault(&profile, &vault);
        state.accounts.push(AccountState {
            profile,
            view,
            vault: Some(vault),
            worker,
            busy: false,
            needs_sign_in: false,
            two_factor: vec![],
            synced_at,
            note: String::new(),
            unlock: UnlockOptions::default(),
            policies: None,
            live_problem: None,
        });
        state.expanded.insert(key.clone());
    }
    refresh_tree(win, st);
    select(win, st, &key);
    update_sync_text(win, st);
    toast(win, st, &format!("Signed in as {email}"));
}

pub(super) fn wire_sign_in(w: &AppWindow, state: &Shared) {
    let data = w.global::<SignInData>();
    let weak = w.as_weak();
    macro_rules! on {
        ($setter:ident, |$win:ident, $st:ident $(, $arg:ident : $ty:ty)*| $body:block) => {{
            let weak = weak.clone();
            let state = state.clone();
            data.$setter(move |$($arg: $ty),*| {
                let Some($win) = weak.upgrade() else { return };
                let $st = &state;
                $st.borrow_mut().last_activity = Instant::now();
                $body
            });
        }};
    }
    on!(on_pick_provider, |win, st, index: i32| {
        pick_provider(&win, st, index);
    });
    on!(on_use_security_key, |win, st, remember: bool| {
        use_security_key(&win, st, remember);
    });
    on!(on_stop_security_key, |win, st| {
        stop_security_key(&win, st);
    });
    on!(
        on_device_login,
        |win, st, choice: i32, url: SharedString, email: SharedString| {
            start_device_login(&win, st, choice, &url, &email);
        }
    );
    on!(on_submit_device_code, |win, st, code: SharedString| {
        submit_device_code(&win, st, &code);
    });
    on!(on_resend_device_code, |win, st| {
        resend_device_code(&win, st);
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use TwoFactorProvider::*;

    #[test]
    fn prefers_security_keys_then_yubikeys() {
        let all = [Authenticator, Email, YubiKey, WebAuthn];
        assert_eq!(default_provider(&all, true), 3);
        // Without options from the server the key cannot be used.
        assert_eq!(default_provider(&all, false), 2);
        assert_eq!(default_provider(&[Email, Authenticator], false), 1);
        assert_eq!(default_provider(&[Email], false), 0);
        assert_eq!(default_provider(&[], false), 0);
    }

    #[test]
    fn codes_lose_their_spaces() {
        assert_eq!(clean_code(Authenticator, " 123 456 "), "123456");
        assert_eq!(clean_code(Email, "12 34\t56"), "123456");
        assert_eq!(clean_code(YubiKey, " cccjgjgkhcbb "), "cccjgjgkhcbb");
    }

    #[test]
    fn saved_servers_fill_the_server_choice() {
        let cloud = Server::parse("bitwarden.eu").unwrap();
        assert_eq!(server_choice(&cloud), (1, String::new()));
        let own = Server::parse("https://vault.example.org").unwrap();
        assert_eq!(server_choice(&own).0, 2);
        assert!(server_choice(&own).1.contains("vault.example.org"));
        assert!(parse_server(2, "  ").is_err());
        assert_eq!(parse_server(0, "").unwrap().name, "bitwarden.com");
    }

    fn challenge(body: serde_json::Value) -> TwoFactorChallenge {
        TwoFactorChallenge::from_response(&body).unwrap()
    }

    #[test]
    fn a_challenge_moves_to_two_step_login() {
        let mut si = SignIn::default();
        apply_challenge(
            &mut si,
            challenge(serde_json::json!({
                "TwoFactorProviders2": {
                    "0": null,
                    "1": { "Email": "a***@example.invalid" },
                    "3": { "Nfc": true }
                }
            })),
        );
        assert_eq!(si.stage, TWO_STEP);
        assert_eq!(si.providers, vec![Authenticator, Email, YubiKey]);
        assert_eq!(si.provider_index, 2);
        assert!(si.error.is_empty());
        // A second challenge at this stage means the code was wrong.
        let again = si.challenge.clone().unwrap();
        apply_challenge(&mut si, again);
        assert_eq!(si.error, "That code was not accepted");
        assert_eq!(si.provider_index, 2);
    }

    #[test]
    fn unsupported_methods_stay_on_the_first_stage() {
        let mut si = SignIn::default();
        apply_challenge(
            &mut si,
            challenge(serde_json::json!({ "TwoFactorProviders2": { "2": null } })),
        );
        assert_eq!(si.stage, CREDENTIALS);
        assert!(si.error.contains("does not support"));
    }

    #[test]
    fn two_step_after_device_approval_finishes_the_device_login() {
        let mut si = SignIn {
            stage: DEVICE_LOGIN,
            ..SignIn::default()
        };
        apply_challenge(
            &mut si,
            challenge(serde_json::json!({ "TwoFactorProviders2": { "0": null } })),
        );
        assert_eq!(si.stage, TWO_STEP);
        assert!(si.via_device);
        si.server = Some(Server::parse("bitwarden.com").unwrap());
        let command = second_command(
            si.via_device,
            request(&si),
            Second::Code(Authenticator, "1".into(), false),
        );
        assert!(matches!(
            command,
            Some(Command::FinishDeviceLogin {
                second: Some(_),
                ..
            })
        ));
    }

    #[test]
    fn retries_keep_the_same_device() {
        let si = SignIn {
            server: Some(Server::parse("bitwarden.com").unwrap()),
            ..SignIn::default()
        };
        let first = request(&si).unwrap().device.unwrap();
        let second = request(&si).unwrap().device.unwrap();
        assert_eq!(first.identifier, second.identifier);
    }
}

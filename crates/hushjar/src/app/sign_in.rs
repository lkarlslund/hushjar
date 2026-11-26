//! The add-account and sign-in form.

use super::*;

pub(super) fn sign_in_submit(
    win: &AppWindow,
    st: &Shared,
    choice: i32,
    url: &str,
    email: &str,
    password: &str,
) {
    let server = match choice {
        0 => Server::parse("bitwarden.com"),
        1 => Server::parse("bitwarden.eu"),
        _ => Server::parse(url),
    };
    {
        let mut state = st.borrow_mut();
        let store = state.store.clone();
        let si = &mut state.sign_in;
        si.server_choice = choice;
        si.url = url.to_string();
        si.email = email.trim().to_string();
        match server {
            Err(e) => si.error = e.to_string(),
            Ok(_) if choice == 2 && url.trim().is_empty() => {
                si.error = "Enter your server's address".into()
            }
            Ok(_) if !email.contains('@') => si.error = "Enter your email address".into(),
            Ok(_) if password.is_empty() => si.error = "Enter your master password".into(),
            Ok(server) => {
                si.error.clear();
                si.busy = true;
                si.password = Zeroizing::new(password.to_string());
                si.server = Some(server.clone());
                if si.worker.is_none() {
                    si.worker = Some(Worker::spawn(store, None, emitter()));
                }
                if let Some(worker) = &si.worker {
                    let _ = worker.tx.send(Command::SignIn {
                        server,
                        email: si.email.clone(),
                        password: si.password.clone(),
                        second: None,
                    });
                }
            }
        }
    }
    render_sign_in(win, st);
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
    let labels: Vec<SharedString> = si
        .providers
        .iter()
        .map(|p| {
            s(match p {
                TwoFactorProvider::Authenticator => "Authenticator app",
                TwoFactorProvider::Email => "Email",
                TwoFactorProvider::YubiKey => "YubiKey",
                TwoFactorProvider::Other(_) => "Other",
            })
        })
        .collect();
    win.set_sign_in(SignInForm {
        stage: si.stage,
        server_choice: si.server_choice,
        url: s(&si.url),
        email: s(&si.email),
        error: s(&si.error),
        busy: si.busy,
        email_provider: si.providers.first() == Some(&TwoFactorProvider::Email)
            && si.providers.len() == 1
            || si.providers.contains(&TwoFactorProvider::Email)
                && !si.providers.contains(&TwoFactorProvider::Authenticator),
        providers: ModelRc::new(VecModel::from(labels)),
        provider_index: 0,
        reconnect: false,
    });
    if state.shown == Shown::SignIn {
        win.set_mode(PaneMode::SignIn);
    }
}

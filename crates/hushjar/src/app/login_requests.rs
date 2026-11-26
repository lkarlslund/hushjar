//! Login requests from other devices ("log in with a device") for unlocked
//! accounts, shown one at a time with Approve and Deny; the account
//! fingerprint phrase; and the timer that polls both.

use hushjar_core::api::AuthRequest;

use super::*;
use crate::{AccountData, LoginRequestData};

/// How often the timer runs; device-login polls go out this often.
const TICK: Duration = Duration::from_secs(3);
/// Ticks between checks for other devices' login requests (60 s).
const CHECK_EVERY: u32 = 20;

/// One request waiting for an answer.
#[derive(Clone, Debug)]
struct LoginPrompt {
    /// The local ID of the account it is for.
    account: String,
    phrase: String,
    request: AuthRequest,
}

/// Login requests and account fingerprints, kept in the app state.
#[derive(Default)]
pub(super) struct Access {
    queue: VecDeque<LoginPrompt>,
    /// Requests answered here, so a check that raced the answer does not
    /// bring them back.
    answered: HashSet<String>,
    /// Account fingerprint phrases by account ID.
    fingerprints: HashMap<String, String>,
    asked_fingerprint: HashSet<String>,
    /// The locked account last shown, to reset the PIN/password switch
    /// when another one is shown.
    pub(super) locked_shown: Option<String>,
    ticks: u32,
}

/// Puts one account's fresh list of requests into the queue: drops those
/// no longer pending, adds new ones at the end, keeps the order otherwise.
fn merge(
    queue: &mut VecDeque<LoginPrompt>,
    answered: &HashSet<String>,
    account: &str,
    fetched: Vec<(String, AuthRequest)>,
) {
    queue.retain(|p| p.account != account || fetched.iter().any(|(_, r)| r.id == p.request.id));
    for (phrase, request) in fetched {
        let known = queue.iter().any(|p| p.request.id == request.id);
        if !known && !answered.contains(&request.id) {
            queue.push_back(LoginPrompt {
                account: account.to_string(),
                phrase,
                request,
            });
        }
    }
}

/// "Linux at 192.0.2.4", or as much of it as the server told.
fn origin(request: &AuthRequest) -> String {
    let device = match request.device_type.trim() {
        "" => "A device",
        name => name,
    };
    match request.ip_address.trim() {
        "" => device.to_string(),
        ip => format!("{device} at {ip}"),
    }
}

/// Asks an unlocked account's worker for other devices' login requests.
/// Called after each sync, once a minute, and when the server notifies of
/// a new request.
pub(super) fn check_login_requests(st: &Shared, account: usize) {
    let state = st.borrow();
    if let Some(a) = state.accounts.get(account)
        && a.vault.is_some()
        && !a.needs_sign_in
    {
        let _ = a.worker.tx.send(Command::CheckLoginRequests);
    }
}

fn check_all(st: &Shared) {
    let count = st.borrow().accounts.len();
    for account in 0..count {
        check_login_requests(st, account);
    }
}

/// Shows the first waiting request for an unlocked account, if any.
pub(super) fn render_login_request(win: &AppWindow, st: &Shared) {
    let mut state = st.borrow_mut();
    let state = &mut *state;
    let unlocked = |id: &str| {
        state
            .accounts
            .iter()
            .any(|a| a.profile.id == id && a.vault.is_some())
    };
    state.access.queue.retain(|p| unlocked(&p.account));
    let data = win.global::<LoginRequestData>();
    let Some(first) = state.access.queue.front() else {
        data.set_visible(false);
        return;
    };
    let email = state
        .accounts
        .iter()
        .find(|a| a.profile.id == first.account)
        .map(|a| a.profile.email.clone())
        .unwrap_or_default();
    data.set_account(s(&email));
    data.set_origin(s(&origin(&first.request)));
    data.set_phrase(s(&first.phrase));
    data.set_more(state.access.queue.len() as i32 - 1);
    data.set_visible(true);
}

fn answer(win: &AppWindow, st: &Shared, approve: bool) {
    {
        let mut state = st.borrow_mut();
        let Some(prompt) = state.access.queue.pop_front() else {
            return;
        };
        state.access.answered.insert(prompt.request.id.clone());
        if let Some(index) = state.account_index(&prompt.account) {
            let _ = state.accounts[index]
                .worker
                .tx
                .send(Command::AnswerLoginRequest {
                    request: Box::new(prompt.request),
                    approve,
                });
        }
    }
    render_login_request(win, st);
}

pub(super) fn login_requests_event(
    win: &AppWindow,
    st: &Shared,
    index: usize,
    requests: Vec<(String, AuthRequest)>,
) {
    {
        let mut state = st.borrow_mut();
        let state = &mut *state;
        let id = state.accounts[index].profile.id.clone();
        merge(
            &mut state.access.queue,
            &state.access.answered,
            &id,
            requests,
        );
    }
    render_login_request(win, st);
}

pub(super) fn login_answered_event(win: &AppWindow, st: &Shared, approved: bool) {
    toast(
        win,
        st,
        if approved {
            "Approved: the other device is signing in"
        } else {
            "Login request denied"
        },
    );
}

pub(super) fn fingerprint_event(win: &AppWindow, st: &Shared, index: usize, phrase: String) {
    {
        let mut state = st.borrow_mut();
        let id = state.accounts[index].profile.id.clone();
        state.access.fingerprints.insert(id, phrase);
    }
    if matches!(st.borrow().shown, Shown::Account(i) if i == index) {
        render_account_fingerprint(win, st, index);
    }
}

/// Shows the account's fingerprint phrase, asking its worker the first
/// time.
pub(super) fn render_account_fingerprint(win: &AppWindow, st: &Shared, account: usize) {
    let mut state = st.borrow_mut();
    let Some(a) = state.accounts.get(account) else {
        return;
    };
    let id = a.profile.id.clone();
    let phrase = state.access.fingerprints.get(&id).cloned();
    if phrase.is_none() && a.vault.is_some() && state.access.asked_fingerprint.insert(id) {
        let _ = state.accounts[account]
            .worker
            .tx
            .send(Command::AccountFingerprint);
    }
    win.global::<AccountData>()
        .set_fingerprint(s(&phrase.unwrap_or_default()));
}

/// Every few seconds: polls a device login in progress, and once a minute
/// checks for other devices' login requests.
pub(super) fn access_timer(win: &AppWindow, st: &Shared) -> Timer {
    let timer = Timer::default();
    let weak = win.as_weak();
    let st = st.clone();
    timer.start(TimerMode::Repeated, TICK, move || {
        if weak.upgrade().is_none() {
            return;
        }
        poll_device_login(&st);
        let due = {
            let mut state = st.borrow_mut();
            state.access.ticks = (state.access.ticks + 1) % CHECK_EVERY;
            state.access.ticks == 0
        };
        if due {
            check_all(&st);
        }
    });
    timer
}

/// Connects the sign-in, unlock and login request globals.
pub(super) fn wire_access(w: &AppWindow, state: &Shared) {
    wire_sign_in(w, state);
    wire_unlock(w, state);
    let weak = w.as_weak();
    let st = state.clone();
    w.global::<LoginRequestData>().on_answer(move |approve| {
        let Some(win) = weak.upgrade() else { return };
        st.borrow_mut().last_activity = Instant::now();
        answer(&win, &st, approve);
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(id: &str) -> AuthRequest {
        AuthRequest {
            id: id.into(),
            public_key: String::new(),
            device_type: "Linux".into(),
            ip_address: "192.0.2.4".into(),
            created: String::new(),
            key: None,
            master_password_hash: None,
            approved: None,
        }
    }

    fn ids(queue: &VecDeque<LoginPrompt>) -> Vec<&str> {
        queue.iter().map(|p| p.request.id.as_str()).collect()
    }

    #[test]
    fn merging_keeps_order_and_drops_answered_requests() {
        let mut queue = VecDeque::new();
        let mut answered = HashSet::new();
        let fetched = |list: &[&str]| -> Vec<(String, AuthRequest)> {
            list.iter()
                .map(|id| ("phrase".into(), request(id)))
                .collect()
        };
        merge(&mut queue, &answered, "a", fetched(&["1", "2"]));
        merge(&mut queue, &answered, "b", fetched(&["9"]));
        assert_eq!(ids(&queue), ["1", "2", "9"]);
        // "1" was answered elsewhere; "3" is new.
        merge(&mut queue, &answered, "a", fetched(&["2", "3"]));
        assert_eq!(ids(&queue), ["2", "9", "3"]);
        // Answered here, but the server still lists it for a moment.
        queue.pop_front();
        answered.insert("2".to_string());
        merge(&mut queue, &answered, "a", fetched(&["2", "3"]));
        assert_eq!(ids(&queue), ["9", "3"]);
        // Another account's empty list leaves this account's requests.
        merge(&mut queue, &answered, "b", vec![]);
        assert_eq!(ids(&queue), ["3"]);
    }

    #[test]
    fn origins_read_naturally() {
        assert_eq!(origin(&request("1")), "Linux at 192.0.2.4");
        let mut bare = request("2");
        bare.device_type.clear();
        bare.ip_address.clear();
        assert_eq!(origin(&bare), "A device");
    }
}

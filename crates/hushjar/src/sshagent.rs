//! Connects the SSH agent to the app: which keys are offered, and approval
//! prompts with the "ask the first time" or "ask every time" setting.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex, MutexGuard, mpsc};
use std::time::{Duration, Instant};

use hushjar_agent::{AgentKey, Approver, KeySource, SignPurpose, SignRequest};

/// How long a prompt waits for an answer before the request is refused.
pub const PROMPT_TIMEOUT: Duration = Duration::from_secs(60);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AskMode {
    /// Ask once; after that the key may be used until its account locks.
    FirstTime,
    EveryTime,
}

impl AskMode {
    pub fn as_str(self) -> &'static str {
        match self {
            AskMode::FirstTime => "first",
            AskMode::EveryTime => "every",
        }
    }

    pub fn parse(text: &str) -> Self {
        if text == "every" {
            AskMode::EveryTime
        } else {
            AskMode::FirstTime
        }
    }
}

#[derive(Default)]
struct Offer {
    keys: Vec<AgentKey>,
    modes: HashMap<String, AskMode>,
    approved: HashSet<String>,
}

/// A request waiting for the user's answer.
pub struct Prompt {
    pub text: String,
    pub deadline: Instant,
    respond: mpsc::Sender<bool>,
}

impl Prompt {
    pub fn answer(&self, allow: bool) {
        let _ = self.respond.send(allow);
    }
}

pub struct Bridge {
    offer: Mutex<Offer>,
    /// One prompt per key at a time; others wait for its answer.
    prompt_locks: Mutex<HashMap<String, Arc<Mutex<()>>>>,
    show: Box<dyn Fn(Prompt) + Send + Sync>,
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

impl Bridge {
    /// `show` hands a prompt to the UI; it is called on agent threads.
    pub fn new(show: impl Fn(Prompt) + Send + Sync + 'static) -> Self {
        Self {
            offer: Mutex::new(Offer::default()),
            prompt_locks: Mutex::new(HashMap::new()),
            show: Box::new(show),
        }
    }

    /// Replaces the keys on offer. Approvals for keys no longer offered (for
    /// example because their account locked) are forgotten.
    pub fn set_keys(&self, keys: Vec<AgentKey>, modes: HashMap<String, AskMode>) {
        let mut offer = lock(&self.offer);
        offer.approved.retain(|id| {
            keys.iter().any(|k| k.id == *id) && modes.get(id) != Some(&AskMode::EveryTime)
        });
        offer.keys = keys;
        offer.modes = modes;
    }

    /// Puts every "first time" key back to asking.
    pub fn forget_approvals(&self) {
        lock(&self.offer).approved.clear();
    }

    pub fn key_count(&self) -> usize {
        lock(&self.offer).keys.len()
    }
}

impl KeySource for Bridge {
    fn keys(&self) -> Vec<AgentKey> {
        lock(&self.offer).keys.clone()
    }
}

impl Approver for Bridge {
    fn approve(&self, request: &SignRequest) -> bool {
        let id = request.key_id.clone();
        let key_lock = lock(&self.prompt_locks)
            .entry(id.clone())
            .or_default()
            .clone();
        let _one_prompt = lock(&key_lock);
        let mode = {
            let offer = lock(&self.offer);
            let mode = offer.modes.get(&id).copied().unwrap_or(AskMode::FirstTime);
            if mode == AskMode::FirstTime && offer.approved.contains(&id) {
                return true;
            }
            mode
        };
        let (tx, rx) = mpsc::channel();
        (self.show)(Prompt {
            text: describe(request),
            deadline: Instant::now() + PROMPT_TIMEOUT,
            respond: tx,
        });
        let allowed = rx.recv_timeout(PROMPT_TIMEOUT).unwrap_or(false);
        if allowed && mode == AskMode::FirstTime {
            let mut offer = lock(&self.offer);
            if offer.keys.iter().any(|k| k.id == id) {
                offer.approved.insert(id);
            }
        }
        allowed
    }
}

/// "ssh (pid 4242) wants to use “Deploy key” to log in as git on SHA256:…".
fn describe(request: &SignRequest) -> String {
    let program = request
        .peer
        .exe
        .as_ref()
        .and_then(|p| p.file_name())
        .map(|n| n.to_string_lossy().to_string())
        .or_else(|| {
            request
                .peer
                .cmdline
                .as_ref()
                .map(|c| c.chars().take(40).collect())
        })
        .unwrap_or_else(|| "A program".into());
    let program = match request.peer.pid {
        Some(pid) => format!("{program} (pid {pid})"),
        None => program,
    };
    let action = match &request.purpose {
        SignPurpose::Login { user } => {
            let host = request
                .host
                .as_ref()
                .map(|h| format!(" on the server {}", short(&h.fingerprint)))
                .unwrap_or_default();
            format!("to log in as {user}{host}")
        }
        SignPurpose::Sshsig { namespace } if namespace == "git" => "to sign with Git".to_string(),
        SignPurpose::Sshsig { namespace } => format!("to sign data ({namespace})"),
        SignPurpose::Other => "to sign data".to_string(),
    };
    let forwarded = if request.forwarded {
        ", through a forwarded connection"
    } else {
        ""
    };
    format!(
        "{program} wants to use “{}” {action}{forwarded}.",
        request.key_name
    )
}

fn short(fingerprint: &str) -> String {
    let cut: String = fingerprint.chars().take(20).collect();
    if cut.len() < fingerprint.len() {
        format!("{cut}…")
    } else {
        cut
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hushjar_agent::{PeerInfo, Zeroizing};

    fn request(id: &str) -> SignRequest {
        SignRequest {
            key_id: id.into(),
            key_name: "Deploy key".into(),
            fingerprint: "SHA256:x".into(),
            peer: PeerInfo {
                pid: Some(7),
                uid: 1000,
                exe: Some("/usr/bin/ssh".into()),
                cmdline: None,
            },
            host: None,
            forwarded: false,
            forwarded_via: vec![],
            purpose: SignPurpose::Login { user: "git".into() },
        }
    }

    fn key(id: &str) -> AgentKey {
        AgentKey {
            id: id.into(),
            name: "k".into(),
            private_key_openssh: Zeroizing::new(String::new()),
        }
    }

    /// A bridge whose prompts are answered with `answer` and counted.
    fn bridge(answer: bool) -> (Arc<Bridge>, Arc<Mutex<usize>>) {
        let shown = Arc::new(Mutex::new(0));
        let counter = shown.clone();
        let bridge = Bridge::new(move |prompt| {
            *counter.lock().unwrap() += 1;
            prompt.answer(answer);
        });
        (Arc::new(bridge), shown)
    }

    #[test]
    fn first_time_asks_once_until_the_key_goes_away() {
        let (b, shown) = bridge(true);
        b.set_keys(
            vec![key("a")],
            HashMap::from([("a".into(), AskMode::FirstTime)]),
        );
        assert!(b.approve(&request("a")));
        assert!(b.approve(&request("a")));
        assert_eq!(*shown.lock().unwrap(), 1);
        // Locking removes the key; offering it again asks again.
        b.set_keys(vec![], HashMap::new());
        b.set_keys(
            vec![key("a")],
            HashMap::from([("a".into(), AskMode::FirstTime)]),
        );
        assert!(b.approve(&request("a")));
        assert_eq!(*shown.lock().unwrap(), 2);
    }

    #[test]
    fn every_time_always_asks() {
        let (b, shown) = bridge(true);
        b.set_keys(
            vec![key("a")],
            HashMap::from([("a".into(), AskMode::EveryTime)]),
        );
        assert!(b.approve(&request("a")));
        assert!(b.approve(&request("a")));
        assert_eq!(*shown.lock().unwrap(), 2);
    }

    #[test]
    fn denial_is_not_remembered() {
        let (b, shown) = bridge(false);
        b.set_keys(vec![key("a")], HashMap::new());
        assert!(!b.approve(&request("a")));
        assert!(!b.approve(&request("a")));
        assert_eq!(*shown.lock().unwrap(), 2);
    }

    #[test]
    fn prompt_text() {
        assert_eq!(
            describe(&request("a")),
            "ssh (pid 7) wants to use “Deploy key” to log in as git."
        );
    }
}

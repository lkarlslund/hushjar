//! Unlocking with system authentication (polkit on Linux).
//!
//! Hushjar asks polkit to authorise the action [`UNLOCK_ACTION`], which is
//! declared `auth_self`: the desktop's polkit agent asks the user for their
//! own login password, or a fingerprint when PAM for polkit is set up for
//! it. The action is installed from `packaging/linux` by root;
//! [`available`] says whether it is.
//!
//! The vault's user keys are kept in a [`KeyHolder`] while Hushjar runs
//! (like Bitwarden's "require password on app start"), and handed out only
//! after a successful [`Authority::authenticate`].

use super::Error;
use std::collections::HashMap;
use std::sync::Mutex;
use zeroize::Zeroizing;

/// The polkit action Hushjar asks to authorise when unlocking.
pub const UNLOCK_ACTION: &str = "io.github.lkarlslund.Hushjar.unlock";

/// Something that can confirm the user is present: polkit on Linux, a mock
/// in tests, Windows Hello or Touch ID later.
pub trait Authority: Send + Sync {
    /// Asks the user to authenticate. Blocks until they answer, so it must
    /// not run on the UI thread. `Ok(false)` means they cancelled or failed.
    ///
    /// `reason` says what is being unlocked. polkit cannot show it: it
    /// refuses caller-supplied details from unprivileged programs, so its
    /// dialog shows the fixed message from the policy file.
    fn authenticate(&self, reason: &str) -> Result<bool, Error>;
}

/// Whether system authentication can be used: the platform supports it and,
/// on Linux, the polkit action is installed.
pub fn available() -> bool {
    imp::available()
}

/// Asks the system to authenticate the user. Blocks until they answer; run
/// it on a worker thread.
pub fn authenticate(reason: &str) -> Result<bool, Error> {
    imp::SystemAuthority::connect()?.authenticate(reason)
}

/// The platform's authority, for passing to [`KeyHolder::unlock`].
pub fn system_authority() -> Result<impl Authority, Error> {
    imp::SystemAuthority::connect()
}

/// Why [`KeyHolder::unlock`] did not hand out a key.
#[derive(Debug, thiserror::Error)]
pub enum UnlockError {
    /// No key is kept for this account; unlock with the master password.
    #[error("no key is kept for this account")]
    NoKey,
    /// The user cancelled or failed authentication.
    #[error("authentication was cancelled or failed")]
    Denied,
    /// Authentication could not be asked for.
    #[error(transparent)]
    Failed(#[from] Error),
}

/// Keeps each account's user key in memory while Hushjar runs, and hands a
/// copy out only after the user authenticated with the system.
///
/// Keys are zeroed when forgotten and when the holder is dropped. It is
/// safe to share between threads; [`KeyHolder::unlock`] holds no lock while
/// the user is authenticating.
#[derive(Default)]
pub struct KeyHolder {
    keys: Mutex<HashMap<String, Zeroizing<Vec<u8>>>>,
}

impl std::fmt::Debug for KeyHolder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let accounts: Vec<String> = self.keys().keys().cloned().collect();
        f.debug_struct("KeyHolder")
            .field("accounts", &accounts)
            .finish()
    }
}

impl KeyHolder {
    pub fn new() -> Self {
        Self::default()
    }

    /// Keeps `key` for `account_id`, replacing any earlier key.
    pub fn keep(&self, account_id: &str, key: Zeroizing<Vec<u8>>) {
        self.keys().insert(account_id.to_owned(), key);
    }

    /// Whether a key is kept for `account_id`, so the unlock form can offer
    /// system authentication.
    pub fn has(&self, account_id: &str) -> bool {
        self.keys().contains_key(account_id)
    }

    /// Forgets the key for `account_id`, for example on log out or when the
    /// user turns system authentication off.
    pub fn forget(&self, account_id: &str) {
        self.keys().remove(account_id);
    }

    /// Forgets every key.
    pub fn forget_all(&self) {
        self.keys().clear();
    }

    /// Asks `authority` to authenticate the user and, if they do, returns a
    /// copy of the key for `account_id`. Does not ask when no key is kept.
    /// Blocks while the user answers; run it on a worker thread.
    pub fn unlock(
        &self,
        account_id: &str,
        authority: &dyn Authority,
        reason: &str,
    ) -> Result<Zeroizing<Vec<u8>>, UnlockError> {
        if !self.has(account_id) {
            return Err(UnlockError::NoKey);
        }
        if !authority.authenticate(reason)? {
            return Err(UnlockError::Denied);
        }
        // Read again: the key may have been forgotten while the user was
        // authenticating.
        self.keys()
            .get(account_id)
            .cloned()
            .ok_or(UnlockError::NoKey)
    }

    fn keys(&self) -> std::sync::MutexGuard<'_, HashMap<String, Zeroizing<Vec<u8>>>> {
        // A panic while holding the lock cannot leave the map half-updated,
        // so a poisoned lock is still usable.
        self.keys
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

#[cfg(target_os = "linux")]
mod imp {
    use super::{Authority, Error, UNLOCK_ACTION};
    use std::collections::HashMap;
    use zbus::blocking::{Connection, Proxy};
    use zbus::zvariant::Value;

    /// polkit's `CheckAuthorization` flag that lets it show a dialog.
    const ALLOW_USER_INTERACTION: u32 = 1;

    /// One action as returned by polkit's `EnumerateActions`.
    type ActionDescription = (
        String,
        String,
        String,
        String,
        String,
        String,
        u32,
        u32,
        u32,
        HashMap<String, String>,
    );

    /// polkit, reached over the system bus.
    pub struct SystemAuthority {
        connection: Connection,
    }

    impl SystemAuthority {
        pub fn connect() -> Result<Self, Error> {
            Ok(Self {
                connection: Connection::system()?,
            })
        }

        fn authority(&self) -> Result<Proxy<'static>, Error> {
            Ok(Proxy::new(
                &self.connection,
                "org.freedesktop.PolicyKit1",
                "/org/freedesktop/PolicyKit1/Authority",
                "org.freedesktop.PolicyKit1.Authority",
            )?)
        }

        /// Whether polkit knows `action_id`.
        pub fn action_installed(&self, action_id: &str) -> Result<bool, Error> {
            let actions: Vec<ActionDescription> =
                self.authority()?.call("EnumerateActions", &("",))?;
            Ok(actions.iter().any(|action| action.0 == action_id))
        }

        /// Asks polkit whether this process may perform `action_id`,
        /// letting it show its dialog when `interactive`. Returns
        /// `(authorised, a challenge would be needed)`.
        pub fn check(&self, action_id: &str, interactive: bool) -> Result<(bool, bool), Error> {
            let name = self
                .connection
                .unique_name()
                .ok_or_else(|| Error::Dbus("no unique name on the system bus".into()))?
                .to_string();
            // The subject is this connection's bus name; polkit looks up
            // the process and user behind it itself.
            let mut subject_details: HashMap<&str, Value> = HashMap::new();
            subject_details.insert("name", Value::from(name));
            let subject = ("system-bus-name", subject_details);
            // Unprivileged callers may not pass details at all.
            let details: HashMap<&str, &str> = HashMap::new();
            let flags = if interactive {
                ALLOW_USER_INTERACTION
            } else {
                0
            };
            let (authorised, challenge, _details): (bool, bool, HashMap<String, String>) =
                self.authority()?.call(
                    "CheckAuthorization",
                    &(subject, action_id, details, flags, ""),
                )?;
            Ok((authorised, challenge))
        }
    }

    impl Authority for SystemAuthority {
        fn authenticate(&self, _reason: &str) -> Result<bool, Error> {
            Ok(self.check(UNLOCK_ACTION, true)?.0)
        }
    }

    pub fn available() -> bool {
        SystemAuthority::connect()
            .and_then(|authority| authority.action_installed(UNLOCK_ACTION))
            .unwrap_or(false)
    }
}

#[cfg(not(target_os = "linux"))]
mod imp {
    use super::{Authority, Error};

    pub struct SystemAuthority;

    impl SystemAuthority {
        pub fn connect() -> Result<Self, Error> {
            Err(Error::Unsupported)
        }
    }

    impl Authority for SystemAuthority {
        fn authenticate(&self, _reason: &str) -> Result<bool, Error> {
            Err(Error::Unsupported)
        }
    }

    pub fn available() -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// An authority that answers from a script and counts how often it was
    /// asked.
    struct Mock {
        answer: fn() -> Result<bool, Error>,
        asked: AtomicUsize,
    }

    impl Mock {
        fn new(answer: fn() -> Result<bool, Error>) -> Self {
            Self {
                answer,
                asked: AtomicUsize::new(0),
            }
        }
    }

    impl Authority for Mock {
        fn authenticate(&self, _reason: &str) -> Result<bool, Error> {
            self.asked.fetch_add(1, Ordering::SeqCst);
            (self.answer)()
        }
    }

    fn holder() -> KeyHolder {
        let holder = KeyHolder::new();
        holder.keep("a", Zeroizing::new(vec![1, 2, 3]));
        holder
    }

    #[test]
    fn keys_are_handed_out_after_authentication() {
        let mock = Mock::new(|| Ok(true));
        let key = holder().unlock("a", &mock, "unlock a").unwrap();
        assert_eq!(*key, vec![1, 2, 3]);
        assert_eq!(mock.asked.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn keys_are_withheld_when_authentication_fails() {
        let mock = Mock::new(|| Ok(false));
        assert!(matches!(
            holder().unlock("a", &mock, "unlock a"),
            Err(UnlockError::Denied)
        ));
        let broken = Mock::new(|| Err(Error::Unavailable("polkit".into())));
        assert!(matches!(
            holder().unlock("a", &broken, "unlock a"),
            Err(UnlockError::Failed(_))
        ));
    }

    #[test]
    fn missing_keys_do_not_prompt() {
        let mock = Mock::new(|| Ok(true));
        assert!(matches!(
            holder().unlock("b", &mock, "unlock b"),
            Err(UnlockError::NoKey)
        ));
        assert_eq!(mock.asked.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn forgotten_keys_are_gone() {
        let mock = Mock::new(|| Ok(true));
        let holder = holder();
        holder.keep("b", Zeroizing::new(vec![4]));
        holder.forget("a");
        assert!(!holder.has("a"));
        assert!(matches!(
            holder.unlock("a", &mock, ""),
            Err(UnlockError::NoKey)
        ));
        holder.forget_all();
        assert!(!holder.has("b"));
    }

    #[test]
    fn debug_shows_accounts_but_not_keys() {
        let holder = KeyHolder::new();
        holder.keep("acct", Zeroizing::new(vec![0xAB; 4]));
        let text = format!("{holder:?}");
        assert!(text.contains("acct"));
        assert!(!text.contains("171"), "{text}");
    }

    /// Talks to the real polkit without ever allowing a dialog: checks an
    /// installed `auth_admin` action non-interactively. Skips where there is
    /// no system bus or polkit.
    #[cfg(target_os = "linux")]
    #[test]
    fn polkit_answers_without_a_dialog() {
        let Ok(authority) = imp::SystemAuthority::connect() else {
            eprintln!("no system bus; skipped");
            return;
        };
        let action = "org.freedesktop.policykit.exec";
        match authority.action_installed(action) {
            Ok(true) => {}
            other => {
                eprintln!("polkit or {action} missing ({other:?}); skipped");
                return;
            }
        }
        assert!(
            !authority
                .action_installed("io.github.lkarlslund.Hushjar.nonexistent")
                .unwrap()
        );
        let (authorised, challenge) = authority.check(action, false).unwrap();
        eprintln!("{action}: authorised {authorised}, challenge {challenge}");
        // pkexec normally needs an administrator password, so without a
        // dialog the answer is "not yet, a challenge is needed"; local rules
        // may differ, so only print it.
        eprintln!("{UNLOCK_ACTION} installed: {}", available());
    }
}

//! Unlocking with a PIN.
//!
//! As in Bitwarden, the PIN key is derived like a master key, with the PIN
//! as password, the email as salt and the account's key derivation settings,
//! then stretched; it wraps the user key (Bitwarden's
//! "pinKeyEncryptedUserKey"). A PIN is short, so anyone who copies the
//! stored data can guess it offline at the speed the key derivation allows.
//! The attempt limit only guards the unlock screen. Without `persist` the
//! data lives only in the app's memory and the master password is needed
//! after a restart, which is Bitwarden's default.

use std::fmt;

use zeroize::Zeroizing;

use super::{Session, SessionError};
use crate::crypto::{self, CryptoError, Kdf, SymmetricKey};
use crate::store::{Profile, Store};

/// Wrong PINs allowed before PIN unlock is turned off.
pub const MAX_PIN_ATTEMPTS: u32 = 5;

/// What PIN unlock needs: the user key wrapped with the PIN key, and how
/// many wrong PINs have been entered since the last success.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct PinUnlock {
    /// The user key encrypted with the stretched PIN key.
    encrypted_user_key: String,
    /// The settings the PIN key was derived with, so a later change of the
    /// account's settings does not break the PIN.
    kdf: Kdf,
    failed_attempts: u32,
}

impl fmt::Debug for PinUnlock {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PinUnlock(failed_attempts: {})", self.failed_attempts)
    }
}

/// Derives the key that wraps the user key from a PIN.
fn pin_key(pin: &str, email: &str, kdf: Kdf) -> Result<SymmetricKey, CryptoError> {
    let derived = crypto::master_key(pin, email, kdf)?;
    Ok(crypto::stretch(&derived))
}

impl PinUnlock {
    /// Wraps the user key with a key derived from the PIN.
    pub fn new(user: &SymmetricKey, pin: &str, email: &str, kdf: Kdf) -> Result<Self, CryptoError> {
        Ok(Self {
            encrypted_user_key: pin_key(pin, email, kdf)?.wrap_key(user),
            kdf,
            failed_attempts: 0,
        })
    }

    /// Wrong PINs that may still be entered.
    pub fn attempts_left(&self) -> u32 {
        MAX_PIN_ATTEMPTS.saturating_sub(self.failed_attempts)
    }

    /// Checks a PIN and returns the user key. Counts a wrong PIN; once the
    /// limit is reached every later attempt fails with `PinUnavailable`.
    fn attempt(&mut self, pin: &str, email: &str) -> Result<SymmetricKey, SessionError> {
        if self.attempts_left() == 0 {
            return Err(SessionError::PinUnavailable);
        }
        match pin_key(pin, email, self.kdf)?.unwrap_key(&self.encrypted_user_key) {
            Ok(user) => {
                self.failed_attempts = 0;
                Ok(user)
            }
            Err(CryptoError::Authentication) => {
                self.failed_attempts += 1;
                match self.attempts_left() {
                    0 => Err(SessionError::PinUnavailable),
                    left => Err(SessionError::WrongPin {
                        attempts_left: left,
                    }),
                }
            }
            Err(other) => Err(other.into()),
        }
    }

    fn to_json(&self) -> Result<Zeroizing<Vec<u8>>, SessionError> {
        Ok(Zeroizing::new(
            serde_json::to_vec(self).map_err(std::io::Error::other)?,
        ))
    }
}

impl Session {
    /// Sets up PIN unlock. With `persist`, the data is stored with the
    /// account so the PIN works after a restart; otherwise any stored PIN is
    /// removed and only the returned value, held in memory, can unlock.
    pub fn enable_pin(
        &self,
        store: &Store,
        pin: &str,
        persist: bool,
    ) -> Result<PinUnlock, SessionError> {
        if pin.is_empty() {
            return Err(SessionError::PinUnavailable);
        }
        let unlock = PinUnlock::new(&self.keys.user, pin, &self.profile.email, self.profile.kdf)?;
        if persist {
            store.write_pin(&self.profile.id, &unlock.to_json()?)?;
        } else {
            store.remove_pin(&self.profile.id)?;
        }
        Ok(unlock)
    }

    /// Turns stored PIN unlock off. The app also drops any value it holds.
    pub fn disable_pin(store: &Store, profile: &Profile) -> Result<(), SessionError> {
        Ok(store.remove_pin(&profile.id)?)
    }

    /// Whether the account has a stored PIN that can still be used.
    pub fn has_stored_pin(store: &Store, profile: &Profile) -> bool {
        Self::stored_pin(store, profile).is_some_and(|p| p.attempts_left() > 0)
    }

    fn stored_pin(store: &Store, profile: &Profile) -> Option<PinUnlock> {
        let data = Zeroizing::new(store.read_pin(&profile.id).ok()?);
        serde_json::from_slice(&data).ok()
    }

    /// Unlocks with a PIN, from `held` when the app keeps PIN unlock in
    /// memory or else from the stored data. Ends in the same state as
    /// [`Session::unlock`].
    ///
    /// A wrong PIN gives [`SessionError::WrongPin`]. After
    /// [`MAX_PIN_ATTEMPTS`] wrong PINs the stored data is deleted and the
    /// result is [`SessionError::PinUnavailable`]; the app should then drop
    /// its held value and ask for the master password.
    pub fn unlock_with_pin(
        store: &Store,
        profile: &Profile,
        pin: &str,
        held: Option<&mut PinUnlock>,
    ) -> Result<Session, SessionError> {
        let user = match held {
            Some(unlock) => unlock.attempt(pin, &profile.email)?,
            None => Self::attempt_stored_pin(store, profile, pin)?,
        };
        Self::open_offline(store, profile, user)
    }

    /// Checks a PIN against the stored data. The failed attempt is written
    /// before the check, so stopping the app mid-check still counts it.
    fn attempt_stored_pin(
        store: &Store,
        profile: &Profile,
        pin: &str,
    ) -> Result<SymmetricKey, SessionError> {
        let mut unlock = Self::stored_pin(store, profile).ok_or(SessionError::PinUnavailable)?;
        if unlock.attempts_left() == 0 {
            store.remove_pin(&profile.id)?;
            return Err(SessionError::PinUnavailable);
        }
        let mut counted = unlock.clone();
        counted.failed_attempts += 1;
        store.write_pin(&profile.id, &counted.to_json()?)?;
        let result = unlock.attempt(pin, &profile.email);
        match &result {
            Ok(_) => store.write_pin(&profile.id, &unlock.to_json()?)?,
            Err(SessionError::PinUnavailable) => store.remove_pin(&profile.id)?,
            Err(_) => {}
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kdf() -> Kdf {
        Kdf::Pbkdf2 { iterations: 5_000 }
    }

    #[test]
    fn opens_with_the_right_pin_only() {
        let user = SymmetricKey::generate();
        let mut unlock = PinUnlock::new(&user, "4321", "A@Example.invalid", kdf()).unwrap();
        // The email is normalised as for the master key.
        let opened = unlock.attempt("4321", "a@example.invalid").unwrap();
        assert_eq!(opened.to_bytes(), user.to_bytes());
        assert!(matches!(
            unlock.attempt("1234", "a@example.invalid"),
            Err(SessionError::WrongPin { attempts_left: 4 })
        ));
        // A success resets the count.
        unlock.attempt("4321", "a@example.invalid").unwrap();
        assert_eq!(unlock.attempts_left(), MAX_PIN_ATTEMPTS);
    }

    #[test]
    fn matches_bitwardens_pin_key() {
        // Bitwarden's PinKey: the KDF over PIN and email, then HKDF stretch,
        // wrapping the 64-byte user key as a type 2 string.
        let user = SymmetricKey::generate();
        let unlock = PinUnlock::new(&user, "0000", "pin@example.invalid", kdf()).unwrap();
        let derived = crypto::master_key("0000", "pin@example.invalid", kdf()).unwrap();
        let opened = crypto::stretch(&derived)
            .unwrap_key(&unlock.encrypted_user_key)
            .unwrap();
        assert_eq!(opened.to_bytes(), user.to_bytes());
        assert!(unlock.encrypted_user_key.starts_with("2."));
    }

    #[test]
    fn locks_after_too_many_wrong_pins() {
        let user = SymmetricKey::generate();
        let mut unlock = PinUnlock::new(&user, "2468", "b@example.invalid", kdf()).unwrap();
        for left in (1..MAX_PIN_ATTEMPTS).rev() {
            assert!(matches!(
                unlock.attempt("0000", "b@example.invalid"),
                Err(SessionError::WrongPin { attempts_left }) if attempts_left == left
            ));
        }
        assert!(matches!(
            unlock.attempt("0000", "b@example.invalid"),
            Err(SessionError::PinUnavailable)
        ));
        // Even the right PIN no longer works.
        assert!(matches!(
            unlock.attempt("2468", "b@example.invalid"),
            Err(SessionError::PinUnavailable)
        ));
    }

    #[test]
    fn debug_hides_the_wrapped_key() {
        let unlock =
            PinUnlock::new(&SymmetricKey::generate(), "1", "c@example.invalid", kdf()).unwrap();
        assert_eq!(format!("{unlock:?}"), "PinUnlock(failed_attempts: 0)");
    }
}

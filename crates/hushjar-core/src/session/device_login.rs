//! Logging in with a device, and approving such logins.
//!
//! The new device makes a key pair and posts a login request
//! ([`Session::start_device_login`]); the user compares the fingerprint
//! phrase on both devices and approves on one already signed in
//! ([`Session::answer_login_request`]), which shares the user key encrypted
//! to the request's public key. The new device polls
//! ([`DeviceLogin::poll`]) and then signs in with the request's access code
//! ([`Session::finish_device_login`]).
//!
//! Vaultwarden 1.37 accepts requests only from a device that has signed in
//! to the account before, and the final sign-in must happen within five
//! minutes of the request.

use std::fmt;
use std::time::{Duration, Instant};

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use zeroize::Zeroizing;

use super::{Session, SessionError, Signer};
use crate::api::{ApiError, AuthRequest, Client, Device, PasswordGrant, SecondFactor, Server};
use crate::crypto::{self, CryptoError, PrivateKey, PublicKey, SymmetricKey};
use crate::store::{Profile, Store};

/// How long a request stays valid. Bitwarden expires requests after 15
/// minutes; Vaultwarden deletes them then.
const REQUEST_LIFETIME: Duration = Duration::from_secs(15 * 60);

/// Length of the access code, the most Bitwarden's server accepts.
const ACCESS_CODE_LENGTH: usize = 25;

/// Where a login request stands.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeviceLoginStatus {
    Pending,
    /// Approved: call [`Session::finish_device_login`] promptly.
    Approved,
    Denied,
    Expired,
}

/// A login request this device made, kept until it is answered.
pub struct DeviceLogin {
    server: Server,
    email: String,
    device: Device,
    id: String,
    access_code: Zeroizing<String>,
    private_key: PrivateKey,
    public_key_der: Vec<u8>,
    started: Instant,
    /// The encrypted key and whether it is a master key, once approved.
    approval: Option<(String, bool)>,
}

impl fmt::Debug for DeviceLogin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DeviceLogin")
            .field("id", &self.id)
            .field("approved", &self.approval.is_some())
            .finish_non_exhaustive()
    }
}

/// A random access code of letters and digits. Rejection sampling keeps
/// every character equally likely.
fn access_code() -> Zeroizing<String> {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let limit = 256 - 256 % ALPHABET.len();
    let mut code = Zeroizing::new(String::with_capacity(ACCESS_CODE_LENGTH));
    while code.len() < ACCESS_CODE_LENGTH {
        for byte in crypto::random_bytes::<32>() {
            if (byte as usize) < limit && code.len() < ACCESS_CODE_LENGTH {
                code.push(ALPHABET[byte as usize % ALPHABET.len()] as char);
            }
        }
    }
    code
}

impl DeviceLogin {
    /// The request ID, which the approving device also sees.
    pub fn id(&self) -> &str {
        &self.id
    }

    /// The request's public key as SubjectPublicKeyInfo DER. With
    /// [`DeviceLogin::fingerprint_material`] it gives the fingerprint phrase
    /// the user compares with the approving device.
    pub fn public_key_der(&self) -> &[u8] {
        &self.public_key_der
    }

    /// The fingerprint material: the account email in lower case.
    pub fn fingerprint_material(&self) -> &str {
        &self.email
    }

    /// The device the request was made from; signing in uses it too.
    pub fn device(&self) -> &Device {
        &self.device
    }

    fn expired(&self) -> bool {
        self.started.elapsed() > REQUEST_LIFETIME
    }

    /// Asks the server whether the request has been answered. Call it every
    /// few seconds while showing the fingerprint phrase.
    pub fn poll(&mut self) -> Result<DeviceLoginStatus, SessionError> {
        if self.approval.is_some() {
            return Ok(DeviceLoginStatus::Approved);
        }
        if self.expired() {
            return Ok(DeviceLoginStatus::Expired);
        }
        let client = Client::new(self.server.clone());
        let request = match client.auth_request_response(&self.id, &self.access_code) {
            Ok(request) => request,
            // Vaultwarden deletes a request when it is denied or expires.
            Err(ApiError::Rejected(_)) => return Ok(DeviceLoginStatus::Denied),
            Err(other) => return Err(other.into()),
        };
        Ok(match (request.approved, request.key) {
            (Some(true), Some(key)) => {
                self.approval = Some((key, request.master_password_hash.is_some()));
                DeviceLoginStatus::Approved
            }
            (Some(false), _) => DeviceLoginStatus::Denied,
            _ => DeviceLoginStatus::Pending,
        })
    }

    /// Opens the shared key and returns the user key. Old clients shared
    /// the master key instead; it then opens the user key from the login.
    fn user_key(&self, login_key: &str) -> Result<SymmetricKey, SessionError> {
        let (shared, is_master_key) = self.approval.as_ref().ok_or(SessionError::NotApproved)?;
        let plain = self.private_key.decrypt(shared)?;
        if *is_master_key {
            let master: Zeroizing<[u8; 32]> =
                Zeroizing::new(plain[..].try_into().map_err(|_| CryptoError::KeySize)?);
            Ok(crypto::stretch(&master).unwrap_key(login_key)?)
        } else {
            Ok(SymmetricKey::from_bytes(&plain)?)
        }
    }
}

impl Session {
    /// Starts logging in with another device. With `existing`, the request
    /// comes from that saved account's device; otherwise from `device`, or
    /// a new one.
    pub fn start_device_login(
        server: Server,
        email: &str,
        device: Option<&Device>,
        existing: Option<&Profile>,
    ) -> Result<DeviceLogin, SessionError> {
        let email = crypto::normalize_email(email);
        let device = existing
            .map(|p| p.device.clone())
            .or_else(|| device.cloned())
            .unwrap_or_default();
        let private_key = PrivateKey::generate()?;
        let public_key_der = private_key.public_key().to_der();
        let access_code = access_code();
        let client = Client::new(server.clone());
        let request = client.create_auth_request(
            &email,
            &B64.encode(&public_key_der),
            &device,
            &access_code,
        )?;
        Ok(DeviceLogin {
            server,
            email,
            device,
            id: request.id,
            access_code,
            private_key,
            public_key_der,
            started: Instant::now(),
            approval: None,
        })
    }

    /// Signs in once [`DeviceLogin::poll`] has reported approval. The account
    /// may still ask for two-step login; then call again with `second`.
    pub fn finish_device_login(
        store: &Store,
        request: &DeviceLogin,
        second: Option<SecondFactor<'_>>,
        existing: Option<&Profile>,
    ) -> Result<Session, SessionError> {
        if request.approval.is_none() {
            return Err(SessionError::NotApproved);
        }
        let client = Client::new(request.server.clone());
        let kdf = client.prelogin(&request.email)?;
        let login = client.password_grant(&PasswordGrant {
            email: &request.email,
            secret: &request.access_code,
            device: &request.device,
            second,
            new_device_code: None,
            auth_request: Some(&request.id),
        })?;
        let user = request.user_key(&login.key)?;
        let who = Signer {
            email: request.email.clone(),
            kdf,
            device: request.device.clone(),
        };
        Self::start_online(store, client, who, login, user, existing)
    }

    /// Login requests from other devices that wait for an answer. Show each
    /// with its fingerprint phrase from the account email and
    /// [`request_public_key`].
    pub fn pending_login_requests(&mut self) -> Result<Vec<AuthRequest>, SessionError> {
        self.with_token(|c, t| c.pending_auth_requests(t))
    }

    /// Approves or denies another device's login request. Approval shares
    /// the user key, encrypted so only that device can open it.
    pub fn answer_login_request(
        &mut self,
        request: &AuthRequest,
        approve: bool,
    ) -> Result<(), SessionError> {
        let key = if approve {
            PublicKey::from_der(&request_public_key(request)?)?.wrap_key(&self.keys.user)?
        } else {
            String::new()
        };
        let device = self.profile.device.clone();
        self.with_token(|c, t| c.answer_auth_request(t, &request.id, &key, &device, approve))
    }
}

/// The requesting device's public key as SubjectPublicKeyInfo DER, for the
/// fingerprint phrase shown when approving.
pub fn request_public_key(request: &AuthRequest) -> Result<Vec<u8>, SessionError> {
    B64.decode(request.public_key.trim())
        .map_err(|_| SessionError::Crypto(CryptoError::Malformed))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn access_codes_are_long_and_varied() {
        let a = access_code();
        let b = access_code();
        assert_eq!(a.len(), ACCESS_CODE_LENGTH);
        assert!(a.chars().all(|c| c.is_ascii_alphanumeric()));
        assert_ne!(*a, *b);
    }

    fn request_with(approval: Option<(String, bool)>, key: PrivateKey) -> DeviceLogin {
        DeviceLogin {
            server: Server::parse("http://127.0.0.1:1").unwrap(),
            email: "d@example.invalid".into(),
            device: Device::new(),
            id: "id".into(),
            access_code: access_code(),
            public_key_der: key.public_key().to_der(),
            private_key: key,
            started: Instant::now(),
            approval,
        }
    }

    #[test]
    fn opens_a_shared_user_key() {
        let key = PrivateKey::generate().unwrap();
        let user = SymmetricKey::generate();
        let shared = key.public_key().wrap_key(&user).unwrap();
        assert!(shared.starts_with("4."));
        let request = request_with(Some((shared, false)), key);
        let opened = request.user_key("unused").unwrap();
        assert_eq!(opened.to_bytes(), user.to_bytes());
    }

    #[test]
    fn opens_a_shared_master_key() {
        let key = PrivateKey::generate().unwrap();
        let user = SymmetricKey::generate();
        let master = crypto::random_bytes::<32>();
        let login_key = crypto::stretch(&master).wrap_key(&user);
        let shared = key.public_key().encrypt(&master).unwrap();
        let request = request_with(Some((shared, true)), key);
        let opened = request.user_key(&login_key).unwrap();
        assert_eq!(opened.to_bytes(), user.to_bytes());
    }

    #[test]
    fn needs_approval_first() {
        let request = request_with(None, PrivateKey::generate().unwrap());
        assert!(matches!(
            request.user_key("x"),
            Err(SessionError::NotApproved)
        ));
    }

    #[test]
    fn public_key_round_trips_through_base64() {
        let key = PrivateKey::generate().unwrap();
        let der = key.public_key().to_der();
        let request = AuthRequest {
            id: "x".into(),
            public_key: B64.encode(&der),
            device_type: String::new(),
            ip_address: String::new(),
            created: String::new(),
            key: None,
            master_password_hash: None,
            approved: None,
        };
        assert_eq!(request_public_key(&request).unwrap(), der);
        assert_eq!(PublicKey::from_der(&der).unwrap().to_der(), der);
    }
}

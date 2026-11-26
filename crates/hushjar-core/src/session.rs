//! An unlocked account: signing in, offline unlock, sync and saving.
//!
//! A session is used from one worker thread at a time; the app sends it
//! commands and receives copies of the decrypted vault.

use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde_json::{Value, json};
use zeroize::Zeroizing;

use crate::api::{
    ApiError, Client, Device, Login, PasswordGrant, SecondFactor, Server, TwoFactorChallenge,
    TwoFactorProvider, field, field_str,
};
use crate::crypto::{self, CryptoError, HashPurpose, Kdf, PrivateKey, SymmetricKey};
use crate::store::{Profile, Store};
use crate::vault::{self, Item, Keys, Vault, VaultError};

mod device_login;
mod pin;

pub use device_login::{DeviceLogin, DeviceLoginStatus, request_public_key};
pub use pin::{MAX_PIN_ATTEMPTS, PinUnlock};

#[derive(Debug, thiserror::Error)]
pub enum SessionError {
    #[error("wrong master password")]
    WrongPassword,
    #[error("two-step login is required")]
    TwoFactorRequired(TwoFactorChallenge),
    /// Sign in again with the emailed code in [`SignInOptions`], using the
    /// same device.
    #[error("enter the code sent to your email to confirm this new device")]
    NewDeviceVerificationRequired,
    #[error("wrong PIN; {attempts_left} attempts left")]
    WrongPin { attempts_left: u32 },
    #[error("PIN unlock is not available; unlock with the master password")]
    PinUnavailable,
    #[error("the saved key no longer opens this account; unlock with the master password")]
    KeyRejected,
    #[error("the login request has not been approved")]
    NotApproved,
    #[error("sign in again to reconnect this account")]
    SignInRequired,
    #[error("{0}")]
    Api(ApiError),
    #[error("{0}")]
    Vault(#[from] VaultError),
    #[error("encryption failed: {0}")]
    Crypto(#[from] CryptoError),
    #[error("could not save to disk: {0}")]
    Storage(#[from] std::io::Error),
    #[error("there is no offline copy of this account yet; connect to sign in")]
    NoOfflineCopy,
    #[error("the server could not confirm whether the item was saved; check after syncing")]
    SaveUncertain,
    #[error("this item is read-only for your account")]
    ReadOnly,
}

impl From<ApiError> for SessionError {
    fn from(error: ApiError) -> Self {
        match error {
            ApiError::TwoFactorRequired(p) => SessionError::TwoFactorRequired(p),
            ApiError::NewDeviceVerificationRequired => SessionError::NewDeviceVerificationRequired,
            ApiError::Unauthorized => SessionError::SignInRequired,
            other => SessionError::Api(other),
        }
    }
}

/// Avatar colours handed out to accounts in turn.
const TINTS: [[u8; 3]; 6] = [
    [0x2f, 0x6f, 0xdb],
    [0x1d, 0x8f, 0x58],
    [0xb0, 0x47, 0x9b],
    [0xc9, 0x6a, 0x12],
    [0x13, 0x86, 0x93],
    [0x8a, 0x5c, 0xd6],
];

/// Extra proof and settings for a password sign-in.
#[derive(Default)]
pub struct SignInOptions<'a> {
    pub second: Option<SecondFactor<'a>>,
    /// The code Bitwarden emailed after [`SessionError::NewDeviceVerificationRequired`].
    pub new_device_code: Option<&'a str>,
    /// The device to sign in as when adding a new account. Keep the same one
    /// across retries: new-device codes and remembered two-step logins are
    /// tied to it. Ignored when reconnecting a saved account, which keeps its
    /// own device.
    pub device: Option<&'a Device>,
}

/// Who is signing in: what a new profile records besides the server.
struct Signer {
    email: String,
    kdf: Kdf,
    device: Device,
}

struct Online {
    access: Zeroizing<String>,
    expires: Instant,
}

pub struct Session {
    pub profile: Profile,
    client: Client,
    keys: Keys,
    pub vault: Vault,
    sync: Value,
    online: Option<Online>,
    refresh: Option<Zeroizing<String>>,
    remember: Option<Zeroizing<String>>,
    pub synced_at: Option<u64>,
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn cache_key(user: &crypto::SymmetricKey, profile: &Profile) -> Zeroizing<[u8; 32]> {
    user.derive_local(
        b"hushjar-cache",
        &format!("hushjar/cache/v1/{}", profile.id),
    )
}

fn cache_aad(profile: &Profile) -> Vec<u8> {
    format!("hushjar-cache-v1|{}|{}", profile.id, profile.user_id).into_bytes()
}

impl Session {
    /// Asks the server to email a two-step login code for this sign-in.
    pub fn send_email_code(
        server: &Server,
        email: &str,
        password: &str,
        device: &Device,
    ) -> Result<(), SessionError> {
        let client = Client::new(server.clone());
        let kdf = client.prelogin(email)?;
        let master = crypto::master_key(password, email, kdf)?;
        let hash = crypto::password_hash(&master, password, HashPurpose::Server);
        client.send_email_code(email, &hash, device)?;
        Ok(())
    }

    /// Asks Bitwarden to email another code for confirming a new device.
    /// Use the same device as the sign-in that asked for it.
    pub fn resend_new_device_code(
        server: &Server,
        email: &str,
        password: &str,
        device: &Device,
    ) -> Result<(), SessionError> {
        let email = crypto::normalize_email(email);
        let client = Client::new(server.clone());
        let kdf = client.prelogin(&email)?;
        let master = crypto::master_key(password, &email, kdf)?;
        let hash = crypto::password_hash(&master, password, HashPurpose::Server);
        client.resend_new_device_code(&email, &hash, device)?;
        Ok(())
    }

    /// Signs in online. With `existing`, reconnects that saved account and
    /// keeps its local identity; otherwise creates a new profile.
    pub fn sign_in(
        store: &Store,
        server: Server,
        email: &str,
        password: &str,
        second: Option<SecondFactor<'_>>,
        existing: Option<&Profile>,
    ) -> Result<Session, SessionError> {
        let options = SignInOptions {
            second,
            ..SignInOptions::default()
        };
        Self::sign_in_with(store, server, email, password, options, existing)
    }

    /// Signs in online with a new-device code or a chosen device, as
    /// [`Session::sign_in`] otherwise.
    pub fn sign_in_with(
        store: &Store,
        server: Server,
        email: &str,
        password: &str,
        options: SignInOptions<'_>,
        existing: Option<&Profile>,
    ) -> Result<Session, SessionError> {
        let email = crypto::normalize_email(email);
        let client = Client::new(server);
        let kdf = client.prelogin(&email)?;
        let master = crypto::master_key(password, &email, kdf)?;
        let hash = crypto::password_hash(&master, password, HashPurpose::Server);
        let device = existing
            .map(|p| p.device.clone())
            .or_else(|| options.device.cloned())
            .unwrap_or_default();
        let login = client.password_grant(&PasswordGrant {
            email: &email,
            secret: &hash,
            device: &device,
            second: options.second,
            new_device_code: options.new_device_code,
            auth_request: None,
        })?;
        let user = crypto::stretch(&master)
            .unwrap_key(&login.key)
            .map_err(|_| SessionError::WrongPassword)?;
        let who = Signer { email, kdf, device };
        Self::start_online(store, client, who, login, user, existing)
    }

    /// Finishes an online sign-in once the user key is known: syncs, then
    /// saves the profile and the offline copy. Shared by every way of
    /// signing in.
    fn start_online(
        store: &Store,
        client: Client,
        who: Signer,
        login: Login,
        user: SymmetricKey,
        existing: Option<&Profile>,
    ) -> Result<Session, SessionError> {
        let Signer { email, kdf, device } = who;
        let server = client.server.clone();
        let private = login
            .private_key
            .as_deref()
            .map(|k| PrivateKey::unwrap(&user, k))
            .transpose()?;

        let issued = Instant::now();
        let sync = client.sync(&login.access_token)?;
        let user_id = field(&sync, "profile")
            .and_then(|p| field_str(p, "id"))
            .unwrap_or_default()
            .to_string();
        if let Some(previous) = existing
            && previous.user_id != user_id
        {
            return Err(SessionError::Api(ApiError::Rejected(
                "this sign-in belongs to a different account".into(),
            )));
        }
        let profile = Profile {
            id: existing
                .map(|p| p.id.clone())
                .unwrap_or_else(|| uuid::Uuid::new_v4().to_string()),
            email,
            server,
            kdf,
            user_id,
            encrypted_user_key: login.key.clone(),
            encrypted_private_key: login.private_key.clone(),
            device,
            tint: existing
                .map(|p| p.tint)
                .unwrap_or(TINTS[store.profiles().len() % TINTS.len()]),
        };
        let keys = Keys::new(user, private.as_ref(), &sync);
        let vault = vault::decrypt_sync(&sync, &keys);
        let session = Session {
            profile,
            client,
            keys,
            vault,
            sync,
            online: Some(Online {
                access: login.access_token,
                expires: issued + Duration::from_secs(login.expires_in),
            }),
            refresh: Some(login.refresh_token),
            remember: login.two_factor_token,
            synced_at: Some(unix_now()),
        };
        store.save_profile(&session.profile)?;
        session.persist(store)?;
        Ok(session)
    }

    /// Unlocks a saved account from its offline copy. The master password is
    /// checked by opening the stored user key; nothing is sent anywhere.
    pub fn unlock(
        store: &Store,
        profile: &Profile,
        password: &str,
    ) -> Result<Session, SessionError> {
        let master = crypto::master_key(password, &profile.email, profile.kdf)?;
        let user = crypto::stretch(&master)
            .unwrap_key(&profile.encrypted_user_key)
            .map_err(|_| SessionError::WrongPassword)?;
        Self::open_offline(store, profile, user)
    }

    /// Unlocks with a user key kept by the operating system, such as behind
    /// a biometric prompt (see [`Session::export_user_key`]). The key is
    /// checked first: it must open the account's private key, when there is
    /// one, and the authenticated offline copy.
    pub fn unlock_with_user_key(
        store: &Store,
        profile: &Profile,
        key: &[u8],
    ) -> Result<Session, SessionError> {
        let user = SymmetricKey::from_bytes(key).map_err(|_| SessionError::KeyRejected)?;
        if let Some(wrapped) = &profile.encrypted_private_key {
            PrivateKey::unwrap(&user, wrapped).map_err(|_| SessionError::KeyRejected)?;
        }
        match Self::open_offline(store, profile, user) {
            Err(SessionError::Crypto(CryptoError::Authentication)) => {
                Err(SessionError::KeyRejected)
            }
            other => other,
        }
    }

    /// The decrypted user key, for the app to keep behind an operating
    /// system prompt for biometric unlock. Never write it to disk unwrapped.
    pub fn export_user_key(&self) -> Zeroizing<Vec<u8>> {
        self.keys.user.to_bytes()
    }

    /// The account's ID on the server: the material for the account
    /// fingerprint phrase, together with [`Session::account_public_key`].
    pub fn user_id(&self) -> &str {
        &self.profile.user_id
    }

    /// The account's RSA public key as SubjectPublicKeyInfo DER, if the
    /// account has a key pair.
    pub fn account_public_key(&self) -> Option<Vec<u8>> {
        let wrapped = self.profile.encrypted_private_key.as_deref()?;
        let private = PrivateKey::unwrap(&self.keys.user, wrapped).ok()?;
        Some(private.public_key().to_der())
    }

    /// Opens the offline copy with the user key. Every way of unlocking ends
    /// here, so they all leave the session in the same state.
    fn open_offline(
        store: &Store,
        profile: &Profile,
        user: SymmetricKey,
    ) -> Result<Session, SessionError> {
        let sealed = store
            .read_cache(&profile.id)
            .map_err(|_| SessionError::NoOfflineCopy)?;
        let plain = crypto::open(&cache_key(&user, profile), &cache_aad(profile), &sealed)?;
        let cache: Value = serde_json::from_slice(&plain).map_err(|_| CryptoError::Malformed)?;
        let sync = cache.get("sync").cloned().unwrap_or(Value::Null);
        let private = profile
            .encrypted_private_key
            .as_deref()
            .map(|k| PrivateKey::unwrap(&user, k))
            .transpose()?;
        let keys = Keys::new(user, private.as_ref(), &sync);
        let vault = vault::decrypt_sync(&sync, &keys);
        let secret = |name: &str| {
            cache
                .get(name)
                .and_then(Value::as_str)
                .map(|s| Zeroizing::new(s.to_string()))
        };
        Ok(Session {
            profile: profile.clone(),
            client: Client::new(profile.server.clone()),
            keys,
            vault,
            refresh: secret("refresh_token"),
            remember: secret("remember_token"),
            synced_at: cache.get("synced_at").and_then(Value::as_u64),
            sync,
            online: None,
        })
    }

    /// Signs in again for an unlocked account whose tokens have expired.
    pub fn reconnect(
        &mut self,
        store: &Store,
        password: &str,
        second: Option<SecondFactor<'_>>,
    ) -> Result<(), SessionError> {
        let master = crypto::master_key(password, &self.profile.email, self.profile.kdf)?;
        let hash = crypto::password_hash(&master, password, HashPurpose::Server);
        let remembered;
        let second = match (second, &self.remember) {
            (Some(s), _) => Some(s),
            (None, Some(token)) => {
                remembered = token.clone();
                Some(SecondFactor {
                    provider: TwoFactorProvider::Other(5),
                    token: &remembered,
                    remember: false,
                })
            }
            (None, None) => None,
        };
        let login =
            match self
                .client
                .login(&self.profile.email, &hash, &self.profile.device, second)
            {
                Err(ApiError::TwoFactorRequired(p)) => {
                    self.remember = None;
                    return Err(SessionError::TwoFactorRequired(p));
                }
                other => other?,
            };
        self.online = Some(Online {
            access: login.access_token,
            expires: Instant::now() + Duration::from_secs(login.expires_in),
        });
        self.refresh = Some(login.refresh_token);
        if login.two_factor_token.is_some() {
            self.remember = login.two_factor_token;
        }
        self.persist(store)
    }

    pub fn is_online(&self) -> bool {
        self.online
            .as_ref()
            .is_some_and(|o| o.expires > Instant::now())
    }

    /// A valid access token, refreshing it when needed.
    fn token(&mut self) -> Result<Zeroizing<String>, SessionError> {
        if let Some(online) = &self.online
            && online.expires > Instant::now() + Duration::from_secs(30)
        {
            return Ok(online.access.clone());
        }
        let refresh = self.refresh.clone().ok_or(SessionError::SignInRequired)?;
        match self.client.refresh(&refresh) {
            Ok(tokens) => {
                let access = tokens.access_token.clone();
                self.online = Some(Online {
                    access: tokens.access_token,
                    expires: Instant::now() + Duration::from_secs(tokens.expires_in),
                });
                self.refresh = Some(tokens.refresh_token);
                Ok(access)
            }
            Err(ApiError::Unauthorized) => {
                self.refresh = None;
                self.online = None;
                Err(SessionError::SignInRequired)
            }
            Err(other) => Err(other.into()),
        }
    }

    /// Runs an authenticated request, retrying once with a fresh token if the
    /// access token was rejected. Never used for requests that create items.
    fn with_token<T>(
        &mut self,
        mut call: impl FnMut(&Client, &str) -> Result<T, ApiError>,
    ) -> Result<T, SessionError> {
        let token = self.token()?;
        match call(&self.client, &token) {
            Err(ApiError::Unauthorized) => {
                self.online = None;
                let token = self.token()?;
                Ok(call(&self.client, &token)?)
            }
            other => Ok(other?),
        }
    }

    pub fn sync(&mut self, store: &Store) -> Result<(), SessionError> {
        let sync = self.with_token(|c, t| c.sync(t))?;
        let private = self
            .profile
            .encrypted_private_key
            .as_deref()
            .map(|k| PrivateKey::unwrap(&self.keys.user, k))
            .transpose()?;
        self.keys = Keys::new(self.keys.user.clone(), private.as_ref(), &sync);
        self.vault = vault::decrypt_sync(&sync, &self.keys);
        self.sync = sync;
        self.synced_at = Some(unix_now());
        self.persist(store)
    }

    /// Writes the encrypted offline copy.
    fn persist(&self, store: &Store) -> Result<(), SessionError> {
        let cache = json!({
            "sync": self.sync,
            "refresh_token": self.refresh.as_deref().map(String::as_str),
            "remember_token": self.remember.as_deref().map(String::as_str),
            "synced_at": self.synced_at,
        });
        let plain = Zeroizing::new(serde_json::to_vec(&cache).map_err(std::io::Error::other)?);
        let sealed = crypto::seal(
            &cache_key(&self.keys.user, &self.profile),
            &cache_aad(&self.profile),
            &plain,
        );
        store.write_cache(&self.profile.id, &sealed)?;
        Ok(())
    }

    /// Replaces or adds one item in the stored sync data and the vault.
    fn apply_cipher(&mut self, store: &Store, raw: Value) -> Result<Item, SessionError> {
        let id = field_str(&raw, "id").unwrap_or_default().to_string();
        if let Some(list) = self.sync.get_mut("ciphers").and_then(Value::as_array_mut) {
            match list
                .iter_mut()
                .find(|c| field_str(c, "id") == Some(id.as_str()))
            {
                Some(slot) => *slot = raw.clone(),
                None => list.push(raw.clone()),
            }
        }
        let item = vault::decrypt_item(&raw, &self.keys);
        match self.vault.items.iter_mut().find(|i| i.id == id) {
            Some(slot) => *slot = item.clone(),
            None => self.vault.items.push(item.clone()),
        }
        self.persist(store)?;
        Ok(item)
    }

    /// Saves an edited or new item and returns the server's copy.
    ///
    /// A new item is posted once. If the reply is lost, the result is
    /// [`SessionError::SaveUncertain`] and nothing is retried: sync first to
    /// see whether it arrived, so no duplicate is created.
    pub fn save(&mut self, store: &Store, item: &Item) -> Result<Item, SessionError> {
        if !item.editable {
            return Err(SessionError::ReadOnly);
        }
        let body = vault::encrypt_item(item, &self.keys)?;
        let reply = if item.is_new() {
            let token = self.token()?;
            let result = match &item.organization_id {
                Some(_) => self
                    .client
                    .create_org_cipher(&token, &body, &item.collection_ids),
                None => self.client.create_cipher(&token, &body),
            };
            match result {
                Ok(reply) => reply,
                Err(ApiError::Network(_)) | Err(ApiError::Decode) => {
                    return Err(SessionError::SaveUncertain);
                }
                Err(other) => return Err(other.into()),
            }
        } else {
            let id = item.id.clone();
            self.with_token(|c, t| c.update_cipher(t, &id, &body))?
        };
        self.apply_cipher(store, reply)
    }

    pub fn trash(&mut self, store: &Store, id: &str) -> Result<(), SessionError> {
        self.with_token(|c, t| c.trash_cipher(t, id))?;
        self.sync(store)
    }

    pub fn restore(&mut self, store: &Store, id: &str) -> Result<(), SessionError> {
        self.with_token(|c, t| c.restore_cipher(t, id))?;
        self.sync(store)
    }

    pub fn delete(&mut self, store: &Store, id: &str) -> Result<(), SessionError> {
        self.with_token(|c, t| c.delete_cipher(t, id))?;
        self.sync(store)
    }

    pub fn create_folder(&mut self, store: &Store, name: &str) -> Result<String, SessionError> {
        let encrypted = self.keys.user.encrypt_str(name);
        let reply = self.with_token(|c, t| c.create_folder(t, &encrypted))?;
        let id = field_str(&reply, "id").unwrap_or_default().to_string();
        self.sync(store)?;
        Ok(id)
    }
}
